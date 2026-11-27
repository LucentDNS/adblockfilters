#!/usr/bin/env python3
"""Audit upstream filter sources using the repository's current Resolver parser."""
import asyncio
import hashlib
import ipaddress
import json
import os
import re
import sys
import httpx
from tld import get_tld
from tld.utils import update_tld_names
from collections import defaultdict
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from readme import ReadMe, Rule  # noqa: E402 - project-root bootstrap above
from resolver import Resolver, configure_logging  # noqa: E402 - project-root bootstrap above
SOURCE_DIR = ROOT / ".cache" / "source"
OUT_DIR = ROOT / ".cache" / "audit"
CANDIDATE_SOURCE_DIR = OUT_DIR / "candidate-source"
TIMEOUT = httpx.Timeout(90.0, connect=30.0)


def source_audit_gate_failures(
    compiled_unparsed: int,
    compiled_non_domain_filters: int,
    source_presence_unexplained: set[str],
    current_source_parent_inactive_unexplained: set[str],
    baseline_allow_missing_still_blocked: set[str],
    source_allow_missing_still_blocked: set[str] | None = None,
) -> list[str]:
    """Fail on active source loss and upstream allow regressions, not historical baseline-only deltas."""
    failures = []
    if compiled_unparsed:
        failures.append(f"compiled DNS output has {compiled_unparsed} unparsed rule lines")
    # Valid AdGuard DNS filter syntax is not limited to hostname rules.
    # Wildcards, regex-like patterns and other supported filter directives may
    # not expose a single domain to this audit's coverage model. Keep their
    # count in the report, but do not misclassify them as invalid or lost rules.
    if source_presence_unexplained:
        failures.append(
            "active baseline DNS source rules are missing from compiled output: "
            + ", ".join(sorted(source_presence_unexplained)[:20])
        )
    if current_source_parent_inactive_unexplained:
        failures.append(
            "baseline rules have inactive current-source parents without a valid exclusion: "
            + ", ".join(sorted(current_source_parent_inactive_unexplained)[:20])
        )
    if baseline_allow_missing_still_blocked:
        failures.append(
            "upstream baseline allow exceptions are missing while domains remain blocked: "
            + ", ".join(sorted(baseline_allow_missing_still_blocked)[:20])
        )
    if source_allow_missing_still_blocked:
        failures.append(
            "active production-source allow exceptions are missing while matching block rules remain: "
            + ", ".join(sorted(source_allow_missing_still_blocked)[:20])
        )
    return failures


def write_domain_list(path, domains, empty_note):
    """Write a non-empty, comment-safe list so empty reports remain publishable."""
    values = sorted(set(domains))
    content = "\n".join(values) + "\n" if values else f"! {empty_note}\n"
    Path(path).write_text(content, encoding="utf-8")



def is_ip_literal(value):
    candidate = str(value).strip()
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1:candidate.index("]")]
    elif candidate.count(":") == 1 and "." in candidate:
        candidate = candidate.rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def full_domain(value):
    if not value:
        return None
    if isinstance(value, tuple) and len(value) == 2:
        fld, subdomain = value
        domain = (f"{subdomain}.{fld}" if subdomain else fld).lower()
    else:
        domain = str(value).lower()
    # IP literals are not DNS domain names and must not inflate domain coverage.
    return None if is_ip_literal(domain) else domain


def ignored_line(line, source_type):
    s = line.strip()
    if not s or s.startswith("!") or (s.startswith("[") and s.endswith("]")):
        return True
    if source_type == "host":
        return s.startswith("#")
    return s.startswith("#") and not s.startswith(("##", "#%#"))


async def download_all(rules, candidate_names):
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    CANDIDATE_SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    sem = asyncio.Semaphore(5)
    results = {}
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True,
                                 headers={"User-Agent": "AdBlock-DNS-Source-Audit/1.0"}) as client:
        async def one(rule):
            async with sem:
                try:
                    target_dir = CANDIDATE_SOURCE_DIR if rule.name in candidate_names else SOURCE_DIR
                    path = target_dir / rule.filename
                    # Reuse the exact snapshots already downloaded by the normal build.
                    # This avoids a second network download and keeps audit/build inputs identical.
                    if path.exists() and path.stat().st_size:
                        content = path.read_text(encoding="utf-8", errors="replace")
                        if not content.strip() or content.lstrip().lower().startswith(("<!doctype html", "<html")):
                            raise ValueError("cached source is empty or HTML")
                        results[rule.name] = {
                            "ok": True, "path": str(path), "bytes": path.stat().st_size,
                            "status": "reused-build-snapshot", "url": rule.url
                        }
                        return
                    response = await client.get(rule.url)
                    response.raise_for_status()
                    content = response.text
                    if not content.strip():
                        raise ValueError("empty response")
                    if content.lstrip().lower().startswith(("<!doctype html", "<html")):
                        raise ValueError("HTML response instead of a filter list")
                    path.write_text(content, encoding="utf-8", errors="replace")
                    results[rule.name] = {
                        "ok": True, "path": str(path), "bytes": len(response.content),
                        "status": response.status_code, "url": rule.url
                    }
                except Exception as exc:
                    results[rule.name] = {
                        "ok": False, "error": f"{type(exc).__name__}: {exc}", "url": rule.url
                    }
        await asyncio.gather(*(one(rule) for rule in rules))
    return results


def audit_one(rule, resolver, download):
    result = {
        "name": rule.name, "type": rule.type, "url": rule.url,
        "download_ok": download.get("ok", False),
        "bytes": download.get("bytes", 0),
        "total_lines": 0, "nonempty_lines": 0, "comment_or_header_lines": 0,
        "candidate_lines": 0, "parsed_lines": 0, "unparsed_candidate_lines": 0,
        "block_entries": 0, "block_ip_entries": 0,
        "allow_entries": 0, "allow_ip_entries": 0, "filter_entries": 0,
        "dns_pattern_block_entries": 0, "dns_pattern_allow_entries": 0,
        "dns_pattern_excluded": 0, "dns_regex_excluded": 0,
        "filter_domain_extracted": 0, "filter_ip_extracted": 0, "filter_domain_unresolved": 0,
        "unique_block_domains": 0, "unique_allow_domains": 0,
        "unique_filter_rules": 0, "unique_extracted_domains": 0,
        "unique_dns_pattern_block_rules": 0, "unique_dns_pattern_allow_rules": 0,
        "duplicate_raw_lines": 0, "download_error": download.get("error", ""),
        "samples_unparsed": [], "samples_filter_domain_unresolved": [],
        "samples_dns_patterns": [], "samples_dns_pattern_excluded": []
    }
    if not download.get("ok"):
        return result, set(), set()

    lines = Path(download["path"]).read_text(encoding="utf-8", errors="replace").splitlines()
    result["source_sha256"] = hashlib.sha256(Path(download["path"]).read_bytes()).hexdigest()
    result["total_lines"] = len(lines)
    seen_lines = set()
    blocks, allows, filters, extracted = set(), set(), set(), set()
    dns_pattern_blocks, dns_pattern_allows = set(), set()

    for line in lines:
        s = line.strip()
        if not s:
            continue
        result["nonempty_lines"] += 1
        if s in seen_lines:
            result["duplicate_raw_lines"] += 1
        seen_lines.add(s)

        if ignored_line(s, rule.type):
            result["comment_or_header_lines"] += 1
            continue

        result["candidate_lines"] += 1
        try:
            if rule.type == "host":
                block = resolver._Resolver__resolveHost(s)
                unblock, filt = None, None
            elif rule.type == "dns":
                block, unblock, filt = resolver._Resolver__resolveDNS(s)
            else:
                block, unblock, filt = resolver._Resolver__resolveFilter(s)

            parsed = False
            if block:
                domain = full_domain(block)
                if domain:
                    blocks.add(domain)
                    result["block_entries"] += 1
                else:
                    result["block_ip_entries"] += 1
                parsed = True
            if unblock:
                domain = full_domain(unblock)
                if domain:
                    allows.add(domain)
                    result["allow_entries"] += 1
                else:
                    result["allow_ip_entries"] += 1
                parsed = True
            if filt:
                filters.add(filt[0])
                result["filter_entries"] += 1
                parsed = True
                pattern = (
                    resolver.resolveDNSPattern(filt[0])
                    if rule.type in {"dns", "dnsfilter"}
                    else None
                )
                if pattern:
                    action, base_domain = pattern
                    if action == "allow":
                        dns_pattern_allows.add(filt[0])
                        # Preserve the effective base domain for cross-source
                        # explicit-allow conflict analysis.
                        allows.add(base_domain)
                        result["dns_pattern_allow_entries"] += 1
                    else:
                        dns_pattern_blocks.add(filt[0])
                        result["dns_pattern_block_entries"] += 1
                    if len(result["samples_dns_patterns"]) < 20:
                        result["samples_dns_patterns"].append({
                            "rule": filt[0],
                            "action": action,
                            "base_domain": base_domain,
                        })
                else:
                    excluded_dns_pattern = False
                    if rule.type in {"dns", "dnsfilter"} and "*" in filt[0]:
                        result["dns_pattern_excluded"] += 1
                        excluded_dns_pattern = True
                        if len(result["samples_dns_pattern_excluded"]) < 20:
                            result["samples_dns_pattern_excluded"].append(s[:240])
                    if rule.type in {"dns", "dnsfilter"} and filt[0].startswith("/") and filt[0].endswith("/"):
                        result["dns_regex_excluded"] += 1
                        excluded_dns_pattern = True
                    if not excluded_dns_pattern:
                        if filt[1]:
                            extracted_domain = full_domain(filt[1])
                            if extracted_domain:
                                extracted.add(extracted_domain)
                                result["filter_domain_extracted"] += 1
                            elif is_ip_literal(filt[1]):
                                result["filter_ip_extracted"] += 1
                            else:
                                result["filter_domain_unresolved"] += 1
                                if len(result["samples_filter_domain_unresolved"]) < 20:
                                    result["samples_filter_domain_unresolved"].append(s[:240])
                        else:
                            result["filter_domain_unresolved"] += 1
                            if len(result["samples_filter_domain_unresolved"]) < 20:
                                result["samples_filter_domain_unresolved"].append(s[:240])
            if parsed:
                result["parsed_lines"] += 1
            else:
                result["unparsed_candidate_lines"] += 1
                if len(result["samples_unparsed"]) < 20:
                    result["samples_unparsed"].append(s[:240])
        except Exception:
            result["unparsed_candidate_lines"] += 1
            if len(result["samples_unparsed"]) < 20:
                result["samples_unparsed"].append(s[:240])

    result["unique_block_domains"] = len(blocks)
    result["unique_allow_domains"] = len(allows)
    result["allow_domain_samples"] = sorted(allows)[:100]
    result["unique_filter_rules"] = len(filters)
    result["unique_extracted_domains"] = len(extracted)
    result["unique_dns_pattern_block_rules"] = len(dns_pattern_blocks)
    result["unique_dns_pattern_allow_rules"] = len(dns_pattern_allows)
    return result, blocks, allows


def render_report(results, production_names, browser_names, candidate_names, overlap, unique_total, pairwise, candidate_overlaps, candidate_pairwise_overlaps):
    cols = [
        ("name", "来源"), ("role", "身份"), ("type", "类型"), ("total_lines", "总行数"),
        ("candidate_lines", "候选行"), ("parsed_lines", "解析接受"),
        ("unparsed_candidate_lines", "未识别候选"),
        ("block_ip_entries", "拦截 IP 条目"), ("allow_ip_entries", "放行 IP 条目"),
        ("unique_block_domains", "唯一拦截域名"),
        ("unique_only_domains", "精确独有域名"),
        ("shared_domains", "精确重复域名"),
        ("effective_unique_domains", "父级压缩后独有候选（白名单前）"),
        ("effective_unique_after_whitelist", "白名单后独有候选"),
        ("white_excluded_domains", "被项目白名单排除"),
        ("external_parent_covered_domains", "被其他来源父域名覆盖"),
        ("internal_parent_covered_domains", "被本来源父域名压缩"),
        ("unique_allow_domains", "唯一放行域名"),
        ("unique_filter_rules", "过滤规则"),
        ("unique_dns_pattern_block_rules", "DNS 通配拦截规则"),
        ("unique_dns_pattern_allow_rules", "DNS 通配放行规则"),
        ("dns_pattern_excluded", "宽泛/不支持通配规则（排除）"),
        ("dns_regex_excluded", "DNS 正则规则（未纳入）"),
        ("filter_domain_unresolved", "其他过滤规则未提取域名"),
        ("filter_ip_extracted", "过滤规则提取的 IP（不计域名）")
    ]
    out = [
        "# 上游规则源基线审计", "",
        f"- 正式 DNS/Hosts 来源数：{len(production_names)}",
        f"- 浏览器补充来源数：{len(browser_names)}（只审计域名提取，不计入 DNS 输出）",
        f"- 额外候选来源数：{len(candidate_names)}（仅用于评估，不参与正式构建）",
        f"- 下载成功：{sum(1 for r in results if r['download_ok'])}",
        f"- 下载失败：{sum(1 for r in results if not r['download_ok'])}",
        f"- 正式来源跨来源重复拦截域名：{overlap}",
        f"- 正式来源合并后的唯一域名：{unique_total}",
        "- 候选来源不计入正式来源的交集、独有贡献或最终规则。",
        "- 解析口径：调用仓库当前 Resolver 的原始解析方法；未识别候选不等同于规则无效，需结合规则语法复核。",
        "",
        "| " + " | ".join(label for _, label in cols) + " |",
        "|" + "|".join("---:" if key not in ("name", "role", "type") else "---" for key, _ in cols) + "|"
    ]
    for row in results:
        out.append("| " + " | ".join(str(row.get(key, "")) for key, _ in cols) + " |")
    out.extend(["", "## 下载失败"])
    failed = [r for r in results if not r["download_ok"]]
    if failed:
        for row in failed:
            out.append(f"- {row['name']}: {row['download_error']} ({row['url']})")
    else:
        out.append("- 无")
    out.extend(["", "## 正式来源两两重复（前 20 组）",
                "| 来源 A | 来源 B | 重复域名数 |", "|---|---|---:|"])
    for left, right, count in pairwise[:20]:
        out.append(f"| {left} | {right} | {count} |")
    if candidate_overlaps:
        out.extend(["", "## 候选来源与正式来源的精确重合",
                    "| 候选来源 | 正式来源 | 重复域名数 |", "|---|---|---:|"])
        for candidate, source, count in candidate_overlaps:
            out.append(f"| {candidate} | {source} | {count} |")
    if candidate_pairwise_overlaps:
        out.extend(["", "## 候选来源独有增量之间的重合（已扣除正式来源、父级覆盖及白名单）",
                    "| 候选来源 A | 候选来源 B | 重复域名数 |", "|---|---|---:|"])
        for left, right, count in candidate_pairwise_overlaps:
            out.append(f"| {left} | {right} | {count} |")
    out.extend([
        "", "## 指标说明",
        "- 候选行：排除空行、注释和列表头后的行。",
        "- 解析接受：当前解析器识别为拦截、放行或过滤规则的行。",
        "- 唯一拦截域名：当前解析器可归一化的拦截域名去重数。",
        "- 其他过滤规则未提取域名：不包括已单独统计的宽泛通配模式和未纳入的 DNS 正则规则。",
        "- IP 字面量单独计数，不纳入 DNS 域名唯一数、来源覆盖或基线域名差异。",
        "- 跨来源重复拦截域名：仅统计正式集成来源中解析为 block 的域名；不把候选来源或浏览器过滤规则提取的域名混入。",
        "- 父级压缩后独有候选（白名单前）：先排除其他正式来源的相同域名/父域名覆盖，再排除本来源内被父域名覆盖的子域名。",
        "- 白名单后独有候选：在父级压缩后独有候选基础上，进一步扣除项目 white.txt 中精确域名及其子域名；尚未扣除动态黑名单和上游 allow 规则，因此仍是来源贡献估计，不代表每条都已完成误杀验证。",
        "- 候选来源的独有贡献：仅与正式来源比较，不能反向减少正式来源的独有贡献。",
        "- 过滤规则的域名提取统计单独保留，不计入 AdGuard Home DNS 拦截域名交集。"
    ])
    return "\n".join(out) + "\n"



def load_project_whitelist():
    """Parse DNS-domain exceptions with the same accepted syntax as Filter.__getWhiteDict."""
    path = ROOT / "rules" / "white.txt"
    domains = set()
    if not path.exists():
        return domains
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        if value.startswith("@@||"):
            value = value[4:]
        elif value.startswith("||"):
            value = value[2:]
        # Modifier-bearing exceptions (e.g. $third-party) are browser rules,
        # not DNS-wide whitelist entries; match Filter.__getWhiteDict semantics.
        if "$" in value:
            continue
        if "^" in value:
            value = value.split("^", 1)[0]
        if (not value or value.endswith(".") or
                any(char in value for char in "*/#|?^$")):
            continue
        try:
            parsed = get_tld(value, fix_protocol=True, as_object=True)
            domain = (f"{parsed.subdomain}." if parsed.subdomain else "") + parsed.fld
            domains.add(domain.lower())
        except Exception:
            continue
    return domains


def covered_by_whitelist(domain, whitelist):
    labels = domain.lower().split(".")
    return any(".".join(labels[index:]) in whitelist for index in range(len(labels)))


def unexplained_absent_baseline_domains(source_absent, blacklist, whitelist, source_allow):
    """Exclude baseline-only domains already explained by active project exceptions."""
    return set(source_absent) - set(blacklist) - set(whitelist) - set(source_allow)


def covered_by_rule_domain(domain, ruleset):
    labels = domain.lower().split(".")
    return any(".".join(labels[index:]) in ruleset for index in range(len(labels)))


def dns_pattern_matches_domain(rule, domain):
    """Match an unscoped, validated AdGuard DNS wildcard rule to a hostname."""
    if "$" in rule:
        return False
    prefix = "@@||" if rule.startswith("@@||") else "||" if rule.startswith("||") else None
    if not prefix:
        return False
    body = rule[len(prefix):]
    if not body.endswith("^") or "*" not in body:
        return False
    pattern = re.escape(body[:-1]).replace(r"\*", ".*")
    return re.fullmatch(rf"(?:.*\.)?{pattern}", domain, flags=re.IGNORECASE) is not None


def parse_lite_dns_rules(lines, resolver):
    """Separate exact/suffix host rules from validated wildcard/dnstype rules."""
    exact_blocks, suffix_blocks, allows = set(), set(), set()
    pattern_blocks, pattern_allows = {}, {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(("!", "#")):
            continue
        parsed = resolver.resolveDNSPattern(line)
        if parsed:
            action, base_domain = parsed
            if action == "allow":
                pattern_allows[line] = base_domain
            else:
                pattern_blocks[line] = base_domain
        elif line.startswith("@@||") and line.endswith("^"):
            allows.add(line[4:-1].lower())
        elif line.startswith("||") and line.endswith("^"):
            suffix_blocks.add(line[2:-1].lower())
        elif "." in line and not any(char in line for char in " /\t^$*"):
            exact_blocks.add(line.lower())
    return {
        "exact_blocks": exact_blocks,
        "suffix_blocks": suffix_blocks,
        "allows": allows,
        "pattern_blocks": pattern_blocks,
        "pattern_allows": pattern_allows,
    }


def domains_overlap(left, right):
    """Whether two suffix-scoped DNS domain rules can affect overlapping names."""
    left = left.lower()
    right = right.lower()
    return left == right or left.endswith("." + right) or right.endswith("." + left)


def validate_source_policy(policy, production_names, candidate_names):
    """Validate source roles while allowing explicitly selected candidate-only comparisons."""
    if not isinstance(policy, dict) or policy.get("version") != 1:
        raise ValueError("Unsupported source-policy.json version")
    review_focus_names = set(policy.get("review_focus_sources", []))
    comparison_names = set(policy.get("comparison_sources", []))
    if review_focus_names & comparison_names:
        raise ValueError("Review-focus and comparison source groups must be disjoint")
    if not review_focus_names <= production_names:
        raise ValueError("Review-focus sources must be active production DNS/Hosts sources")
    if (review_focus_names | (comparison_names & production_names)) != production_names:
        raise ValueError("Every production DNS/Hosts source must be classified exactly once")
    unknown = comparison_names - production_names - candidate_names
    if unknown:
        raise ValueError(f"Unknown comparison sources: {sorted(unknown)}")
    return review_focus_names, comparison_names


def classify_review_focus_candidates(review_focus_blocks, comparison_blocks, comparison_allows, whitelist):
    """Separate review-focus-unshared candidates from explicit cross-source allow conflicts.

    A parent block or parent allow covers its subdomains. Absence from a
    comparison source is not treated as an allow decision.
    """
    review_focus_blocks = {domain.lower() for domain in review_focus_blocks}
    comparison_blocks = {domain.lower() for domain in comparison_blocks}
    comparison_allows = {domain.lower() for domain in comparison_allows}

    allow_conflicts = sorted(
        domain for domain in review_focus_blocks
        if any(domains_overlap(domain, allowed) for allowed in comparison_allows)
    )
    review_focus_unshared = sorted(
        domain for domain in review_focus_blocks
        if not covered_by_rule_domain(domain, comparison_blocks)
        and not any(domains_overlap(domain, allowed) for allowed in comparison_allows)
        and not covered_by_whitelist(domain, whitelist)
    )
    return review_focus_unshared, allow_conflicts


def main():
    try:
        update_tld_names()
    except Exception as exc:
        print(f"Warning: public suffix list update failed: {exc}")

    # DNS/Hosts 来源作为正式候选进行贡献审计；浏览器 filter 单独审计其可提取域名，
    # 仅用于解释原作者旧版 DNS 输出差异，绝不将这些域名计入本项目 DNS 正式来源。
    all_rules = ReadMe(str(ROOT / "README.md")).getRules()
    production_rules = [rule for rule in all_rules if rule.type in ("host", "dns", "dnsfilter")]
    browser_rules = [rule for rule in all_rules if rule.type == "filter"]
    # Benchmark currently listed AdGuard HostlistsRegistry DNS filters as audit-only sources.
    # They are never merged into production automatically; contribution and parser coverage
    # are measured first, then false-positive and compatibility evidence is reviewed manually.
    candidate_rules = [
        Rule("CHN: AdRules DNS List (AdGuard Registry candidate only)", "dns",
             "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt", "live upstream"),
        Rule("OISD Blocklist Small (AdGuard Registry candidate only)", "dns",
             "https://small.oisd.nl/", "live upstream"),
        Rule("OISD Blocklist Big (AdGuard Registry benchmark only; higher FP risk)", "dns",
             "https://big.oisd.nl/", "live upstream"),
        Rule("HaGeZi Pro (AdGuard Registry benchmark against Pro Mini)", "dns",
             "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt", "live upstream"),
        Rule("HaGeZi Normal (AdGuard Registry benchmark against Pro Mini)", "dns",
             "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt", "live upstream")
    ]
    rules = production_rules + browser_rules + candidate_rules
    production_names = {rule.name for rule in production_rules}
    browser_names = {rule.name for rule in browser_rules}
    candidate_names = {rule.name for rule in candidate_rules}
    license_manifest = json.loads((ROOT / "source-licenses.json").read_text(encoding="utf-8"))
    license_records = {item["name"]: item for item in license_manifest["sources"]}
    if not candidate_names.issubset(license_records):
        raise ValueError("source-licenses.json is missing candidate source records")
    nonredistributable_candidate_names = {
        name for name in candidate_names
        if not license_records[name].get("redistribute_audit_data", False)
    }
    downloads = asyncio.run(download_all(rules, candidate_names))
    resolver = Resolver(str(SOURCE_DIR))
    results, domain_sets, allow_sets = [], {}, {}

    for rule in rules:
        row, domains, allows = audit_one(rule, resolver, downloads.get(rule.name, {}))
        if rule.name in nonredistributable_candidate_names:
            # Keep aggregate counts and overlap metrics, but do not redistribute
            # normalized domain data from mixed/unclear-license candidate lists.
            source_path = Path(downloads.get(rule.name, {}).get("path", ""))
            if source_path.is_file():
                source_path.unlink()
            for field in ("samples_unparsed", "samples_filter_domain_unresolved", "samples_dns_patterns"):
                row[field] = []
        if rule.name in production_names:
            row["role"] = "正式 DNS/Hosts 来源"
        elif rule.name in browser_names:
            row["role"] = "浏览器补充（不进入 DNS）"
        else:
            row["role"] = "候选源（不集成）"
        results.append(row)
        domain_sets[rule.name] = domains
        allow_sets[rule.name] = allows

    production_sets = {name: domain_sets.get(name, set()) for name in production_names}
    project_whitelist = load_project_whitelist()

    def domain_suffixes(domain):
        labels = domain.lower().split(".")
        return {".".join(labels[index:]) for index in range(len(labels))}

    whitelist_dns_sources = {domain: set() for domain in project_whitelist}
    for whitelist_domain in project_whitelist:
        for source_name in production_names:
            if domain_suffixes(whitelist_domain) & production_sets.get(source_name, set()):
                whitelist_dns_sources[whitelist_domain].add(source_name)

    whitelist_browser_sources = {domain: set() for domain in project_whitelist}
    for source_name in browser_names:
        for source_domain in domain_sets.get(source_name, set()):
            for suffix in domain_suffixes(source_domain):
                if suffix in whitelist_browser_sources:
                    whitelist_browser_sources[suffix].add(source_name)

    whitelist_coverage = {
        domain: {
            "dns_sources": sorted(whitelist_dns_sources[domain]),
            "browser_sources": sorted(whitelist_browser_sources[domain]),
            "used_by_current_sources": bool(
                whitelist_dns_sources[domain] or whitelist_browser_sources[domain]
            ),
        }
        for domain in sorted(project_whitelist)
    }
    whitelist_unused = {
        domain for domain, data in whitelist_coverage.items()
        if not data["used_by_current_sources"]
    }

    memberships = defaultdict(set)
    for name, domains in production_sets.items():
        for domain in domains:
            if domain:
                memberships[domain].add(name)

    overlap = sum(1 for names in memberships.values() if len(names) > 1)
    unique_total = len(memberships)
    effective_unique_after_whitelist_sets = {}

    for row in results:
        name = row["name"]
        own = domain_sets.get(name, set())
        if name in production_names:
            other_sets = [domains for other, domains in production_sets.items() if other != name]
        else:
            other_sets = list(production_sets.values())
        other_domains = set().union(*other_sets) if other_sets else set()

        if name in production_names:
            row["unique_only_domains"] = sum(1 for domain in own if memberships[domain] == {name})
        else:
            # Browser sources and candidate sources are compared only with the
            # production DNS/Hosts set; they never become production DNS inputs.
            row["unique_only_domains"] = sum(1 for domain in own if domain not in memberships)
        row["shared_domains"] = len(own) - row["unique_only_domains"]

        def covered_by_other_parent(domain):
            labels = domain.split(".")
            return any(".".join(labels[index:]) in other_domains for index in range(len(labels)))

        after_external = {domain for domain in own if not covered_by_other_parent(domain)}
        effective_unique = {
            domain for domain in after_external
            if not any(".".join(domain.split(".")[index:]) in after_external
                       for index in range(1, len(domain.split("."))))
        }
        after_whitelist = {domain for domain in effective_unique
                           if not covered_by_whitelist(domain, project_whitelist)}
        effective_unique_after_whitelist_sets[name] = after_whitelist
        row["effective_unique_domains"] = len(effective_unique)
        row["effective_unique_after_whitelist"] = len(after_whitelist)
        row["white_excluded_domains"] = len(effective_unique) - len(after_whitelist)
        row["effective_unique_after_whitelist_samples"] = sorted(after_whitelist)[:100]
        row["external_parent_covered_domains"] = len(own) - len(after_external)
        row["internal_parent_covered_domains"] = len(after_external) - len(effective_unique)
        row["effective_unique_samples"] = sorted(effective_unique)[:100]

    pairwise = []
    for left, right in combinations(sorted(production_names), 2):
        count = len(production_sets.get(left, set()) & production_sets.get(right, set()))
        if count:
            pairwise.append((left, right, count))
    pairwise.sort(key=lambda item: item[2], reverse=True)

    candidate_overlaps = []
    for candidate in sorted(candidate_names):
        for source in sorted(production_names):
            count = len(domain_sets.get(candidate, set()) & production_sets.get(source, set()))
            if count:
                candidate_overlaps.append((candidate, source, count))
    candidate_overlaps.sort(key=lambda item: item[2], reverse=True)

    candidate_pairwise_overlaps = []
    for left, right in combinations(sorted(candidate_names), 2):
        count = len(
            effective_unique_after_whitelist_sets.get(left, set())
            & effective_unique_after_whitelist_sets.get(right, set())
        )
        if count:
            candidate_pairwise_overlaps.append((left, right, count))
    candidate_pairwise_overlaps.sort(key=lambda item: item[2], reverse=True)

    # Review-focus policy is an audit-only comparison, never a production inclusion rule. It never mutates the
    # production resolver inputs or treats non-membership as explicit allow.
    policy_path = ROOT / "source-policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    review_focus_names, comparison_names = validate_source_policy(
        policy, production_names, candidate_names
    )
    review_focus_blocks = set().union(*(production_sets[name] for name in review_focus_names))
    comparison_blocks = set().union(*(domain_sets[name] for name in comparison_names))
    comparison_allows = set().union(*(allow_sets[name] for name in comparison_names))
    review_focus_unshared_candidates, review_focus_allow_conflicts = classify_review_focus_candidates(
        review_focus_blocks, comparison_blocks, comparison_allows, project_whitelist
    )
    allow_conflict_details = []
    for domain in review_focus_allow_conflicts:
        allow_sources = []
        for source_name in sorted(comparison_names):
            matched = sorted(
                allow_domain for allow_domain in allow_sets[source_name]
                if domains_overlap(domain, allow_domain)
            )
            if matched:
                allow_sources.append({"source": source_name, "allow_domains": matched})
        allow_conflict_details.append({
            "domain": domain,
            "review_focus_block_sources": sorted(
                name for name in review_focus_names if domain in production_sets[name]
            ),
            "explicit_allow_sources": allow_sources,
        })

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_domain_list(
        OUT_DIR / "review-focus-unshared-candidates.txt",
        review_focus_unshared_candidates,
        "No review-focus-source-only domains after comparison-source block/allow coverage and project whitelist."
    )
    (OUT_DIR / "source-policy-conflicts.json").write_text(
        json.dumps({
            "policy_version": policy["version"],
            "review_focus_sources": sorted(review_focus_names),
            "comparison_sources": sorted(comparison_names),
            "review_focus_unshared_candidate_count": len(review_focus_unshared_candidates),
            "review_focus_vs_explicit_allow_conflict_count": len(allow_conflict_details),
            "review_focus_vs_explicit_allow_conflicts": allow_conflict_details,
            "review_focus_unshared_candidates_file": "review-focus-unshared-candidates.txt",
            "upstream_lineage_status": "partially_documented",
            "source_independence_claimed": False,
            "policy_note": policy.get("policy_note", ""),
            "lineage_evidence": policy.get("lineage_evidence", []),
            "policy_profiles": policy.get("policy_profiles", []),
            "conflict_resolution": policy.get("conflict_resolution", {}),
            "decision": "audit_only_no_automatic_production_inclusion"
        }, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8"
    )
    unique_dir = OUT_DIR / "effective-unique"
    unique_dir.mkdir(parents=True, exist_ok=True)
    unique_after_whitelist_dir = OUT_DIR / "effective-unique-after-whitelist"
    unique_after_whitelist_dir.mkdir(parents=True, exist_ok=True)
    allow_dir = OUT_DIR / "source-allow-domains"
    allow_dir.mkdir(parents=True, exist_ok=True)
    for row in results:
        name = row["name"]
        if name in nonredistributable_candidate_names:
            continue
        own = domain_sets.get(name, set())
        if name in production_names:
            other_sets = [domains for other, domains in production_sets.items() if other != name]
        else:
            other_sets = list(production_sets.values())
        other_domains = set().union(*other_sets) if other_sets else set()
        after_external = set()
        for domain in own:
            labels = domain.split(".")
            if not any(".".join(labels[index:]) in other_domains for index in range(len(labels))):
                after_external.add(domain)
        unique_domains = [
            domain for domain in after_external
            if not any(".".join(domain.split(".")[index:]) in after_external
                       for index in range(1, len(domain.split("."))))
        ]
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_.")
        (unique_dir / f"{safe_name}.txt").write_text(
            "\n".join(sorted(unique_domains)) + ("\n" if unique_domains else ""), encoding="utf-8"
        )
        after_whitelist_domains = [
            domain for domain in unique_domains
            if not covered_by_whitelist(domain, project_whitelist)
        ]
        (unique_after_whitelist_dir / f"{safe_name}.txt").write_text(
            "\n".join(sorted(after_whitelist_domains)) +
            ("\n" if after_whitelist_domains else ""), encoding="utf-8"
        )
        allow_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_.")
        write_domain_list(
            allow_dir / f"{allow_name}.txt",
            allow_sets.get(name, set()),
            "No source allow domains."
        )

    (OUT_DIR / "whitelist-coverage.json").write_text(
        json.dumps(whitelist_coverage, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_domain_list(
        OUT_DIR / "whitelist-unused.txt",
        whitelist_unused,
        "Every project whitelist domain is exercised by a current upstream source."
    )

    (OUT_DIR / "source-audit.json").write_text(
        json.dumps({
            "audit_generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "production_sources": len(production_names),
            "browser_supplement_sources": len(browser_names),
            "candidate_sources": len(candidate_names),
            "project_whitelist_domains_parsed": len(project_whitelist),
            "sources": results,
            "cross_source_duplicate_domains": overlap,
            "unique_domains_all_production_sources": unique_total,
            "candidate_overlaps": [
                {"candidate": a, "production_source": b, "shared_domains": n}
                for a, b, n in candidate_overlaps
            ],
            "candidate_pairwise_overlaps": [
                {"candidate_a": a, "candidate_b": b, "shared_domains": n}
                for a, b, n in candidate_pairwise_overlaps
            ],
            "top_pairwise_overlaps": [
                {"source_a": a, "source_b": b, "shared_domains": n}
                for a, b, n in pairwise[:20]
            ]
        }, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    report = render_report(
        results, production_names, browser_names, candidate_names,
        overlap, unique_total, pairwise, candidate_overlaps, candidate_pairwise_overlaps
    )
    report += "\n## 重点复核来源与上游谱系审计（仅供人工复核）\n\n"
    report += f"- 重点复核来源：{', '.join(sorted(review_focus_names))}。\n"
    report += f"- 对照来源：{', '.join(sorted(comparison_names))}。\n"
    report += f"- 重点复核来源未共享候选（已排除对照来源父级/精确拦截、明确放行及项目白名单）：{len(review_focus_unshared_candidates)} 条，详见 review-focus-unshared-candidates.txt。\n"
    report += f"- 与对照来源明确放行规则冲突：{len(allow_conflict_details)} 条，详见 source-policy-conflicts.json。\n"
    report += "- 来源未收录不视为明确放行；来源重合不证明上游独立；本报告不自动把重点复核来源候选并入正式规则。\n"
    report += "- 正式 DNS/Hosts 来源的显式 allow 在合并输出中作为兼容性例外，优先于其他正式来源的冲突 block；候选来源的 allow 只作对照，不改变正式输出。\n"
    report += "- 上游谱系证据按公开文档分级记录；致谢不等于当前实际集成，来源重合不构成独立投票。\n"
    report += "- CHN AdRules 候选源含混合上游许可，本项目只保留汇总统计，不在公开审计产物中分发其提取域名文件。\n"
    for evidence in policy.get("lineage_evidence", []):
        report += f"- {evidence.get('source', 'Unknown')}: {evidence.get('relation', 'unspecified')} — {evidence.get('evidence_url', '')}。{evidence.get('interpretation', '')}\n"
    report += "\n### 原作者策略差异（依据公开政策，不作简单投票）\n\n"
    for profile in policy.get("policy_profiles", []):
        sources_label = "、".join(profile.get("sources", []))
        report += f"- {sources_label}（{profile.get('list', '未注明版本')}）：{profile.get('philosophy', '')} 证据：{profile.get('evidence_url', '')}\n"
    report += "\n## 项目白名单当前来源覆盖审计\n\n"
    report += f"- 可解析的项目白名单域名：{len(project_whitelist)} 条。\n"
    report += f"- 被当前 DNS/Hosts 或浏览器补充来源实际覆盖：{len(project_whitelist) - len(whitelist_unused)} 条。\n"
    report += f"- 未命中当前任何来源、仅作为未来防误杀保护的候选项：{len(whitelist_unused)} 条（不自动删除，需逐项确认）。\n"

    # Explain whether baseline-only DNS block rules were extracted from browser filters.
    baseline_path = ROOT / ".cache" / "report" / "baseline-only.txt"
    if not baseline_path.exists():
        # The standalone source-audit workflow does not run the full rule build.
        # Never interpret a missing baseline artifact as an empty difference set.
        unavailable = {
            "baseline_comparison_available": False,
            "reason": "The baseline-only report is generated by the full build workflow and is not available in a standalone source audit.",
            "baseline_path": str(baseline_path.relative_to(ROOT)),
        }
        (OUT_DIR / "baseline-browser-analysis.json").write_text(
            json.dumps(unavailable, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8"
        )
        report += (
            "\n## 原作者基线差异分析\n\n"
            "- 本次未执行：独立来源审计工作流没有运行完整规则构建，因此没有 baseline-only.txt。\n"
            "- 缺少基线数据不代表原作者独有规则为 0 条；请以完整构建工作流生成的差异报告为准。\n"
        )
        (OUT_DIR / "source-audit.md").write_text(report, encoding="utf-8")
        print(report)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as stream:
                stream.write(report)
        required_names = production_names | browser_names
        failed_required = [row["name"] for row in results
                           if row["name"] in required_names and not row["download_ok"]]
        # Candidate benchmarks are informational; an unavailable candidate must not
        # block production when every enabled production source is healthy.
        if failed_required:
            raise SystemExit(
                "Audit incomplete; required source failures=" + ", ".join(failed_required)
            )
        return

    baseline_blocks = set()
    baseline_ip_literals = set()
    baseline_allow_domains = set()
    baseline_allow_ip_literals = set()
    if baseline_path.exists():
        for raw in baseline_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line.startswith("@@||") and line.endswith("^"):
                domain = line[4:-1].lower()
                if is_ip_literal(domain):
                    baseline_allow_ip_literals.add(domain)
                else:
                    baseline_allow_domains.add(domain)
            elif line.startswith("||") and line.endswith("^") and not line.startswith("@@"):
                domain = line[2:-1].lower()
                if is_ip_literal(domain):
                    baseline_ip_literals.add(domain)
                else:
                    baseline_blocks.add(domain)

    browser_domains = set().union(*(domain_sets.get(name, set()) for name in browser_names)) if browser_names else set()
    browser_exact = baseline_blocks & browser_domains

    def covered_by_browser_parent(domain):
        labels = domain.split(".")
        return any(".".join(labels[index:]) in browser_domains for index in range(len(labels)))

    browser_explained = {domain for domain in baseline_blocks if covered_by_browser_parent(domain)}
    browser_unexplained = baseline_blocks - browser_explained
    browser_analysis = {
        "baseline_only_block_rules": len(baseline_blocks),
        "baseline_only_ip_literals_excluded_from_domain_audit": len(baseline_ip_literals),
        "browser_filter_extracted_unique_domains": len(browser_domains),
        "baseline_only_exact_domain_overlap_with_browser_sources": len(browser_exact),
        "baseline_only_domain_or_parent_overlap_with_browser_sources": len(browser_explained),
        "baseline_only_without_browser_domain_overlap": len(browser_unexplained),
        "per_browser_source_exact_domain_overlap": {
            name: len(baseline_blocks & domain_sets.get(name, set()))
            for name in sorted(browser_names)
        }
    }
    report += "\n## 原作者基线独有拦截规则与浏览器来源域名重合分析（非来源归因）\n\n"
    report += "- 本分析只统计原作者基线独有 DNS 拦截规则与当前浏览器补充来源的同域名/父域名重合；重合不证明原作者规则来自该浏览器来源，也不代表浏览器规则可替代 DNS 规则。\n"
    report += f"- 原作者基线独有 DNS 域名拦截规则：{len(baseline_blocks)} 条。\n"
    report += f"- 从域名比较中单独排除的 IP 字面量：{len(baseline_ip_literals)} 条（不属于 DNS 域名规则）。\n"
    report += f"- 浏览器来源可提取的唯一拦截域名：{len(browser_domains)} 个。\n"
    report += f"- 与浏览器来源精确匹配：{len(browser_exact)} 条；被浏览器来源父域名覆盖：{len(browser_explained)} 条；未能由浏览器来源解释：{len(browser_unexplained)} 条。\n"
    report += "\n| 浏览器来源 | 与基线独有拦截规则精确匹配数 |\n|---|---:|\n"
    for name, count in sorted(browser_analysis["per_browser_source_exact_domain_overlap"].items(), key=lambda item: item[1], reverse=True):
        report += f"| {name} | {count} |\n"

    (OUT_DIR / "baseline-browser-analysis.json").write_text(
        json.dumps(browser_analysis, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    write_domain_list(
        OUT_DIR / "baseline-only-browser-overlap.txt",
        browser_explained,
        "No baseline-only block rule overlaps browser-source domains."
    )
    write_domain_list(
        OUT_DIR / "baseline-only-no-browser-overlap.txt",
        browser_unexplained,
        "No baseline-only block rule remains outside browser-source domain coverage."
    )

    # Separate genuine source omissions from exclusions inherited from the
    # current blacklist / project whitelist inputs.
    current_dns_domains = set(memberships)
    current_source_exact = baseline_blocks & current_dns_domains

    blacklist_path = ROOT / ".cache" / "domain" / "black.txt"
    blacklist_domains = set()
    if blacklist_path.exists():
        for raw in blacklist_path.read_text(encoding="utf-8", errors="replace").splitlines():
            value = raw.strip().lower()
            if not value or value.startswith(("#", "!")):
                continue
            if value.startswith("||"):
                value = value[2:]
            if "^" in value:
                value = value.split("^", 1)[0]
            if "$" in value:
                value = value.split("$", 1)[0]
            parts = value.split()
            if parts:
                candidate = parts[-1].rstrip(".")
                if candidate and "/" not in candidate and "*" not in candidate:
                    blacklist_domains.add(candidate)

    current_source_allow_domains = set().union(
        *(allow_sets.get(name, set()) for name in production_names)
    ) if production_names else set()

    def covered_by_source_allow(domain):
        labels = domain.split(".")
        return any(".".join(labels[index:]) in current_source_allow_domains
                   for index in range(len(labels)))

    current_source_exact_blacklisted = current_source_exact & blacklist_domains
    current_source_exact_whitelisted = {
        domain for domain in current_source_exact
        if covered_by_whitelist(domain, project_whitelist)
    }
    current_source_exact_upstream_allowed = {
        domain for domain in current_source_exact
        if covered_by_source_allow(domain)
    }
    current_source_exact_active = (
        current_source_exact
        - current_source_exact_blacklisted
        - current_source_exact_whitelisted
        - current_source_exact_upstream_allowed
    )

    def parent_domains(domain):
        labels = domain.split(".")
        return [".".join(labels[index:]) for index in range(1, len(labels))]

    def covered_by_active_current_parent(domain):
        for parent in parent_domains(domain):
            if (parent in current_dns_domains and parent not in blacklist_domains
                    and not covered_by_whitelist(parent, project_whitelist)
                    and not covered_by_source_allow(parent)):
                return True
        return False

    current_source_parent_present = {
        domain for domain in baseline_blocks - current_source_exact
        if any(parent in current_dns_domains for parent in parent_domains(domain))
    }
    current_source_parent_covered = {
        domain for domain in current_source_parent_present
        if covered_by_active_current_parent(domain)
    }
    current_source_parent_inactive = current_source_parent_present - current_source_parent_covered
    current_source_parent_inactive_blacklisted = {
        domain for domain in current_source_parent_inactive
        if any(parent in blacklist_domains for parent in parent_domains(domain))
    }
    current_source_parent_inactive_whitelisted = {
        domain for domain in current_source_parent_inactive
        if any(covered_by_whitelist(parent, project_whitelist) for parent in parent_domains(domain))
    }
    current_source_parent_inactive_upstream_allowed = {
        domain for domain in current_source_parent_inactive
        if any(covered_by_source_allow(parent) for parent in parent_domains(domain))
    }

    # Parse the generated AdGuard DNS file once; later audit gates use the
    # compiled output as the source of truth for effective block coverage.
    compiled_dns_path = ROOT / ".cache" / "out" / "adblockdns.txt"
    compiled_block_domains = set()
    compiled_allow_domains = set()
    compiled_unparsed = 0
    compiled_non_domain_filters = 0
    if compiled_dns_path.exists():
        for raw in compiled_dns_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith(("!", "#")):
                continue
            try:
                block, unblock, filt = resolver._Resolver__resolveDNS(line)
            except Exception:
                compiled_unparsed += 1
                continue
            block_domain = full_domain(block)
            allow_domain = full_domain(unblock)
            if block_domain:
                compiled_block_domains.add(block_domain)
            if allow_domain:
                compiled_allow_domains.add(allow_domain)
            if filt:
                rule_text = filt[0] if isinstance(filt, (tuple, list)) else str(filt)
                filter_domain = (
                    full_domain(filt[1])
                    if isinstance(filt, (tuple, list)) and len(filt) > 1
                    else None
                )
                if filter_domain:
                    if rule_text.lstrip().startswith("@@"):
                        compiled_allow_domains.add(filter_domain)
                    else:
                        compiled_block_domains.add(filter_domain)
                else:
                    compiled_non_domain_filters += 1

    def covered_by_compiled_output(domain):
        return (
            compiled_dns_path.exists()
            and covered_by_rule_domain(domain, compiled_block_domains)
            and not covered_by_rule_domain(domain, compiled_allow_domains)
        )

    # Explicit allows from active production DNS/Hosts sources are compatibility
    # exceptions across the merged output. Verify that every allow overlapping
    # a compiled block remains effective after generation.
    source_allow_conflicts = {
        allow_domain for allow_domain in current_source_allow_domains
        if any(domains_overlap(allow_domain, block_domain) for block_domain in compiled_block_domains)
    }
    source_allow_missing_still_blocked = {
        allow_domain for allow_domain in source_allow_conflicts
        if not covered_by_rule_domain(allow_domain, compiled_allow_domains)
    }
    write_domain_list(
        OUT_DIR / "source-allow-conflicts-still-blocked.txt",
        source_allow_missing_still_blocked,
        "Every active production-source allow exception overlapping a compiled block remains effective."
    )
    (OUT_DIR / "source-allow-output-audit.json").write_text(
        json.dumps({
            "available": compiled_dns_path.is_file(),
            "active_production_source_allow_domains": len(current_source_allow_domains),
            "allow_domains_overlapping_compiled_blocks": len(source_allow_conflicts),
            "overlapping_allows_missing_from_compiled_output": len(source_allow_missing_still_blocked),
            "missing_allow_samples": sorted(source_allow_missing_still_blocked)[:100],
        }, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    source_presence_parent_output_covered = {
        domain for domain in current_source_exact_active
        if domain not in compiled_block_domains and covered_by_compiled_output(domain)
    }
    source_presence_unexplained = {
        domain for domain in current_source_exact_active
        if not covered_by_compiled_output(domain)
    }
    current_source_parent_inactive_output_covered = {
        domain for domain in current_source_parent_inactive
        if covered_by_compiled_output(domain)
    }
    source_absent = baseline_blocks - current_source_exact - current_source_parent_present
    current_source_parent_inactive_unexplained = (
        current_source_parent_inactive
        - current_source_parent_inactive_blacklisted
        - current_source_parent_inactive_whitelisted
        - current_source_parent_inactive_upstream_allowed
        - current_source_parent_inactive_output_covered
    )
    baseline_only_source_allow_covered = {
        domain for domain in baseline_blocks if covered_by_source_allow(domain)
    }
    blacklist_overlap = baseline_blocks & blacklist_domains
    whitelist_covered = {
        domain for domain in baseline_blocks
        if covered_by_whitelist(domain, project_whitelist)
    }
    source_absent_unexplained = unexplained_absent_baseline_domains(
        source_absent,
        blacklist_overlap,
        whitelist_covered,
        baseline_only_source_allow_covered,
    )
    source_unexplained = (
        source_presence_unexplained
        | current_source_parent_inactive_unexplained
        | source_absent_unexplained
    )
    source_not_effectively_covered = source_unexplained

    # Project-maintained manual blocks are intentionally separate from upstream
    # source attribution, but they still provide effective coverage of baseline
    # domains. Report that coverage explicitly instead of calling it unexplained.
    manual_block_domains = set()
    manual_rules_path = ROOT / "rules" / "myblock.txt"
    if manual_rules_path.exists():
        for raw in manual_rules_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line.startswith("||") and line.endswith("^"):
                domain = line[2:-1].strip().lower()
                if domain and not any(char in domain for char in " /\t^$*"):
                    manual_block_domains.add(domain)
    manual_block_domains = {
        domain for domain in manual_block_domains
        if domain not in blacklist_domains
        and not covered_by_whitelist(domain, project_whitelist)
        and not covered_by_source_allow(domain)
    }
    baseline_manual_block_covered = {
        domain for domain in baseline_blocks
        if covered_by_rule_domain(domain, manual_block_domains)
        and not covered_by_whitelist(domain, project_whitelist)
        and not covered_by_source_allow(domain)
    }
    source_unexplained_after_manual = source_unexplained - baseline_manual_block_covered

    provenance_path = ROOT / ".cache" / "domain" / "input-provenance.txt"
    input_provenance = {}
    if provenance_path.exists():
        for raw in provenance_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "\t" in raw:
                key, value = raw.split("\t", 1)
                input_provenance[key] = value

    # Attribute baseline-only DNS blocks to the upstream author's OISD Basic
    # snapshot separately from the current AdBlock DNS OISD Small source.
    baseline_candidate_analysis = {}
    for candidate in sorted(candidate_names):
        candidate_row = next(row for row in results if row["name"] == candidate)
        if not candidate_row["download_ok"]:
            baseline_candidate_analysis[candidate] = {
                "available": False,
                "reason": candidate_row.get("download_error") or "candidate source download failed",
            }
            continue
        candidate_domains = domain_sets.get(candidate, set())
        exact = baseline_blocks & candidate_domains
        parent_covered = {
            domain for domain in baseline_blocks
            if any(".".join(domain.split(".")[index:]) in candidate_domains
                   for index in range(1, len(domain.split("."))))
        }
        baseline_candidate_analysis[candidate] = {
            "available": True,
            "candidate_unique_domains": len(candidate_domains),
            "baseline_only_exact_overlap": len(exact),
            "baseline_only_parent_covered": len(parent_covered),
            "baseline_only_exact_or_parent_covered": len(exact | parent_covered),
            "baseline_only_not_covered": len(baseline_blocks - exact - parent_covered),
            "exact_overlap_samples": sorted(exact)[:100],
            "parent_coverage_samples": sorted(parent_covered)[:100],
        }

    browser_analysis.update({
        "baseline_comparison_available": True,
        "baseline_candidate_analysis": baseline_candidate_analysis,
        "current_dns_source_unique_domains": len(current_dns_domains),
        "current_dns_source_allow_domains": len(current_source_allow_domains),
        "baseline_only_exactly_present_in_current_dns_sources": len(current_source_exact),
        "baseline_only_exact_source_rules_excluded_by_blacklist": len(current_source_exact_blacklisted),
        "baseline_only_exact_source_rules_excluded_by_whitelist": len(current_source_exact_whitelisted),
        "baseline_only_exact_source_rules_excluded_by_upstream_allow": len(current_source_exact_upstream_allowed),
        "baseline_only_source_allow_covered": len(baseline_only_source_allow_covered),
        "baseline_only_current_source_rules_covered_by_compiled_output_parent": len(source_presence_parent_output_covered),
        "baseline_only_parent_inactive_rules_covered_by_compiled_output": len(current_source_parent_inactive_output_covered),
        "baseline_only_exact_source_rules_active_but_missing_from_output": len(source_presence_unexplained),
        "baseline_only_parent_present_in_current_dns_sources": len(current_source_parent_present),
        "baseline_only_covered_by_active_current_source_parent": len(current_source_parent_covered),
        "baseline_only_parent_inactive": len(current_source_parent_inactive),
        "baseline_only_parent_inactive_blacklisted": len(current_source_parent_inactive_blacklisted),
        "baseline_only_parent_inactive_whitelisted": len(current_source_parent_inactive_whitelisted),
        "baseline_only_parent_inactive_upstream_allowed": len(current_source_parent_inactive_upstream_allowed),
        "baseline_only_parent_inactive_unexplained": len(current_source_parent_inactive_unexplained),
        "baseline_only_blacklist_exact_overlap": len(blacklist_overlap),
        "baseline_only_project_whitelist_parent_coverage": len(whitelist_covered),
        "baseline_only_not_effectively_covered_by_current_dns_sources": len(source_unexplained),
        "baseline_only_project_manual_block_covered": len(baseline_manual_block_covered),
        "baseline_only_unexplained_after_manual_blocks": len(source_unexplained_after_manual),
        "baseline_only_absent_from_current_dns_sources": len(source_absent),
        "blacklist_input_available": blacklist_path.exists(),
        "domain_input_provenance": input_provenance
    })
    report += "\n## 原作者基线差异与当前 DNS 来源、黑名单、白名单及来源放行的关系\n\n"
    report += f"- 当前六个 DNS/Hosts 来源合并的精确域名数：{len(current_dns_domains)}；来源放行域名：{len(current_source_allow_domains)}。\n"
    report += f"- 与编译拦截规则冲突的正式来源 allow：{len(source_allow_conflicts)} 条；未在编译输出中保留有效放行：{len(source_allow_missing_still_blocked)} 条。\n"
    report += f"- 基线独有 block 中，精确存在于当前 DNS 来源：{len(current_source_exact)} 条；另有父域名来源覆盖：{len(current_source_parent_present)} 条。\n"
    report += f"- 精确来源规则中，被当前黑名单排除：{len(current_source_exact_blacklisted)} 条；被项目白名单覆盖：{len(current_source_exact_whitelisted)} 条；被上游来源 allow 规则覆盖：{len(current_source_exact_upstream_allowed)} 条。\n"
    report += f"- 基线 block 被当前来源 allow 精确或父域名覆盖：{len(baseline_only_source_allow_covered)} 条。\n"
    report += f"- 当前来源精确域名虽未逐条输出、但已由编译结果父规则覆盖：{len(source_presence_parent_output_covered)} 条。\n"
    report += f"- 原作者基线域名的当前来源父规则虽经 DNS 判为失效、但已由实际编译输出规则覆盖：{len(current_source_parent_inactive_output_covered)} 条。\n"
    report += f"- 当前来源中存在、未被黑/白名单或来源 allow 解释、且未被任何编译输出规则覆盖：{len(source_presence_unexplained)} 条。\n"
    report += f"- 父域名来源覆盖：有效父域名 {len(current_source_parent_covered)} 条；失效或被例外排除的父域名 {len(current_source_parent_inactive)} 条（黑名单 {len(current_source_parent_inactive_blacklisted)}、白名单 {len(current_source_parent_inactive_whitelisted)}、来源 allow {len(current_source_parent_inactive_upstream_allowed)}、仍未解释 {len(current_source_parent_inactive_unexplained)}）。\n"
    report += f"- 当前六个 DNS/Hosts 来源中既无精确规则也无父域名：{len(source_absent)} 条。\n"
    report += f"- 上述来源缺失项中，已由当前黑名单排除：{len(blacklist_overlap & source_absent)} 条；由项目白名单覆盖：{len(whitelist_covered & source_absent)} 条；由来源 allow 覆盖：{len(baseline_only_source_allow_covered & source_absent)} 条。\n"
    report += f"- 项目手工补充拦截规则覆盖的基线独有域名：{len(baseline_manual_block_covered)} 条（独立于上游来源统计）。\n"
    report += f"- 扣除项目手工拦截后，仍未由当前来源、黑名单、白名单、来源 allow 或手工规则解释的基线差异：{len(source_unexplained_after_manual)} 条。\n"
    report += f"- 黑名单文件存在：{blacklist_path.exists()}；输入来源：{input_provenance.get('black.txt', '未记录')}。\n"
    report += "- DNS NXDOMAIN 只用于解释确实经过本项目 DNS 验证的域名；未验证的基线独有域名不得假定为失效。\n"
    manual_block_audit = {"available": compiled_dns_path.exists(), "manual_block_domains": len(manual_block_domains)}
    if compiled_dns_path.exists():
        manual_block_covered = {
            domain for domain in manual_block_domains
            if covered_by_rule_domain(domain, compiled_block_domains)
            and not covered_by_rule_domain(domain, compiled_allow_domains)
        }
        manual_block_missing = manual_block_domains - manual_block_covered
        manual_block_audit.update({
            "covered": len(manual_block_covered),
            "missing": len(manual_block_missing),
            "missing_domains": sorted(manual_block_missing),
        })
        write_domain_list(
            OUT_DIR / "manual-block-domains-covered.txt",
            manual_block_covered,
            "No active manual block domains."
        )
        write_domain_list(
            OUT_DIR / "manual-block-domains-missing.txt",
            manual_block_missing,
            "All active manual block domains are present in compiled DNS output."
        )
        report += "\n## 项目手工拦截规则回归\n\n"
        report += f"- 应进入 Full DNS 输出的手工拦截域名：{len(manual_block_domains)} 条；实际覆盖：{len(manual_block_covered)} 条；缺失：{len(manual_block_missing)} 条。\n"
        if manual_block_missing:
            raise SystemExit(
                "Manual block regression failed: "
                + ", ".join(sorted(manual_block_missing))
            )
    (OUT_DIR / "manual-block-audit.json").write_text(
        json.dumps(manual_block_audit, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    lite_scope = {"available": False, "reason": "current domain input, domestic classification, or DNS Lite output is unavailable"}
    domain_input_path = ROOT / ".cache" / "domain" / "domain.txt"
    validation_input_path = ROOT / ".cache" / "domain" / "validated-domain-input.txt"
    china_input_path = ROOT / ".cache" / "domain" / "china.txt"
    china_provenance_path = ROOT / ".cache" / "domain" / "china-classification.json"
    lite_dns_path = ROOT / ".cache" / "out" / "adblockdnslite.txt"
    if domain_input_path.exists() and china_input_path.exists() and lite_dns_path.exists():
        source_input_domains = {
            line.strip().lower()
            for line in domain_input_path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.lstrip().startswith(("#", "!"))
        }
        validated_domains = set()
        if validation_input_path.exists():
            validated_domains = {
                line.strip().lower()
                for line in validation_input_path.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip() and not line.lstrip().startswith(("#", "!"))
            }
        china_domains = {
            line.strip().lower()
            for line in china_input_path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.lstrip().startswith(("#", "!"))
        }
        china_provenance = {}
        if china_provenance_path.exists():
            china_provenance = json.loads(china_provenance_path.read_text(encoding="utf-8"))
        lite_rules = parse_lite_dns_rules(
            lite_dns_path.read_text(encoding="utf-8", errors="replace").splitlines(),
            Resolver(str(SOURCE_DIR)),
        )
        lite_blocks_exact = lite_rules["exact_blocks"]
        lite_blocks_suffix = lite_rules["suffix_blocks"]
        lite_allows = lite_rules["allows"]
        lite_pattern_blocks = lite_rules["pattern_blocks"]
        lite_pattern_allows = lite_rules["pattern_allows"]
        lite_pattern_base_domains = set(lite_pattern_blocks.values())

        source_block_domains = set().union(
            *(domain_sets.get(name, set()) for name in production_names)
        ) if production_names else set()
        source_block_domains = {
            domain.lower() for domain in source_block_domains
            if domain and not is_ip_literal(domain)
        }
        china_source_blocks = source_block_domains & china_domains
        validated_non_china_source_blocks = (
            source_block_domains & validated_domains
        ) - china_domains
        unvalidated_source_blocks = source_block_domains - validated_domains

        def lite_block_covers(domain):
            return (
                domain in lite_blocks_exact
                or covered_by_rule_domain(domain, lite_blocks_suffix)
                or domain in lite_pattern_base_domains
                or any(
                    dns_pattern_matches_domain(rule, domain)
                    for rule in lite_pattern_blocks
                )
            )

        def lite_allow_covers(domain):
            return (
                covered_by_rule_domain(domain, lite_allows)
                or any(
                    dns_pattern_matches_domain(rule, domain)
                    for rule in lite_pattern_allows
                )
            )

        known_non_china_covered = {
            domain for domain in validated_non_china_source_blocks
            if lite_block_covers(domain) and not lite_allow_covers(domain)
        }
        china_source_missing = {
            domain for domain in china_source_blocks
            if not lite_block_covers(domain)
            and not lite_allow_covers(domain)
            and not covered_by_whitelist(domain, project_whitelist)
        }
        lite_rules_not_classified_china = (
            lite_blocks_exact | lite_blocks_suffix | lite_pattern_base_domains
        ) - china_domains
        lite_suffix_rules_not_classified_china = lite_blocks_suffix - china_domains

        lite_scope = {
            "available": True,
            "source_domain_input_count": len(source_input_domains),
            "validated_domain_input_count": len(validated_domains),
            "china_classification_mode": china_provenance.get(
                "generator", "conservative direct-domain classification"
            ),
            "china_classification_policy": china_provenance.get("classification_policy", []),
            "china_classified_domain_count": len(china_domains),
            "current_source_block_domain_count": len(source_block_domains),
            "china_classified_source_block_domains": len(china_source_blocks),
            "validated_non_china_source_block_domains": len(validated_non_china_source_blocks),
            "unvalidated_current_source_block_domains": len(unvalidated_source_blocks),
            "lite_block_rules": (
                len(lite_blocks_exact) + len(lite_blocks_suffix) + len(lite_pattern_blocks)
            ),
            "lite_exact_block_rules": len(lite_blocks_exact),
            "lite_suffix_block_rules": len(lite_blocks_suffix),
            "lite_pattern_block_rules": len(lite_pattern_blocks),
            "lite_allow_rules": len(lite_allows) + len(lite_pattern_allows),
            "lite_pattern_allow_rules": len(lite_pattern_allows),
            "lite_rules_not_classified_china": len(lite_rules_not_classified_china),
            "lite_suffix_rules_not_classified_china": len(lite_suffix_rules_not_classified_china),
            "known_non_china_source_domains_effectively_blocked_by_lite": len(known_non_china_covered),
            "china_classified_source_domains_missing_from_lite": len(china_source_missing),
        }
        write_domain_list(
            OUT_DIR / "lite-scope-known-non-china-covered.txt",
            known_non_china_covered,
            "No DNS-validated non-China source domain is effectively blocked by Lite.",
        )
        write_domain_list(
            OUT_DIR / "lite-scope-china-domains-missing.txt",
            china_source_missing,
            "All direct-classified domestic source block domains are represented in Lite.",
        )
        write_domain_list(
            OUT_DIR / "lite-scope-rules-not-classified-china.txt",
            lite_rules_not_classified_china,
            "Every Lite DNS block rule root is in the domestic classification set.",
        )
        write_domain_list(
            OUT_DIR / "lite-scope-unvalidated-source-domains.txt",
            unvalidated_source_blocks,
            "Unvalidated current source domains are listed here; no DNS liveness inference is made.",
        )
        write_domain_list(
            OUT_DIR / "lite-scope-pattern-block-rules.txt",
            set(lite_pattern_blocks),
            "No wildcard or dnstype DNS block patterns are present in Lite.",
        )

    (OUT_DIR / "lite-scope-audit.json").write_text(
        json.dumps(lite_scope, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    if not lite_scope["available"]:
        raise SystemExit("Lite domestic scope audit unavailable: " + lite_scope["reason"])
    if (
        lite_scope["lite_rules_not_classified_china"]
        or lite_scope["china_classified_source_domains_missing_from_lite"]
    ):
        raise SystemExit(
            "Lite scope quality gate failed: "
            + json.dumps(lite_scope, ensure_ascii=False, sort_keys=True)
        )
    report += "\n## Lite 国内域名范围审计\n\n"
    report += f"- 国内分类方式：{lite_scope['china_classification_mode']}。\n"
    report += f"- 当前 DNS/Hosts 来源域名输入：{lite_scope['source_domain_input_count']} 条；独立 DNS 验证输入：{lite_scope['validated_domain_input_count']} 条；国内分类域名：{lite_scope['china_classified_domain_count']} 条。\n"
    report += f"- Lite 拦截规则：{lite_scope['lite_block_rules']} 条（精确主机：{lite_scope['lite_exact_block_rules']}；后缀规则：{lite_scope['lite_suffix_block_rules']}；通配/类型限定模式：{lite_scope['lite_pattern_block_rules']}）；放行例外：{lite_scope['lite_allow_rules']} 条。\n"
    report += f"- 已归类为国内的来源拦截域名，未被 Lite 拦截或放行规则覆盖：{lite_scope['china_classified_source_domains_missing_from_lite']} 条。\n"
    report += f"- 当前来源中尚未进入 DNS 验证状态的域名：{lite_scope['unvalidated_current_source_block_domains']} 条；未验证不等于非国内。\n"
    report += f"- 已验证为非国内、但被 Lite 规则覆盖的来源域名：{lite_scope['known_non_china_source_domains_effectively_blocked_by_lite']} 条（仅统计有成功 DNS 验证记录的域名）。\n"

    baseline_allow_current_covered = {
        domain for domain in baseline_allow_domains
        if covered_by_rule_domain(domain, compiled_allow_domains)
    }
    baseline_allow_missing = baseline_allow_domains - baseline_allow_current_covered
    baseline_allow_missing_still_blocked = {
        domain for domain in baseline_allow_missing
        if covered_by_rule_domain(domain, compiled_block_domains)
    }
    baseline_allow_missing_not_needed = baseline_allow_missing - baseline_allow_missing_still_blocked

    browser_analysis.update({
        "baseline_allow_rules": len(baseline_allow_domains),
        "baseline_allow_current_exact_or_parent_covered": len(baseline_allow_current_covered),
        "baseline_allow_missing_but_still_blocked": len(baseline_allow_missing_still_blocked),
        "baseline_allow_missing_and_not_currently_blocked": len(baseline_allow_missing_not_needed),
        "baseline_allow_missing_still_blocked_samples": sorted(baseline_allow_missing_still_blocked)[:100],
        "compiled_dns_unparsed_lines": compiled_unparsed,
    })
    (OUT_DIR / "baseline-only-allow-exceptions-still-blocked.txt").write_text(
        "\n".join(sorted(baseline_allow_missing_still_blocked))
        + ("\n" if baseline_allow_missing_still_blocked else ""),
        encoding="utf-8",
    )
    (OUT_DIR / "baseline-only-allow-exceptions-no-longer-needed.txt").write_text(
        "\n".join(sorted(baseline_allow_missing_not_needed))
        + ("\n" if baseline_allow_missing_not_needed else ""),
        encoding="utf-8",
    )
    report += "\n## 原作者基线 allow 例外规则复核\n\n"
    report += f"- 原作者独有 allow 规则：{len(baseline_allow_domains)} 条。\n"
    report += f"- 当前编译输出中有精确或父域名 allow 覆盖：{len(baseline_allow_current_covered)} 条。\n"
    report += f"- 当前没有 allow 覆盖、但仍被 AdBlock DNS block 规则覆盖：{len(baseline_allow_missing_still_blocked)} 条（需要人工判断是否应保留例外）。\n"
    report += f"- 当前没有 allow 覆盖且也没有被 AdBlock DNS block 规则覆盖：{len(baseline_allow_missing_not_needed)} 条（目前不需要额外例外）。\n"
    if baseline_allow_missing_still_blocked:
        report += "\n| 原作者 allow 域名 | 当前覆盖它的 block 规则 |\n|---|---|\n"
        for domain in sorted(baseline_allow_missing_still_blocked):
            matches = sorted(rule for rule in compiled_block_domains
                             if domain == rule or domain.endswith("." + rule))
            report += f"| {domain} | {', '.join(matches)} |\n"
    report += f"\n- 当前编译 DNS 输出无法归一化的规则行：{compiled_unparsed} 条；这些行另需结合原始语法审查。\n"

    report += "\n### 原作者 OISD 来源快照对基线差异的覆盖\n\n"
    report += "- 上游 README 标注为 OISD Basic 的 release 资产，实际 payload 标题为 OISD Small；本次与正式 OISD Small 快照共享 62,805/62,806 个可解析拦截域名（双方各有 1 个快照差异），不视为独立新增来源。\n"
    report += "| 候选来源 | 可解析域名 | 基线独有精确重合 | 父域名覆盖 | 合计覆盖 | 未覆盖 |\n|---|---:|---:|---:|---:|---:|\n"
    for candidate, stats in sorted(baseline_candidate_analysis.items()):
        if not stats.get("available"):
            report += f"| {candidate} | 不可用 | 不可用 | 不可用 | 不可用 | 不可用 |\n"
            continue
        report += (
            f"| {candidate} | {stats['candidate_unique_domains']} | "
            f"{stats['baseline_only_exact_overlap']} | "
            f"{stats['baseline_only_parent_covered']} | "
            f"{stats['baseline_only_exact_or_parent_covered']} | "
            f"{stats['baseline_only_not_covered']} |\n"
        )

    write_domain_list(
        OUT_DIR / "baseline-only-manual-block-covered.txt",
        baseline_manual_block_covered,
        "No upstream baseline-only block is covered by project manual blocks."
    )
    write_domain_list(
        OUT_DIR / "baseline-only-unexplained-after-manual.txt",
        source_unexplained_after_manual,
        "No baseline-only block remains unexplained after manual blocks."
    )
    write_domain_list(
        OUT_DIR / "baseline-only-current-dns-source-overlap.txt",
        current_source_exact | current_source_parent_present,
        "No baseline-only block rule is present in current DNS sources."
    )
    write_domain_list(
        OUT_DIR / "baseline-only-current-source-allow-covered.txt",
        baseline_only_source_allow_covered,
        "No baseline-only block rule is covered by current source allow rules."
    )
    write_domain_list(
        OUT_DIR / "baseline-only-current-source-parent-inactive.txt",
        current_source_parent_inactive,
        "No baseline-only block rule has an inactive current-source parent."
    )
    write_domain_list(
        OUT_DIR / "baseline-only-current-source-parent-inactive-blacklisted.txt",
        current_source_parent_inactive_blacklisted,
        "No baseline-only block rule has a blacklisted current-source parent."
    )
    write_domain_list(
        OUT_DIR / "baseline-only-current-source-parent-inactive-whitelisted.txt",
        current_source_parent_inactive_whitelisted,
        "No baseline-only block rule has a whitelisted current-source parent."
    )
    write_domain_list(
        OUT_DIR / "baseline-only-current-source-parent-inactive-allowed.txt",
        current_source_parent_inactive_upstream_allowed,
        "No baseline-only block rule has a source-allowed current-source parent."
    )
    write_domain_list(
        OUT_DIR / "baseline-only-current-blacklist-overlap.txt",
        blacklist_overlap,
        "No baseline-only rule is excluded by the current blacklist."
    )
    write_domain_list(
        OUT_DIR / "baseline-only-current-whitelist-covered.txt",
        whitelist_covered,
        "No baseline-only rule is covered by the project whitelist."
    )
    write_domain_list(
        OUT_DIR / "baseline-only-current-source-parent-output-covered.txt",
        source_presence_parent_output_covered,
        "No baseline-only current-source domain is covered by a compiled parent rule."
    )
    write_domain_list(
        OUT_DIR / "baseline-only-parent-inactive-output-covered.txt",
        current_source_parent_inactive_output_covered,
        "No baseline-only domain with an inactive current-source parent is covered by the compiled output."
    )
    write_domain_list(
        OUT_DIR / "baseline-only-current-source-unexplained.txt",
        source_presence_unexplained,
        "No active current-source rule is missing from the generated DNS output."
    )
    write_domain_list(
        OUT_DIR / "baseline-only-not-effectively-covered-by-current-dns.txt",
        source_not_effectively_covered,
        "All baseline-only block rules are effectively covered by current DNS sources."
    )
    write_domain_list(
        OUT_DIR / "baseline-only-absent-from-current-dns-sources.txt",
        source_absent,
        "No baseline-only block rule is absent from current DNS sources."
    )

    (OUT_DIR / "baseline-browser-analysis.json").write_text(
        json.dumps(browser_analysis, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    report += "\n## 上游基线差异的处理原则\n\n"
    report += "- 上游基线独有域名与本项目当前所选来源不一致时，差异保留在审计清单中，供持续人工复核；不自动加入白名单，也不盲目全量导入。\n"
    report += "- 这类差异本身不作为硬失败，因为本项目不是逐条复制上游输出；硬门槛仍要求当前启用来源中的有效规则不丢失、编译结果可解析，并且上游明确的 allow 例外不被误拦。\n"
    report += "- 只有有独立证据支持的广告、跟踪或钓鱼域名才补入维护规则；只有有充分证据确认正常且必要的业务域名才可排除；证据不足的项目继续保留待审。\n"

    (OUT_DIR / "source-audit.md").write_text(report, encoding="utf-8")
    print(report)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write(report)

    required_names = production_names | browser_names
    failed_required = [row["name"] for row in results
                       if row["name"] in required_names and not row["download_ok"]]
    # Candidate benchmarks are informational; an unavailable candidate must not
    # block production when every enabled production source is healthy.
    if failed_required:
        raise SystemExit(
            "Audit incomplete; required source failures=" + ", ".join(failed_required)
        )

    gate_failures = source_audit_gate_failures(
        compiled_unparsed,
        compiled_non_domain_filters,
        source_presence_unexplained,
        current_source_parent_inactive_unexplained,
        baseline_allow_missing_still_blocked,
        source_allow_missing_still_blocked,
    )
    if gate_failures:
        raise SystemExit("Source/output consistency gate failed:\n- " + "\n- ".join(gate_failures))


if __name__ == "__main__":
    configure_logging()
    main()
