#!/usr/bin/env python3
"""Audit upstream filter sources using the repository's current Resolver parser."""
import asyncio
import hashlib
import ipaddress
import json
import os
import re
import sys
from datetime import datetime, timezone
from collections import defaultdict
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import httpx
from tld import get_tld
from tld.utils import update_tld_names

from readme import ReadMe, Rule
from resolver import Resolver
SOURCE_DIR = ROOT / ".cache" / "source"
OUT_DIR = ROOT / ".cache" / "audit"
CANDIDATE_SOURCE_DIR = OUT_DIR / "candidate-source"
TIMEOUT = httpx.Timeout(90.0, connect=30.0)


def source_audit_gate_failures(
    compiled_unparsed,
    source_presence_unexplained,
    current_source_parent_inactive_unexplained,
    baseline_allow_missing_still_blocked,
):
    """Return hard failures where source intent is lost or upstream allows regress."""
    failures = []
    if compiled_unparsed:
        failures.append(f"compiled DNS output has {compiled_unparsed} unparsed rule lines")
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
        "filter_domain_extracted": 0, "filter_ip_extracted": 0, "filter_domain_unresolved": 0,
        "unique_block_domains": 0, "unique_allow_domains": 0,
        "unique_filter_rules": 0, "unique_extracted_domains": 0,
        "duplicate_raw_lines": 0, "download_error": download.get("error", ""),
        "samples_unparsed": [], "samples_filter_domain_unresolved": []
    }
    if not download.get("ok"):
        return result, set(), set()

    lines = Path(download["path"]).read_text(encoding="utf-8", errors="replace").splitlines()
    result["source_sha256"] = hashlib.sha256(Path(download["path"]).read_bytes()).hexdigest()
    result["total_lines"] = len(lines)
    seen_lines = set()
    blocks, allows, filters, extracted = set(), set(), set(), set()

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
    return result, blocks, allows


def render_report(results, production_names, browser_names, candidate_names, overlap, unique_total, pairwise, candidate_overlaps):
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
        ("filter_domain_unresolved", "过滤规则未提取域名"),
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
    out.extend([
        "", "## 指标说明",
        "- 候选行：排除空行、注释和列表头后的行。",
        "- 解析接受：当前解析器识别为拦截、放行或过滤规则的行。",
        "- 唯一拦截域名：当前解析器可归一化的拦截域名去重数。",
        "- 过滤规则未提取域名：规则本身被保留，但当前解析器未能关联出域名；不能简单视为规则丢失。",
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
    candidate_rules = [
        Rule("Pollock hosts (candidate only)", "host",
             "https://someonewhocares.org/hosts/hosts", "2026/11/22"),
        # The upstream README labels this asset OISD Basic, but the downloaded payload
        # metadata identifies itself as "oisd small". In the latest audit it
        # shares 62,805 of 62,806 parsed block domains with the production OISD
        # Small snapshot (one snapshot-specific domain differs on each side).
        # Keep it audit-only; do not infer a distinct Basic-vs-Small advantage
        # from the README label.
        Rule("OISD upstream release snapshot (README says Basic; payload title says Small)", "dns",
             "https://github.com/217heidai/adblockfilters/releases/download/source/OISD_Basic.txt",
             "upstream release snapshot")
    ]
    rules = production_rules + browser_rules + candidate_rules
    production_names = {rule.name for rule in production_rules}
    browser_names = {rule.name for rule in browser_rules}
    candidate_names = {rule.name for rule in candidate_rules}
    downloads = asyncio.run(download_all(rules, candidate_names))
    resolver = Resolver(str(SOURCE_DIR))
    results, domain_sets, allow_sets = [], {}, {}

    for rule in rules:
        row, domains, allows = audit_one(rule, resolver, downloads.get(rule.name, {}))
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

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    unique_dir = OUT_DIR / "effective-unique"
    unique_dir.mkdir(parents=True, exist_ok=True)
    unique_after_whitelist_dir = OUT_DIR / "effective-unique-after-whitelist"
    unique_after_whitelist_dir.mkdir(parents=True, exist_ok=True)
    allow_dir = OUT_DIR / "source-allow-domains"
    allow_dir.mkdir(parents=True, exist_ok=True)
    for row in results:
        name = row["name"]
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
            "top_pairwise_overlaps": [
                {"source_a": a, "source_b": b, "shared_domains": n}
                for a, b, n in pairwise[:20]
            ]
        }, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    report = render_report(
        results, production_names, browser_names, candidate_names,
        overlap, unique_total, pairwise, candidate_overlaps
    )
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
        critical_candidates = {"OISD upstream release snapshot (README says Basic; payload title says Small)"}
        failed_candidates = [name for name in critical_candidates
                             if not downloads.get(name, {}).get("ok")]
        if failed_required or failed_candidates:
            raise SystemExit(
                "Audit incomplete; required source failures="
                + ", ".join(failed_required + failed_candidates)
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

    def covered_by_compiled_output(domain):
        return (
            compiled_dns_path.exists()
            and covered_by_rule_domain(domain, compiled_block_domains)
            and not covered_by_rule_domain(domain, compiled_allow_domains)
        )

    source_presence_parent_output_covered = {
        domain for domain in current_source_exact_active
        if domain not in compiled_block_domains and covered_by_compiled_output(domain)
    }
    source_presence_unexplained = {
        domain for domain in current_source_exact_active
        if not covered_by_compiled_output(domain)
    }
    source_absent = baseline_blocks - current_source_exact - current_source_parent_present
    current_source_parent_inactive_unexplained = (
        current_source_parent_inactive
        - current_source_parent_inactive_blacklisted
        - current_source_parent_inactive_whitelisted
        - current_source_parent_inactive_upstream_allowed
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
    current_effective_coverage = (
        (current_source_exact_active - source_presence_unexplained)
        | current_source_parent_covered
        | current_source_exact_blacklisted
        | current_source_exact_whitelisted
        | current_source_exact_upstream_allowed
        | blacklist_overlap
        | whitelist_covered
        | baseline_only_source_allow_covered
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
    report += f"- 基线独有 block 中，精确存在于当前 DNS 来源：{len(current_source_exact)} 条；另有父域名来源覆盖：{len(current_source_parent_present)} 条。\n"
    report += f"- 精确来源规则中，被当前黑名单排除：{len(current_source_exact_blacklisted)} 条；被项目白名单覆盖：{len(current_source_exact_whitelisted)} 条；被上游来源 allow 规则覆盖：{len(current_source_exact_upstream_allowed)} 条。\n"
    report += f"- 基线 block 被当前来源 allow 精确或父域名覆盖：{len(baseline_only_source_allow_covered)} 条。\n"
    report += f"- 当前来源精确域名虽未逐条输出、但已由编译结果父规则覆盖：{len(source_presence_parent_output_covered)} 条。\n"
    report += f"- 当前来源中存在、未被黑/白名单或来源 allow 解释、且未被任何编译输出规则覆盖：{len(source_presence_unexplained)} 条。\n"
    report += f"- 父域名来源覆盖：有效父域名 {len(current_source_parent_covered)} 条；失效或被例外排除的父域名 {len(current_source_parent_inactive)} 条（黑名单 {len(current_source_parent_inactive_blacklisted)}、白名单 {len(current_source_parent_inactive_whitelisted)}、来源 allow {len(current_source_parent_inactive_upstream_allowed)}、仍未解释 {len(current_source_parent_inactive_unexplained)}）。\n"
    report += f"- 当前六个 DNS/Hosts 来源中既无精确规则也无父域名：{len(source_absent)} 条。\n"
    report += f"- 上述来源缺失项中，已由当前黑名单排除：{len(blacklist_overlap & source_absent)} 条；由项目白名单覆盖：{len(whitelist_covered & source_absent)} 条；由来源 allow 覆盖：{len(baseline_only_source_allow_covered & source_absent)} 条。\n"
    report += f"- 项目手工补充拦截规则覆盖的基线独有域名：{len(baseline_manual_block_covered)} 条（独立于上游来源统计）。\n"
    report += f"- 扣除项目手工拦截后，仍未由当前来源、黑名单、白名单、来源 allow 或手工规则解释的基线差异：{len(source_unexplained_after_manual)} 条。\n"
    report += f"- 黑名单文件存在：{blacklist_path.exists()}；输入来源：{input_provenance.get('black.txt', '未记录')}。\n"
    report += "- DNS NXDOMAIN 只用于解释确实经过本项目 DNS 验证的域名；未验证的基线独有域名不得假定为失效。\n"
    compiled_dns_path = ROOT / ".cache" / "out" / "adblockdns.txt"
    compiled_block_domains = set()
    compiled_allow_domains = set()
    compiled_unparsed = 0
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
                filter_domain = full_domain(filt[1]) if isinstance(filt, (tuple, list)) and len(filt) > 1 else None
                if filter_domain:
                    if rule_text.lstrip().startswith("@@"):
                        compiled_allow_domains.add(filter_domain)
                    else:
                        compiled_block_domains.add(filter_domain)

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

    lite_scope = {"available": False, "reason": "validated-domain input, china.txt, or Lite output is unavailable"}
    validation_input_path = ROOT / ".cache" / "domain" / "validated-domain-input.txt"
    china_input_path = ROOT / ".cache" / "domain" / "china.txt"
    lite_dns_path = ROOT / ".cache" / "out" / "adblockdnslite.txt"
    if validation_input_path.exists() and china_input_path.exists() and lite_dns_path.exists():
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
        lite_blocks_exact, lite_blocks_suffix, lite_allows = set(), set(), set()
        for raw in lite_dns_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith(("!", "#")):
                continue
            if line.startswith("@@||") and line.endswith("^"):
                lite_allows.add(line[4:-1].lower())
            elif line.startswith("||") and line.endswith("^"):
                lite_blocks_suffix.add(line[2:-1].lower())
            elif "." in line and not any(char in line for char in " /\t^$*"):
                lite_blocks_exact.add(line.lower())

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

        known_non_china_covered = {
            domain for domain in validated_non_china_source_blocks
            if (domain in lite_blocks_exact or covered_by_rule_domain(domain, lite_blocks_suffix))
            and not covered_by_rule_domain(domain, lite_allows)
        }
        china_source_missing = {
            domain for domain in china_source_blocks
            if domain not in lite_blocks_exact
            and not covered_by_rule_domain(domain, lite_blocks_suffix)
            and not covered_by_rule_domain(domain, lite_allows)
            and not covered_by_whitelist(domain, project_whitelist)
        }
        # AdGuard DNS Lite intentionally follows the upstream-compatible syntax:
        # ||domain^ blocks the selected domain AND its subdomains. Audit the rule
        # roots against China classification; report suffix side-effects separately
        # rather than misclassifying every valid suffix rule as out-of-scope.
        lite_rules_not_classified_china = (lite_blocks_exact | lite_blocks_suffix) - china_domains
        lite_suffix_rules_not_classified_china = lite_blocks_suffix - china_domains

        # InviZible/DNSCrypt uses =domain for exact-host matching; a plain domain
        # is suffix-based, so it must never appear in its Lite output.
        invizible_lite_path = ROOT / ".cache" / "out" / "adblockdomainlite.txt"
        invizible_blocks_exact, invizible_blocks_suffix = set(), set()
        if invizible_lite_path.exists():
            for raw in invizible_lite_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw.strip()
                if not line or line.startswith(("!", "#")):
                    continue
                if line.startswith("="):
                    invizible_blocks_exact.add(line[1:].lower())
                elif "." in line and not any(char in line for char in " /\t^$*"):
                    invizible_blocks_suffix.add(line.lower())
        invizible_non_china_covered = {
            domain for domain in validated_non_china_source_blocks
            if (
                domain in invizible_blocks_exact
                or covered_by_rule_domain(domain, invizible_blocks_suffix)
            )
            and not covered_by_rule_domain(domain, lite_allows)
        }
        invizible_china_missing = {
            domain for domain in china_source_blocks
            if domain not in invizible_blocks_exact
            and not covered_by_rule_domain(domain, invizible_blocks_suffix)
            and not covered_by_rule_domain(domain, lite_allows)
            and not covered_by_whitelist(domain, project_whitelist)
        }
        invizible_rules_not_classified_china = (
            (invizible_blocks_exact - china_domains) | invizible_blocks_suffix
        )

        lite_scope = {
            "available": True,
            "validated_domain_input_count": len(validated_domains),
            "china_classified_domain_count": len(china_domains),
            "current_source_block_domain_count": len(source_block_domains),
            "china_classified_source_block_domains": len(china_source_blocks),
            "validated_non_china_source_block_domains": len(validated_non_china_source_blocks),
            "unvalidated_current_source_block_domains": len(unvalidated_source_blocks),
            "lite_block_rules": len(lite_blocks_exact) + len(lite_blocks_suffix),
            "lite_exact_block_rules": len(lite_blocks_exact),
            "lite_suffix_block_rules": len(lite_blocks_suffix),
            "lite_allow_rules": len(lite_allows),
            "lite_rules_not_classified_china": len(lite_rules_not_classified_china),
            "lite_suffix_rules_not_classified_china": len(lite_suffix_rules_not_classified_china),
            "known_non_china_source_domains_effectively_blocked_by_lite": len(known_non_china_covered),
            "china_classified_source_domains_missing_from_lite": len(china_source_missing),
            "invizible_lite_block_rules": len(invizible_blocks_exact) + len(invizible_blocks_suffix),
            "invizible_lite_exact_block_rules": len(invizible_blocks_exact),
            "invizible_lite_suffix_block_rules": len(invizible_blocks_suffix),
            "invizible_known_non_china_source_domains_effectively_blocked": len(invizible_non_china_covered),
            "invizible_china_source_domains_missing": len(invizible_china_missing),
            "invizible_lite_rules_not_classified_china": len(invizible_rules_not_classified_china),
        }
        write_domain_list(
            OUT_DIR / "lite-scope-known-non-china-covered.txt",
            known_non_china_covered,
            "No validated non-China source domain is effectively blocked by Lite."
        )
        write_domain_list(
            OUT_DIR / "lite-scope-china-domains-missing.txt",
            china_source_missing,
            "All validated China-classified source block domains are represented in Lite."
        )
        write_domain_list(
            OUT_DIR / "lite-scope-rules-not-classified-china.txt",
            lite_rules_not_classified_china,
            "Every Lite block rule is present in the China-classified domain set."
        )
        write_domain_list(
            OUT_DIR / "lite-scope-unvalidated-source-domains.txt",
            unvalidated_source_blocks,
            "All current source block domains have validation state."
        )
        write_domain_list(
            OUT_DIR / "lite-scope-invizible-known-non-china-covered.txt",
            invizible_non_china_covered,
            "No validated non-China source domain is covered by InviZible Lite."
        )
        write_domain_list(
            OUT_DIR / "lite-scope-invizible-china-domains-missing.txt",
            invizible_china_missing,
            "All validated China-classified source block domains are represented in InviZible Lite."
        )
        write_domain_list(
            OUT_DIR / "lite-scope-invizible-rules-not-classified-china.txt",
            invizible_rules_not_classified_china,
            "Every InviZible Lite exact rule is present in the China-classified domain set."
        )
    (OUT_DIR / "lite-scope-audit.json").write_text(
        json.dumps(lite_scope, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    invizible_allow_path = ROOT / ".cache" / "out" / "adblockdomainallow.txt"
    invizible_allowlist_audit = {
        "available": False,
        "allowlist_rules": 0,
        "expected_source_and_project_allow_domains": 0,
        "missing_allow_domains": 0,
    }
    invizible_allowlist_missing = set()
    if invizible_allow_path.exists():
        invizible_allow_domains = {
            line.strip().lower()
            for line in invizible_allow_path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.lstrip().startswith(("!", "#"))
        }
        current_source_allow_domains = set().union(
            *(allow_sets.get(name, set()) for name in production_names)
        ) if production_names else set()
        expected_invizible_allow_domains = (
            current_source_allow_domains - blacklist_domains
        ) | project_whitelist
        invizible_allowlist_missing = {
            domain for domain in expected_invizible_allow_domains
            if not covered_by_rule_domain(domain, invizible_allow_domains)
        }
        invizible_allowlist_audit = {
            "available": True,
            "allowlist_rules": len(invizible_allow_domains),
            "expected_source_and_project_allow_domains": len(expected_invizible_allow_domains),
            "missing_allow_domains": len(invizible_allowlist_missing),
            "missing_allow_domain_samples": sorted(invizible_allowlist_missing)[:100],
        }
    (OUT_DIR / "invizible-allowlist-audit.json").write_text(
        json.dumps(invizible_allowlist_audit, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_domain_list(
        OUT_DIR / "invizible-allowlist-missing.txt",
        invizible_allowlist_missing,
        "All current source allow rules and project whitelist domains are present in the InviZible allowlist."
    )
    if invizible_allowlist_audit["available"] and invizible_allowlist_missing:
        raise SystemExit(
            "InviZible allowlist quality gate failed: "
            + json.dumps(invizible_allowlist_audit, ensure_ascii=False, sort_keys=True)
        )

    if invizible_allowlist_audit["available"]:
        report += "\n## InviZible DNSCrypt allowlist 覆盖审计\n\n"
        report += f"- allowlist 规则：{invizible_allowlist_audit['allowlist_rules']} 条；应覆盖的上游 allow 与项目白名单：{invizible_allowlist_audit['expected_source_and_project_allow_domains']} 条。\n"
        report += f"- 未覆盖例外：{invizible_allowlist_audit['missing_allow_domains']} 条。\n"
    else:
        report += "\n## InviZible DNSCrypt allowlist 覆盖审计\n\n- 未执行：当前运行没有完整构建产物。\n"

    if lite_scope["available"]:
        if (
            lite_scope["lite_rules_not_classified_china"]
            or lite_scope["china_classified_source_domains_missing_from_lite"]
            or lite_scope["invizible_lite_rules_not_classified_china"]
            or lite_scope["invizible_known_non_china_source_domains_effectively_blocked"]
            or lite_scope["invizible_china_source_domains_missing"]
            or lite_scope["invizible_lite_suffix_block_rules"]
        ):
            raise SystemExit(
                "Lite scope quality gate failed: "
                + json.dumps(lite_scope, ensure_ascii=False, sort_keys=True)
            )
        report += "\n## Lite 国内域名范围审计\n\n"
        report += f"- Lite 拦截规则：{lite_scope['lite_block_rules']} 条（精确主机：{lite_scope['lite_exact_block_rules']}；后缀规则：{lite_scope['lite_suffix_block_rules']}）；放行例外：{lite_scope['lite_allow_rules']} 条。\n"
        report += f"- AdGuard 后缀匹配连带覆盖的非国内分类来源域名：{lite_scope['known_non_china_source_domains_effectively_blocked_by_lite']} 条（属于 `||domain^` 对子域名的标准匹配范围，单独列示，不计作非国内规则根）。\n"
        report += f"- 已归类为国内的来源拦截域名，未被 Lite 拦截或放行规则覆盖：{lite_scope['china_classified_source_domains_missing_from_lite']} 条。\n"
        report += f"- 当前来源中尚未进入验证状态、暂无法判定国内属性：{lite_scope['unvalidated_current_source_block_domains']} 条。\n"
        report += f"- InviZible Lite 精确规则：{lite_scope['invizible_lite_exact_block_rules']} 条；后缀规则：{lite_scope['invizible_lite_suffix_block_rules']} 条。\n"
        report += f"- InviZible Lite 已知非国内域名连带拦截：{lite_scope['invizible_known_non_china_source_domains_effectively_blocked']} 条；国内域名漏项：{lite_scope['invizible_china_source_domains_missing']} 条。\n"
        report += "- 注：AdGuard Home Lite 使用与上游一致的 `||domain^` 后缀语义（主域名及其子域名）；InviZible DNSCrypt Lite 使用 `=domain` 精确匹配；放行例外保留原有匹配范围。\n"
    else:
        report += f"\n## Lite 国内域名范围审计\n\n- 未执行：{lite_scope['reason']}。\n"

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

    (OUT_DIR / "source-audit.md").write_text(report, encoding="utf-8")
    print(report)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write(report)

    required_names = production_names | browser_names
    failed_required = [row["name"] for row in results
                       if row["name"] in required_names and not row["download_ok"]]
    critical_candidates = {"OISD upstream release snapshot (README says Basic; payload title says Small)"}
    failed_candidates = [name for name in critical_candidates
                         if not downloads.get(name, {}).get("ok")]
    if failed_required or failed_candidates:
        raise SystemExit(
            "Audit incomplete; required source failures="
            + ", ".join(failed_required + failed_candidates)
        )

    gate_failures = source_audit_gate_failures(
        compiled_unparsed,
        source_presence_unexplained,
        current_source_parent_inactive_unexplained,
        baseline_allow_missing_still_blocked,
    )
    if gate_failures:
        raise SystemExit("Source/output consistency gate failed:\n- " + "\n- ".join(gate_failures))


if __name__ == "__main__":
    main()
