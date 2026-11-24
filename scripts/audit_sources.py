#!/usr/bin/env python3
"""Audit upstream filter sources using the repository's current Resolver parser."""
import asyncio
import hashlib
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
from tld.utils import update_tld_names

from readme import ReadMe, Rule
from resolver import Resolver
SOURCE_DIR = ROOT / ".cache" / "source"
OUT_DIR = ROOT / ".cache" / "audit"
TIMEOUT = httpx.Timeout(90.0, connect=30.0)


def full_domain(value):
    if not value:
        return None
    if isinstance(value, tuple) and len(value) == 2:
        fld, subdomain = value
        return (f"{subdomain}.{fld}" if subdomain else fld).lower()
    return str(value).lower()


def ignored_line(line, source_type):
    s = line.strip()
    if not s or s.startswith("!") or (s.startswith("[") and s.endswith("]")):
        return True
    if source_type == "host":
        return s.startswith("#")
    return s.startswith("#") and not s.startswith(("##", "#%#"))


async def download_all(rules):
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    sem = asyncio.Semaphore(5)
    results = {}
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True,
                                 headers={"User-Agent": "LucentDNS-Source-Audit/1.0"}) as client:
        async def one(rule):
            async with sem:
                try:
                    path = SOURCE_DIR / rule.filename
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
        "block_entries": 0, "allow_entries": 0, "filter_entries": 0,
        "filter_domain_extracted": 0, "filter_domain_unresolved": 0,
        "unique_block_domains": 0, "unique_allow_domains": 0,
        "unique_filter_rules": 0, "unique_extracted_domains": 0,
        "duplicate_raw_lines": 0, "download_error": download.get("error", ""),
        "samples_unparsed": [], "samples_filter_domain_unresolved": []
    }
    if not download.get("ok"):
        return result, set()

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
                blocks.add(full_domain(block))
                result["block_entries"] += 1
                parsed = True
            if unblock:
                allows.add(full_domain(unblock))
                result["allow_entries"] += 1
                parsed = True
            if filt:
                filters.add(filt[0])
                result["filter_entries"] += 1
                parsed = True
                if filt[1]:
                    extracted.add(filt[1].lower())
                    result["filter_domain_extracted"] += 1
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
    result["unique_filter_rules"] = len(filters)
    result["unique_extracted_domains"] = len(extracted)
    return result, blocks


def render_report(results, production_names, candidate_names, overlap, unique_total, pairwise, candidate_overlaps):
    cols = [
        ("name", "来源"), ("role", "身份"), ("type", "类型"), ("total_lines", "总行数"),
        ("candidate_lines", "候选行"), ("parsed_lines", "解析接受"),
        ("unparsed_candidate_lines", "未识别候选"),
        ("unique_block_domains", "唯一拦截域名"),
        ("unique_only_domains", "精确独有域名"),
        ("shared_domains", "精确重复域名"),
        ("effective_unique_domains", "最终父级压缩后独有域名"),
        ("external_parent_covered_domains", "被其他来源父域名覆盖"),
        ("internal_parent_covered_domains", "被本来源父域名压缩"),
        ("unique_allow_domains", "唯一放行域名"),
        ("unique_filter_rules", "过滤规则"),
        ("filter_domain_unresolved", "过滤规则未提取域名")
    ]
    out = [
        "# 上游规则源基线审计", "",
        f"- 正式集成来源数：{len(production_names)}",
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
        "- 跨来源重复拦截域名：仅统计正式集成来源中解析为 block 的域名；不把候选来源或浏览器过滤规则提取的域名混入。",
        "- 最终父级压缩后独有域名：先排除其他正式来源的相同域名/父域名覆盖，再排除本来源内被父域名覆盖的子域名；仍未扣除项目黑名单、白名单和上游 allow 例外，因此是来源贡献上限估计，不代表这些域名都应拦截。",
        "- 候选来源的独有贡献：仅与正式来源比较，不能反向减少正式来源的独有贡献。",
        "- 过滤规则的域名提取统计单独保留，不计入 AdGuard Home DNS 拦截域名交集。"
    ])
    return "\n".join(out) + "\n"


def main():
    try:
        update_tld_names()
    except Exception as exc:
        print(f"Warning: public suffix list update failed: {exc}")

    # 本审计只回答 DNS 上游是否值得进入 DNS 规则：仅审计 host/dns/dnsfilter。
    # 浏览器 filter 来源不应被解析成 DNS 域名，也不应让大量路径型规则污染 DNS 来源报告。
    all_rules = ReadMe(str(ROOT / "README.md")).getRules()
    production_rules = [rule for rule in all_rules if rule.type in ("host", "dns", "dnsfilter")]
    candidate_rules = [
        Rule("Pollock hosts (candidate only)", "host",
             "https://someonewhocares.org/hosts/hosts", "2026/11/22")
    ]
    rules = production_rules + candidate_rules
    production_names = {rule.name for rule in production_rules}
    candidate_names = {rule.name for rule in candidate_rules}
    downloads = asyncio.run(download_all(rules))
    resolver = Resolver(str(SOURCE_DIR))
    results, domain_sets = [], {}

    for rule in rules:
        row, domains = audit_one(rule, resolver, downloads.get(rule.name, {}))
        row["role"] = "正式来源" if rule.name in production_names else "候选源（不集成）"
        results.append(row)
        domain_sets[rule.name] = domains

    production_sets = {name: domain_sets.get(name, set()) for name in production_names}
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
        row["effective_unique_domains"] = len(effective_unique)
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

    (OUT_DIR / "source-audit.json").write_text(
        json.dumps({
            "audit_generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "production_sources": len(production_names),
            "candidate_sources": len(candidate_names),
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
        results, production_names, candidate_names, overlap, unique_total, pairwise, candidate_overlaps
    )
    (OUT_DIR / "source-audit.md").write_text(report, encoding="utf-8")
    print(report)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write(report)

    if not any(row["download_ok"] for row in results):
        raise SystemExit("All upstream source downloads failed; audit cannot proceed.")


if __name__ == "__main__":
    main()
