#!/usr/bin/env python3
"""Audit upstream filter sources using the repository's current Resolver parser."""
import asyncio
import json
import os
import re
import sys
from collections import defaultdict
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import httpx
from tld.utils import update_tld_names

from readme import ReadMe
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


def render_report(results, overlap, total_rules, unique_total, pairwise):
    cols = [
        ("name", "来源"), ("type", "类型"), ("total_lines", "总行数"),
        ("candidate_lines", "候选行"), ("parsed_lines", "解析接受"),
        ("unparsed_candidate_lines", "未识别候选"),
        ("unique_block_domains", "唯一拦截域名"),
        ("unique_only_domains", "精确独有域名"),
        ("shared_domains", "精确重复域名"),
        ("effective_unique_domains", "父级去重后独有候选"),
        ("parent_covered_domains", "被其他来源父域名覆盖"),
        ("unique_allow_domains", "唯一放行域名"),
        ("unique_filter_rules", "过滤规则"),
        ("filter_domain_unresolved", "过滤规则未提取域名")
    ]
    out = [
        "# 上游规则源基线审计", "",
        f"- 来源总数：{total_rules}",
        f"- 下载成功：{sum(1 for r in results if r['download_ok'])}",
        f"- 下载失败：{sum(1 for r in results if not r['download_ok'])}",
        f"- 跨来源重复拦截域名：{overlap}",
        f"- 所有来源合并后的唯一域名：{unique_total}",
        "- 解析口径：调用仓库当前 Resolver 的原始解析方法；未识别候选不等同于规则无效，需结合规则语法复核。",
        "",
        "| " + " | ".join(label for _, label in cols) + " |",
        "|" + "|".join("---:" if key not in ("name", "type") else "---" for key, _ in cols) + "|"
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
    out.extend(["", "## 来源两两重复（前 20 组）",
                "| 来源 A | 来源 B | 重复域名数 |", "|---|---|---:|"])
    for left, right, count in pairwise[:20]:
        out.append(f"| {left} | {right} | {count} |")
    out.extend([
        "", "## 指标说明",
        "- 候选行：排除空行、注释和列表头后的行。",
        "- 解析接受：当前解析器识别为拦截、放行或过滤规则的行。",
        "- 唯一拦截域名：当前解析器可归一化的拦截域名去重数。",
        "- 过滤规则未提取域名：规则本身被保留，但当前解析器未能关联出域名；不能简单视为规则丢失。",
        "- 跨来源重复拦截域名：仅统计解析为 block 的域名，和 AdGuard Home DNS 输出口径一致；不把浏览器过滤规则中提取出的域名混入。",
        "- 父级去重后独有候选：仅排除其他来源中相同域名或父域名已覆盖的条目；当前为来源贡献初筛，尚未扣除全局 allow/白名单例外，也不代表这些域名都应拦截。",
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
    rules = [rule for rule in all_rules if rule.type in ("host", "dns", "dnsfilter")]
    downloads = asyncio.run(download_all(rules))
    resolver = Resolver(str(SOURCE_DIR))
    results, memberships, domain_sets = [], defaultdict(set), {}

    for rule in rules:
        row, domains = audit_one(rule, resolver, downloads.get(rule.name, {}))
        results.append(row)
        domain_sets[rule.name] = domains
        for domain in domains:
            if domain:
                memberships[domain].add(rule.name)

    overlap = sum(1 for names in memberships.values() if len(names) > 1)
    for row in results:
        own = domain_sets.get(row["name"], set())
        row["unique_only_domains"] = sum(1 for domain in own if memberships[domain] == {row["name"]})
        row["shared_domains"] = len(own) - row["unique_only_domains"]
        other_domains = set().union(*(domains for name, domains in domain_sets.items() if name != row["name"]))
        def covered_by_other_parent(domain):
            labels = domain.split(".")
            return any(".".join(labels[index:]) in other_domains for index in range(len(labels)))
        effective_unique = {domain for domain in own if not covered_by_other_parent(domain)}
        row["effective_unique_domains"] = len(effective_unique)
        row["parent_covered_domains"] = len(own) - len(effective_unique)
        row["effective_unique_samples"] = sorted(effective_unique)[:100]
    pairwise = []
    for left, right in combinations([rule.name for rule in rules], 2):
        count = len(domain_sets.get(left, set()) & domain_sets.get(right, set()))
        if count:
            pairwise.append((left, right, count))
    pairwise.sort(key=lambda item: item[2], reverse=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    unique_dir = OUT_DIR / "effective-unique"
    unique_dir.mkdir(parents=True, exist_ok=True)
    for row in results:
        name = row["name"]
        own = domain_sets.get(name, set())
        other_domains = set().union(*(domains for other, domains in domain_sets.items() if other != name))
        unique_domains = []
        for domain in own:
            labels = domain.split(".")
            if not any(".".join(labels[index:]) in other_domains for index in range(len(labels))):
                unique_domains.append(domain)
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_.")
        (unique_dir / f"{safe_name}.txt").write_text("\\n".join(sorted(unique_domains)) + ("\\n" if unique_domains else ""), encoding="utf-8")
    (OUT_DIR / "source-audit.json").write_text(
        json.dumps({"sources": results, "cross_source_duplicate_domains": overlap,
                    "unique_domains_all_sources": len(memberships),
                    "top_pairwise_overlaps": [{"source_a": a, "source_b": b, "shared_domains": n}
                                              for a, b, n in pairwise[:20]]},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    report = render_report(results, overlap, len(rules), len(memberships), pairwise)
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
