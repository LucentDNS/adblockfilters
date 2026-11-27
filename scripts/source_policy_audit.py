#!/usr/bin/env python3
"""Policy-aware audit of strict-source domains; never changes production rules."""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from readme import ReadMe, Rule  # noqa: E402
from resolver import Resolver, configure_logging  # noqa: E402
from scripts.audit_sources import audit_one, covered_by_whitelist, load_project_whitelist, write_domain_list  # noqa: E402

POLICY_PATH = ROOT / "source-policy.json"
SOURCE_DIR = ROOT / ".cache" / "source"
CANDIDATE_DIR = ROOT / ".cache" / "audit" / "candidate-source"
OUT_DIR = ROOT / ".cache" / "audit" / "source-policy"


def covered_by(domain, roots):
    """Return matching exact/parent roots; child-only matches do not cover a parent."""
    labels = domain.lower().split(".")
    return sorted(".".join(labels[index:]) for index in range(len(labels)) if ".".join(labels[index:]) in roots)


def classify_strict_domains(strict_domains, stability_blocks, stability_allows, targeted_blocks, whitelist):
    """Classify strict hits without treating source absence as an allow or source count as votes."""
    strict_only = set()
    stability_supported = set()
    explicit_allow_conflicts = set()
    targeted_supported = set()
    whitelist_excluded = set()
    details = {}
    for domain in sorted(strict_domains):
        stable_block_roots = covered_by(domain, stability_blocks)
        stable_allow_roots = covered_by(domain, stability_allows)
        targeted_block_roots = covered_by(domain, targeted_blocks)
        white = covered_by_whitelist(domain, whitelist)
        if white:
            whitelist_excluded.add(domain)
        if stable_block_roots:
            stability_supported.add(domain)
        if stable_allow_roots:
            explicit_allow_conflicts.add(domain)
        if targeted_block_roots:
            targeted_supported.add(domain)
        if not stable_block_roots and not stable_allow_roots and not white:
            strict_only.add(domain)
        details[domain] = {
            "stability_block_parent_or_exact": stable_block_roots,
            "stability_explicit_allow_parent_or_exact": stable_allow_roots,
            "targeted_block_parent_or_exact": targeted_block_roots,
            "project_whitelist_parent_or_exact": bool(white),
            "classification": (
                "project_whitelist_excluded" if white else
                "explicit_stability_allow_conflict" if stable_allow_roots else
                "stability_source_block_covered" if stable_block_roots else
                "strict_only_review" 
            )
        }
    return {
        "strict_only_review": strict_only,
        "stability_supported": stability_supported,
        "explicit_allow_conflicts": explicit_allow_conflicts,
        "targeted_supported": targeted_supported,
        "whitelist_excluded": whitelist_excluded,
        "details": details,
    }


def main():
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    if policy.get("version") != 1:
        raise SystemExit("Unsupported source-policy.json version")
    source_policy = {item["name"]: item for item in policy["sources"]}
    all_rules = ReadMe(str(ROOT / "README.md")).getRules()
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
             "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt", "live upstream"),
    ]
    rules = [rule for rule in all_rules if rule.type in {"host", "dns", "dnsfilter"}] + candidate_rules
    domain_sets, allow_sets, unavailable = {}, {}, []
    for rule in rules:
        policy_item = source_policy.get(rule.name)
        if not policy_item:
            continue
        base = CANDIDATE_DIR if policy_item["role"] == "candidate" else SOURCE_DIR
        path = base / rule.filename
        if not path.is_file() or not path.stat().st_size:
            unavailable.append(rule.name)
            continue
        resolver = Resolver(str(base))
        _row, blocks, allows = audit_one(rule, resolver, {"ok": True, "path": str(path)})
        domain_sets[rule.name] = blocks
        allow_sets[rule.name] = allows

    required = {name for name, item in source_policy.items() if item["role"] == "production"}
    missing = sorted(required - set(domain_sets))
    if missing:
        raise SystemExit("Required policy sources are unavailable: " + ", ".join(missing))

    def union_for(style, action):
        names = [name for name, item in source_policy.items() if item["style"] == style]
        mapping = domain_sets if action == "block" else allow_sets
        return set().union(*(mapping.get(name, set()) for name in names)) if names else set()

    strict_blocks = union_for("strict", "block")
    stability_blocks = union_for("stability_reference", "block")
    stability_allows = union_for("stability_reference", "allow")
    targeted_blocks = union_for("targeted", "block")
    whitelist = load_project_whitelist()
    result = classify_strict_domains(
        strict_blocks, stability_blocks, stability_allows, targeted_blocks, whitelist
    )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_domain_list(OUT_DIR / "strict-only-review.txt", result["strict_only_review"],
                      "No strict-only domains require review.")
    write_domain_list(OUT_DIR / "strict-stability-supported.txt", result["stability_supported"],
                      "No strict domains are covered by stability-reference blocks.")
    write_domain_list(OUT_DIR / "strict-explicit-allow-conflicts.txt", result["explicit_allow_conflicts"],
                      "No strict domains conflict with explicit stability-reference allow rules.")
    write_domain_list(OUT_DIR / "strict-targeted-source-supported.txt", result["targeted_supported"],
                      "No strict domains are covered by targeted production sources.")
    write_domain_list(OUT_DIR / "strict-project-whitelist-excluded.txt", result["whitelist_excluded"],
                      "No strict domains are excluded by the project whitelist.")

    families = defaultdict(list)
    for name, item in source_policy.items():
        families[item["family"]].append(name)
    report = {
        "version": 1,
        "policy_principles": policy["principles"],
        "source_families": {key: sorted(value) for key, value in sorted(families.items())},
        "source_status": {
            name: {
                "style": item["style"], "family": item["family"], "role": item["role"],
                "available": name in domain_sets,
                "unique_block_domains": len(domain_sets.get(name, set())),
                "unique_allow_domains": len(allow_sets.get(name, set())),
            } for name, item in sorted(source_policy.items())
        },
        "counts": {
            "strict_block_domains": len(strict_blocks),
            "strict_only_review": len(result["strict_only_review"]),
            "stability_block_supported": len(result["stability_supported"]),
            "explicit_stability_allow_conflicts": len(result["explicit_allow_conflicts"]),
            "targeted_source_supported": len(result["targeted_supported"]),
            "project_whitelist_excluded": len(result["whitelist_excluded"]),
        },
        "unavailable_sources": sorted(set(unavailable)),
        "domain_decisions": result["details"],
        "decision_policy": (
            "This is an evidence-separation report, not a voting system. Same-family lists are "
            "not independent corroboration. A missing domain in a stability list is not an allow. "
            "Strict-only domains remain review candidates and are never auto-added to production. "
            "Explicit allow rules and project whitelist coverage are reported as conflicts/exclusions."
        ),
    }
    (OUT_DIR / "source-policy-audit.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "# 来源理念冲突审计", "",
        "- 本报告只分离来源证据，不按来源数量投票，也不自动改变正式规则。",
        "- 同一作者/规则家族的多个列表不视为独立证据。",
        "- 稳定型来源没有收录某域名，不等于它明确放行该域名。",
        "- 严格型来源独有域名进入人工复核集合，不自动加入 Full/Lite。",
        "- 稳定型来源明确 allow 与严格型来源 block 冲突时，单独列出，不静默覆盖。",
        "",
        "| 指标 | 数量 |", "|---|---:|",
    ]
    labels = [
        ("strict_block_domains", "严格型来源拦截域名"),
        ("strict_only_review", "严格来源独有待复核"),
        ("stability_block_supported", "稳定型来源拦截覆盖"),
        ("explicit_stability_allow_conflicts", "稳定型明确放行冲突"),
        ("targeted_source_supported", "广告专项来源交叉覆盖"),
        ("project_whitelist_excluded", "项目白名单排除"),
    ]
    for key, label in labels:
        lines.append(f"| {label} | {report['counts'][key]} |")
    lines.extend(["", "## 判定口径", "", report["decision_policy"], "",
                  "## 来源不可用", ""])
    lines.extend(f"- {name}" for name in sorted(set(unavailable)) if name)
    if not unavailable:
        lines.append("- 无")
    (OUT_DIR / "source-policy-audit.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    configure_logging()
    main()
