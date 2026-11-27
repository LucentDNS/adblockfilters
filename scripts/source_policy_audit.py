#!/usr/bin/env python3
"""Policy-aware audit of strict-source domains; never changes production rules."""
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from readme import ReadMe, Rule  # noqa: E402
from resolver import Resolver, configure_logging  # noqa: E402
from scripts.audit_sources import (  # noqa: E402
    audit_one,
    covered_by_whitelist,
    load_project_whitelist,
    write_domain_list,
)

POLICY_PATH = ROOT / "source-policy.json"
SOURCE_DIR = ROOT / ".cache" / "source"
CANDIDATE_DIR = ROOT / ".cache" / "audit" / "candidate-source"
OUT_DIR = ROOT / ".cache" / "audit" / "source-policy"


def covered_by(domain, roots):
    """Return exact/parent matches; a child rule does not cover its parent."""
    labels = domain.lower().split(".")
    return [
        ".".join(labels[index:])
        for index in range(len(labels))
        if ".".join(labels[index:]) in roots
    ]


def classify_strict_domains(
    strict_domains,
    stability_blocks,
    stability_allows,
    targeted_blocks,
    whitelist,
    other_reference_blocks=None,
):
    """Separate evidence without treating source absence as an allow or counts as votes."""
    other_reference_blocks = other_reference_blocks or set()
    strict_only = set()
    stability_supported = set()
    explicit_allow_conflicts = set()
    targeted_supported = set()
    other_reference_supported = set()
    whitelist_excluded = set()
    details = {}

    for domain in sorted(strict_domains):
        stable_block_roots = covered_by(domain, stability_blocks)
        stable_allow_roots = covered_by(domain, stability_allows)
        targeted_roots = covered_by(domain, targeted_blocks)
        other_reference_roots = covered_by(domain, other_reference_blocks)
        white = covered_by_whitelist(domain, whitelist)

        if white:
            whitelist_excluded.add(domain)
        if stable_block_roots:
            stability_supported.add(domain)
        if stable_allow_roots:
            explicit_allow_conflicts.add(domain)
        if targeted_roots:
            targeted_supported.add(domain)
        if other_reference_roots:
            other_reference_supported.add(domain)
        if not (
            stable_block_roots
            or stable_allow_roots
            or targeted_roots
            or other_reference_roots
            or white
        ):
            strict_only.add(domain)

        if white:
            classification = "project_whitelist_excluded"
        elif stable_allow_roots:
            classification = "explicit_stability_allow_conflict"
        elif stable_block_roots:
            classification = "stability_source_block_covered"
        elif targeted_roots:
            classification = "targeted_source_supported"
        elif other_reference_roots:
            classification = "other_reference_supported"
        else:
            classification = "strict_only_review"

        details[domain] = {
            "stability_block_parent_or_exact": stable_block_roots,
            "stability_explicit_allow_parent_or_exact": stable_allow_roots,
            "targeted_block_parent_or_exact": targeted_roots,
            "other_reference_block_parent_or_exact": other_reference_roots,
            "project_whitelist_parent_or_exact": bool(white),
            "classification": classification,
        }

    return {
        "strict_only_review": strict_only,
        "stability_supported": stability_supported,
        "explicit_allow_conflicts": explicit_allow_conflicts,
        "targeted_supported": targeted_supported,
        "other_reference_supported": other_reference_supported,
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
        Rule(
            "CHN: AdRules DNS List (AdGuard Registry candidate only)",
            "dns",
            "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
            "live upstream",
        ),
        Rule(
            "OISD Blocklist Small (AdGuard Registry candidate only)",
            "dns",
            "https://small.oisd.nl/",
            "live upstream",
        ),
        Rule(
            "OISD Blocklist Big (AdGuard Registry benchmark only; higher FP risk)",
            "dns",
            "https://big.oisd.nl/",
            "live upstream",
        ),
        Rule(
            "HaGeZi Pro (AdGuard Registry benchmark against Pro Mini)",
            "dns",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
            "live upstream",
        ),
        Rule(
            "HaGeZi Normal (AdGuard Registry benchmark against Pro Mini)",
            "dns",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt",
            "live upstream",
        ),
    ]
    rules = [
        rule for rule in all_rules if rule.type in {"host", "dns", "dnsfilter"}
    ] + candidate_rules

    domain_sets = {}
    allow_sets = {}
    unavailable = []
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
        _row, blocks, allows = audit_one(
            rule, resolver, {"ok": True, "path": str(path)}
        )
        domain_sets[rule.name] = blocks
        allow_sets[rule.name] = allows

    required = {
        name for name, item in source_policy.items()
        if item["role"] == "production"
    }
    missing = sorted(required - set(domain_sets))
    if missing:
        raise SystemExit(
            "Required policy sources are unavailable: " + ", ".join(missing)
        )

    def union_for(style, action):
        names = [
            name for name, item in source_policy.items()
            if item["style"] == style
        ]
        mapping = domain_sets if action == "block" else allow_sets
        return (
            set().union(*(mapping.get(name, set()) for name in names))
            if names else set()
        )

    strict_blocks = union_for("strict", "block")
    stability_blocks = union_for("stability_reference", "block")
    stability_allows = union_for("stability_reference", "allow")
    targeted_blocks = union_for("targeted", "block")
    other_reference_blocks = union_for("other_reference", "block")
    whitelist = load_project_whitelist()

    result = classify_strict_domains(
        strict_blocks,
        stability_blocks,
        stability_allows,
        targeted_blocks,
        whitelist,
        other_reference_blocks,
    )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    reports = [
        ("strict-only-review.txt", "strict_only_review", "No strict-only domains require review."),
        ("strict-stability-supported.txt", "stability_supported", "No strict domains are covered by stability-reference blocks."),
        ("strict-explicit-allow-conflicts.txt", "explicit_allow_conflicts", "No strict domains conflict with explicit stability-reference allow rules."),
        ("strict-targeted-source-supported.txt", "targeted_supported", "No strict domains are covered by targeted production sources."),
        ("strict-other-reference-supported.txt", "other_reference_supported", "No strict domains are covered by other reference sources."),
        ("strict-project-whitelist-excluded.txt", "whitelist_excluded", "No strict domains are excluded by the project whitelist."),
    ]
    for filename, key, note in reports:
        write_domain_list(OUT_DIR / filename, result[key], note)

    families = defaultdict(list)
    for name, item in source_policy.items():
        families[item["family"]].append(name)

    report = {
        "version": 1,
        "policy_principles": policy["principles"],
        "source_families": {
            key: sorted(value) for key, value in sorted(families.items())
        },
        "source_status": {
            name: {
                "style": item["style"],
                "family": item["family"],
                "role": item["role"],
                "available": name in domain_sets,
                "unique_block_domains": len(domain_sets.get(name, set())),
                "unique_allow_domains": len(allow_sets.get(name, set())),
            }
            for name, item in sorted(source_policy.items())
        },
        "counts": {
            "strict_block_domains": len(strict_blocks),
            "strict_only_review": len(result["strict_only_review"]),
            "stability_block_supported": len(result["stability_supported"]),
            "explicit_stability_allow_conflicts": len(result["explicit_allow_conflicts"]),
            "targeted_source_supported": len(result["targeted_supported"]),
            "other_reference_supported": len(result["other_reference_supported"]),
            "project_whitelist_excluded": len(result["whitelist_excluded"]),
        },
        "unavailable_sources": sorted(set(unavailable)),
        "domain_decisions": result["details"],
        "decision_policy": (
            "This is an evidence-separation report, not a voting system. Same-family lists "
            "are not independent corroboration. A missing domain in a stability list is "
            "not an allow. Strict-only domains remain review candidates and are never "
            "auto-added to production. Explicit allow rules and project whitelist coverage "
            "are reported separately."
        ),
    }
    (OUT_DIR / "source-policy-audit.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    labels = [
        ("strict_block_domains", "严格型来源拦截域名"),
        ("strict_only_review", "严格来源独有待复核"),
        ("stability_block_supported", "稳定型来源拦截覆盖"),
        ("explicit_stability_allow_conflicts", "稳定型明确放行冲突"),
        ("targeted_source_supported", "广告专项来源交叉覆盖"),
        ("other_reference_supported", "其他候选来源交叉覆盖"),
        ("project_whitelist_excluded", "项目白名单排除"),
    ]
    lines = [
        "# 来源理念冲突审计",
        "",
        "- 本报告只分离来源证据，不按来源数量投票，也不自动改变正式规则。",
        "- 同一作者/规则家族的多个列表不视为独立证据。",
        "- 稳定型来源没有收录某域名，不等于它明确放行该域名。",
        "- 严格型来源独有域名进入人工复核集合，不自动加入 Full/Lite。",
        "- 稳定型来源明确 allow 与严格型来源 block 冲突时，单独列出。",
        "",
        "| 指标 | 数量 |",
        "|---|---:|",
    ]
    for key, label in labels:
        lines.append(f"| {label} | {report['counts'][key]} |")
    lines.extend(["", "## 判定口径", "", report["decision_policy"], "", "## 来源不可用", ""])
    lines.extend(f"- {name}" for name in sorted(set(unavailable)))
    if not unavailable:
        lines.append("- 无")

    markdown = "\n".join(lines) + "\n"
    (OUT_DIR / "source-policy-audit.md").write_text(markdown, encoding="utf-8")
    print(markdown)


if __name__ == "__main__":
    configure_logging()
    main()
