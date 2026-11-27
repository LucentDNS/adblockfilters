#!/usr/bin/env python3
"""Validate and compare both Full and Lite outputs with the upstream release baseline."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from resolver import Resolver  # noqa: E402 - project-root bootstrap above

BASELINE_DIR = Path(".cache/baseline")
CURRENT_DIR = Path(".cache/out")
REPORT_DIR = Path(".cache/report")
BASELINE_SOURCE = "217heidai/adblockfilters release rule"
MINIMUM_RULES = {"full": 100_000, "lite": 1_000}
EXPECTED_TITLES = {
    "full": "! Title: AdBlock DNS",
    "lite": "! Title: AdBlock DNS Lite",
}
DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
LEGACY_BASELINE_LABEL = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
DNS_PATTERN_RESOLVER = Resolver(".")


def _is_domain_rule(rule: str, allow_legacy_service_labels: bool = False) -> bool:
    if rule.startswith("@@||"):
        domain = rule[4:]
    elif rule.startswith("||"):
        domain = rule[2:]
    else:
        return False
    # Use the production parser for supported wildcard and dnstype patterns.
    if "*" in domain or "$" in domain:
        return DNS_PATTERN_RESOLVER.resolveDNSPattern(rule) is not None
    if not domain.endswith("^"):
        return False
    domain = domain[:-1]
    if not domain or len(domain) > 253:
        return False
    labels = domain.split(".")
    label_pattern = LEGACY_BASELINE_LABEL if allow_legacy_service_labels else DOMAIN_LABEL
    return all(
        label and len(label) <= 63 and label_pattern.fullmatch(label)
        for label in labels
    )


def parse_filter(
    path: Path,
    expected_title: str,
    minimum_rules: int,
    allow_legacy_service_labels: bool = False,
) -> dict:
    if not path.is_file() or path.stat().st_size == 0:
        raise SystemExit(f"DNS filter file is missing or empty: {path}")
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    title = next((line for line in lines if line.startswith("! Title:")), None)
    version = next(
        (line.partition(": ")[2].strip() for line in lines if line.startswith("! Version:")),
        "",
    )
    rules = [
        line.strip()
        for line in lines
        if line.strip() and not line.lstrip().startswith(("!", "#"))
    ]
    if title != expected_title:
        raise SystemExit(f"Unexpected title in {path}: {title!r}")
    if not version:
        raise SystemExit(f"DNS filter is missing a version marker: {path}")
    if len(rules) < minimum_rules:
        raise SystemExit(
            f"DNS filter is unexpectedly small: {path} contains {len(rules)} rules"
        )
    invalid = [
        rule for rule in rules
        if not _is_domain_rule(rule, allow_legacy_service_labels)
    ]
    if invalid:
        raise SystemExit(
            f"DNS filter contains non-domain rules in {path}: {invalid[:10]}"
        )
    duplicates = len(rules) - len(set(rules))
    if duplicates:
        raise SystemExit(f"DNS filter contains {duplicates} duplicate rules: {path}")
    return {"title": title, "version": version, "rules": set(rules)}


def compare_variant(
    name: str, baseline_path: Path, current_path: Path, minimum_rules: int | None = None
) -> dict:
    title = EXPECTED_TITLES[name]
    minimum = MINIMUM_RULES[name] if minimum_rules is None else minimum_rules
    baseline = parse_filter(
        baseline_path, title, minimum, allow_legacy_service_labels=True
    )
    current = parse_filter(current_path, title, minimum)
    baseline_rules = baseline["rules"]
    current_rules = current["rules"]
    optimized_only = sorted(current_rules - baseline_rules)
    baseline_only = sorted(baseline_rules - current_rules)
    metrics = {
        "baseline_title": baseline["title"],
        "baseline_version": baseline["version"],
        "current_title": current["title"],
        "current_version": current["version"],
        "baseline_rules": len(baseline_rules),
        "optimized_rules": len(current_rules),
        "shared_rules": len(current_rules & baseline_rules),
        "optimized_only": len(optimized_only),
        "baseline_only": len(baseline_only),
        "baseline_block_rules": sum(rule.startswith("||") for rule in baseline_rules),
        "baseline_allow_rules": sum(rule.startswith("@@||") for rule in baseline_rules),
        "optimized_block_rules": sum(rule.startswith("||") for rule in current_rules),
        "optimized_allow_rules": sum(rule.startswith("@@||") for rule in current_rules),
        "optimized_only_sample": optimized_only[:100],
        "baseline_only_sample": baseline_only[:100],
    }
    return {
        "metrics": metrics,
        "optimized_only_rules": optimized_only,
        "baseline_only_rules": baseline_only,
    }


def _write_list(path: Path, rules: list[str], empty_message: str) -> None:
    content = "\n".join(rules)
    if content:
        content += "\n"
    else:
        content = f"! {empty_message}\n"
    path.write_text(content, encoding="utf-8")


def write_reports(full: dict, lite: dict) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    _write_list(
        REPORT_DIR / "optimized-only.txt",
        full["optimized_only_rules"],
        "No project-only Full rules in this comparison.",
    )
    _write_list(
        REPORT_DIR / "baseline-only.txt",
        full["baseline_only_rules"],
        "No upstream-only Full rules in this comparison.",
    )
    _write_list(
        REPORT_DIR / "lite-optimized-only.txt",
        lite["optimized_only_rules"],
        "No project-only Lite rules in this comparison.",
    )
    _write_list(
        REPORT_DIR / "lite-baseline-only.txt",
        lite["baseline_only_rules"],
        "No upstream-only Lite rules in this comparison.",
    )
    lite_missing_block_domains = sorted(
        rule[2:-1]
        for rule in lite["baseline_only_rules"]
        if rule.startswith("||") and rule.endswith("^")
    )
    _write_list(
        REPORT_DIR / "lite-baseline-only-domains.txt",
        lite_missing_block_domains,
        "No upstream-only Lite block domains in this comparison.",
    )

    full_metrics = full["metrics"]
    lite_metrics = lite["metrics"]
    report = {
        "baseline_source": BASELINE_SOURCE,
        "baseline_version": full_metrics["baseline_version"],
        "current_version": full_metrics["current_version"],
        **full_metrics,
        "full": full_metrics,
        "lite": lite_metrics,
    }
    (REPORT_DIR / "comparison.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# DNS output comparison",
        "",
        f"- Baseline source: {BASELINE_SOURCE}",
        f"- Current build version: {full_metrics['current_version']}",
        "",
    ]
    for label, metrics in (("Full", full_metrics), ("Lite", lite_metrics)):
        lines.extend(
            [
                f"## {label}",
                "",
                f"- Upstream version: {metrics['baseline_version']}",
                f"- Upstream rules: {metrics['baseline_rules']}",
                f"- Current rules: {metrics['optimized_rules']}",
                f"- Shared rules: {metrics['shared_rules']}",
                f"- Project-only rules: {metrics['optimized_only']}",
                f"- Upstream-only rules: {metrics['baseline_only']}",
                f"- Upstream block/allow: {metrics['baseline_block_rules']}/{metrics['baseline_allow_rules']}",
                f"- Current block/allow: {metrics['optimized_block_rules']}/{metrics['optimized_allow_rules']}",
                "",
            ]
        )
    (REPORT_DIR / "comparison.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


def main() -> None:
    full = compare_variant(
        "full",
        BASELINE_DIR / "upstream-adblockdns.txt",
        CURRENT_DIR / "adblockdns.txt",
    )
    lite = compare_variant(
        "lite",
        BASELINE_DIR / "upstream-adblockdnslite.txt",
        CURRENT_DIR / "adblockdnslite.txt",
    )
    if full["metrics"]["current_version"] != lite["metrics"]["current_version"]:
        raise SystemExit("Current Full and Lite outputs have different build versions")
    write_reports(full, lite)


if __name__ == "__main__":
    main()
