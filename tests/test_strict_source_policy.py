import json
from pathlib import Path

from scripts.audit_sources import classify_strict_source_candidates


ROOT = Path(__file__).resolve().parents[1]


def test_source_policy_classifies_every_enabled_dns_source_once():
    manifest = json.loads((ROOT / "sources.json").read_text(encoding="utf-8"))
    policy = json.loads((ROOT / "source-policy.json").read_text(encoding="utf-8"))
    production = {
        source["name"]
        for source in manifest["sources"]
        if source.get("enabled", True) and source["type"] in {"host", "dns", "dnsfilter"}
    }
    strict = set(policy["strict_review_sources"])
    comparison = set(policy["comparison_sources"])
    assert strict.isdisjoint(comparison)
    assert strict | comparison == production
    assert strict == {"HaGeZi DNS-Blocklists"}


def test_strict_only_candidates_are_not_treated_as_explicit_allows():
    strict_only, conflicts = classify_strict_source_candidates(
        strict_blocks={"sub.safe.example", "unique.example", "allowed.example", "child.blocked.example"},
        comparison_blocks={"safe.example", "blocked.example"},
        comparison_allows={"allowed.example"},
        whitelist=set(),
    )
    assert strict_only == ["unique.example"]
    assert conflicts == ["allowed.example"]


def test_project_whitelist_excludes_strict_only_candidates():
    strict_only, conflicts = classify_strict_source_candidates(
        strict_blocks={"protected.example", "unlisted.example"},
        comparison_blocks=set(),
        comparison_allows=set(),
        whitelist={"protected.example"},
    )
    assert strict_only == ["unlisted.example"]
    assert conflicts == []


def test_parent_allow_conflicts_cover_strict_subdomains():
    strict_only, conflicts = classify_strict_source_candidates(
        strict_blocks={"child.allowed.example"},
        comparison_blocks=set(),
        comparison_allows={"allowed.example"},
        whitelist=set(),
    )
    assert strict_only == []
    assert conflicts == ["child.allowed.example"]


def test_parent_block_and_child_allow_are_reported_as_conflict():
    strict_only, conflicts = classify_strict_source_candidates(
        strict_blocks={"example.com"},
        comparison_blocks=set(),
        comparison_allows={"app.example.com"},
        whitelist=set(),
    )
    assert strict_only == []
    assert conflicts == ["example.com"]
