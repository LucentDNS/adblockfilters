import json
from pathlib import Path

from scripts.audit_sources import classify_review_focus_candidates


ROOT = Path(__file__).resolve().parents[1]


def test_source_policy_classifies_every_enabled_dns_source_once():
    manifest = json.loads((ROOT / "sources.json").read_text(encoding="utf-8"))
    policy = json.loads((ROOT / "source-policy.json").read_text(encoding="utf-8"))
    production = {
        source["name"]
        for source in manifest["sources"]
        if source.get("enabled", True) and source["type"] in {"host", "dns", "dnsfilter"}
    }
    review_focus = set(policy["review_focus_sources"])
    comparison = set(policy["comparison_sources"])
    assert review_focus.isdisjoint(comparison)
    assert review_focus | comparison == production
    assert review_focus == {"HaGeZi DNS-Blocklists"}
    lineage = policy["lineage_evidence"]
    assert any(
        item["source"] == "HaGeZi DNS-Blocklists"
        and "1Hosts Lite" in item["mentions"]
        for item in lineage
    )
    assert "not as an author-defined strict/aggressive tier" in policy["policy_note"]


def test_review_focus_unshared_candidates_are_not_treated_as_explicit_allows():
    review_focus_unshared, conflicts = classify_review_focus_candidates(
        review_focus_blocks={"sub.safe.example", "unique.example", "allowed.example", "child.blocked.example"},
        comparison_blocks={"safe.example", "blocked.example"},
        comparison_allows={"allowed.example"},
        whitelist=set(),
    )
    assert review_focus_unshared == ["unique.example"]
    assert conflicts == ["allowed.example"]


def test_project_whitelist_excludes_review_focus_unshared_candidates():
    review_focus_unshared, conflicts = classify_review_focus_candidates(
        review_focus_blocks={"protected.example", "unlisted.example"},
        comparison_blocks=set(),
        comparison_allows=set(),
        whitelist={"protected.example"},
    )
    assert review_focus_unshared == ["unlisted.example"]
    assert conflicts == []


def test_parent_allow_conflicts_cover_strict_subdomains():
    review_focus_unshared, conflicts = classify_review_focus_candidates(
        review_focus_blocks={"child.allowed.example"},
        comparison_blocks=set(),
        comparison_allows={"allowed.example"},
        whitelist=set(),
    )
    assert review_focus_unshared == []
    assert conflicts == ["child.allowed.example"]


def test_parent_block_and_child_allow_are_reported_as_conflict():
    review_focus_unshared, conflicts = classify_review_focus_candidates(
        review_focus_blocks={"example.com"},
        comparison_blocks=set(),
        comparison_allows={"app.example.com"},
        whitelist=set(),
    )
    assert review_focus_unshared == []
    assert conflicts == ["example.com"]
