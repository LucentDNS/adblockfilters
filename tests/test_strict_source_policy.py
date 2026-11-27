import json
from pathlib import Path

from scripts.audit_sources import classify_review_focus_candidates, validate_source_policy


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
    assert review_focus | (comparison & production) == production
    candidate_names = {
        "OISD Blocklist Small (AdGuard Registry candidate only)",
        "OISD Blocklist Big (AdGuard Registry benchmark only; higher FP risk)",
        "CHN: AdRules DNS List (AdGuard Registry candidate only)",
        "HaGeZi Pro (AdGuard Registry benchmark against Pro Mini)",
        "HaGeZi Normal (AdGuard Registry benchmark against Pro Mini)",
    }
    assert comparison - production == {
        "OISD Blocklist Small (AdGuard Registry candidate only)",
        "OISD Blocklist Big (AdGuard Registry benchmark only; higher FP risk)",
    }
    assert validate_source_policy(policy, production, candidate_names) == (review_focus, comparison)
    assert review_focus == {"HaGeZi DNS-Blocklists"}
    lineage = policy["lineage_evidence"]
    assert any(
        item["source"] == "HaGeZi DNS-Blocklists"
        and "1Hosts Lite" in item["mentions"]
        for item in lineage
    )
    assert "not as an author-defined strict/aggressive tier" in policy["policy_note"]
    profiles = policy["policy_profiles"]
    assert any(
        item["sources"] == ["HaGeZi DNS-Blocklists"]
        and "low-to-moderate breakage" in item["philosophy"]
        for item in profiles
    )
    assert any(
        "OISD Blocklist Small (AdGuard Registry candidate only)" in item["sources"]
        and "zero breakage" in item["philosophy"]
        for item in profiles
    )
    assert any(
        item["sources"] == ["AdGuard DNS filter"]
        and "sufficient site traffic" in item["philosophy"]
        for item in profiles
    )


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


def test_parent_allow_conflicts_cover_review_focus_subdomains():
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


def test_candidate_only_comparisons_are_allowed_but_not_production_sources():
    policy = {
        "version": 1,
        "review_focus_sources": {"focus"},
        "comparison_sources": {"stable", "OISD candidate"},
    }
    assert validate_source_policy(policy, {"focus", "stable"}, {"OISD candidate"}) == (
        {"focus"}, {"stable", "OISD candidate"}
    )


def test_unknown_comparison_source_is_rejected():
    policy = {
        "version": 1,
        "review_focus_sources": {"focus"},
        "comparison_sources": {"stable", "unknown"},
    }
    try:
        validate_source_policy(policy, {"focus", "stable"}, {"known candidate"})
    except ValueError as exc:
        assert "Unknown comparison sources" in str(exc)
    else:
        raise AssertionError("unknown comparison sources must fail closed")


def test_candidate_source_cannot_replace_a_production_classification():
    policy = {
        "version": 1,
        "review_focus_sources": {"focus"},
        "comparison_sources": {"OISD candidate"},
    }
    try:
        validate_source_policy(policy, {"focus", "stable"}, {"OISD candidate"})
    except ValueError as exc:
        assert "classified exactly once" in str(exc)
    else:
        raise AssertionError("all production sources must be classified")
