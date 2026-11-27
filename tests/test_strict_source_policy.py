from scripts.audit_sources import classify_strict_source_candidates


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
