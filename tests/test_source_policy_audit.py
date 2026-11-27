from scripts.source_policy_audit import classify_strict_domains


def test_absence_from_stability_sources_is_not_allow_and_strict_only_is_review():
    result = classify_strict_domains(
        {"tracker.example", "api.example.com"},
        set(),
        set(),
        set(),
        set(),
    )
    assert result["strict_only_review"] == {"tracker.example", "api.example.com"}
    assert result["explicit_allow_conflicts"] == set()


def test_explicit_stability_allow_is_reported_as_conflict_not_silently_ignored():
    result = classify_strict_domains(
        {"ads.example.com"},
        set(),
        {"example.com"},
        set(),
        set(),
    )
    assert result["explicit_allow_conflicts"] == {"ads.example.com"}
    assert "ads.example.com" not in result["strict_only_review"]


def test_parent_block_supports_child_but_child_does_not_support_parent():
    result = classify_strict_domains(
        {"a.example.com", "example.com"},
        {"example.com"},
        set(),
        set(),
        set(),
    )
    assert result["stability_supported"] == {"a.example.com", "example.com"}
    assert result["strict_only_review"] == set()


def test_whitelist_is_separate_from_upstream_allow_evidence():
    result = classify_strict_domains(
        {"ads.example.com"},
        set(),
        set(),
        set(),
        {"example.com"},
    )
    assert result["whitelist_excluded"] == {"ads.example.com"}
    assert result["explicit_allow_conflicts"] == set()
    assert result["strict_only_review"] == set()


def test_targeted_source_support_is_reported_separately():
    result = classify_strict_domains(
        {"ads.example.com"},
        set(),
        set(),
        {"example.com"},
        set(),
    )
    assert result["targeted_supported"] == {"ads.example.com"}
    assert result["strict_only_review"] == set()


def test_other_reference_candidate_support_is_separate_from_targeted_support():
    result = classify_strict_domains(
        {"ads.example.com"},
        set(),
        set(),
        set(),
        set(),
        {"example.com"},
    )
    assert result["other_reference_supported"] == {"ads.example.com"}
    assert result["targeted_supported"] == set()
    assert result["strict_only_review"] == set()
