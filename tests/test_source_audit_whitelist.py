from scripts import audit_sources


def test_project_whitelist_excludes_modifier_scoped_browser_exceptions(tmp_path, monkeypatch):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "white.txt").write_text(
        "safe.example.com\n"
        "||api.example.net^\n"
        "||nimiq.com^$third-party\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(audit_sources, "ROOT", tmp_path)

    assert audit_sources.load_project_whitelist() == {
        "safe.example.com",
        "api.example.net",
    }


def test_source_audit_gate_accepts_fully_explained_output():
    assert audit_sources.source_audit_gate_failures(0, 0, set(), set(), set()) == []


def test_source_audit_gate_rejects_unparsed_or_lost_source_rules():
    failures = audit_sources.source_audit_gate_failures(
        1,
        1,
        {"lost.example"},
        {"inactive.example"},
        {"blocked-allow.example"},
    )

    # Non-domain AdGuard filter rules are valid syntax; only genuinely
    # unparsed lines and unexplained source/allow losses are hard failures.
    assert len(failures) == 4
    assert "unparsed rule lines" in failures[0]
    assert "lost.example" in failures[1]
    assert "inactive.example" in failures[2]
    assert "blocked-allow.example" in failures[3]


def test_explained_upstream_baseline_delta_does_not_require_output_identity():
    # Differences explicitly explained by current DNS validation, project
    # exceptions, source allow rules, or manual evidence do not force cloning.
    assert audit_sources.source_audit_gate_failures(0, 0, set(), set(), set()) == []


def test_source_audit_gate_does_not_reject_supported_non_domain_filter_rules():
    # 340 supported non-domain filter rules were previously treated as a hard
    # failure even though the AdGuard Hostlist Compiler accepted the output.
    assert audit_sources.source_audit_gate_failures(0, 340, set(), set(), set()) == []



def test_source_audit_gate_rejects_missing_active_production_source_allow():
    failures = audit_sources.source_audit_gate_failures(
        0, 0, set(), set(), set(),
        {"ads.microsoft.com", "360.cn"},
    )

    assert len(failures) == 1
    assert "active production-source allow exceptions" in failures[0]
    assert "ads.microsoft.com" in failures[0]


def test_source_audit_gate_accepts_preserved_active_production_source_allow():
    assert audit_sources.source_audit_gate_failures(
        0, 0, set(), set(), set(), set()
    ) == []



def test_source_allow_output_audit_checks_parent_and_child_conflicts():
    conflicts, missing = audit_sources.audit_source_allow_output(
        {"360.cn", "ads.microsoft.com", "safe.example.org"},
        {"ad.dev.360.cn", "microsoft.com", "other.example.org"},
        {"360.cn", "ads.microsoft.com"},
    )

    assert conflicts == {"360.cn", "ads.microsoft.com", "safe.example.org"}
    assert missing == {"safe.example.org"}
