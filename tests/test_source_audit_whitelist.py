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
    assert audit_sources.source_audit_gate_failures(0, 0, set(), set(), set(), set()) == []


def test_source_audit_gate_rejects_unparsed_or_lost_source_rules():
    failures = audit_sources.source_audit_gate_failures(
        1,
        1,
        {"lost.example"},
        {"inactive.example"},
        {"blocked-allow.example"},
        {"unexplained-baseline.example"},
    )

    assert len(failures) == 6
    assert "unparsed rule lines" in failures[0]
    assert "non-domain filter rules" in failures[1]
    assert "lost.example" in failures[2]
    assert "inactive.example" in failures[3]
    assert "blocked-allow.example" in failures[4]
    assert "unexplained-baseline.example" in failures[5]


def test_unexplained_upstream_baseline_domains_block_publication():
    failures = audit_sources.source_audit_gate_failures(
        0, 0, set(), set(), set(), {"legacy-ad-domain.example"}
    )
    assert len(failures) == 1
    assert "absent from current DNS sources" in failures[0]
    assert "legacy-ad-domain.example" in failures[0]


def test_explained_upstream_baseline_delta_does_not_require_output_identity():
    # Differences explicitly explained by current DNS validation, project
    # exceptions, source allow rules, or manual evidence do not force cloning.
    assert audit_sources.source_audit_gate_failures(0, 0, set(), set(), set(), set()) == []
