from pathlib import Path

import pytest

from scripts.compare_baseline import compare_variant, parse_filter, write_reports


def _write_filter(path: Path, title: str, version: str, rules: list[str]) -> None:
    path.write_text(
        "\n".join([title, f"! Version: {version}", *rules]) + "\n",
        encoding="utf-8",
    )


def test_full_and_lite_comparisons_write_separate_deterministic_reports(tmp_path, monkeypatch):
    baseline_dir = tmp_path / "baseline"
    current_dir = tmp_path / "current"
    report_dir = tmp_path / "report"
    baseline_dir.mkdir()
    current_dir.mkdir()

    _write_filter(
        baseline_dir / "full.txt",
        "! Title: AdBlock DNS",
        "upstream-full",
        ["||shared.example^", "||old-full.example^"],
    )
    _write_filter(
        current_dir / "full.txt",
        "! Title: AdBlock DNS",
        "current-build",
        ["||shared.example^", "||new-full.example^"],
    )
    _write_filter(
        baseline_dir / "lite.txt",
        "! Title: AdBlock DNS Lite",
        "upstream-lite",
        ["||shared.example^", "@@||allow.example^"],
    )
    _write_filter(
        current_dir / "lite.txt",
        "! Title: AdBlock DNS Lite",
        "current-build",
        ["||shared.example^", "||new-lite.example^", "@@||allow.example^"],
    )

    monkeypatch.setattr("scripts.compare_baseline.REPORT_DIR", report_dir)
    full = compare_variant(
        "full", baseline_dir / "full.txt", current_dir / "full.txt", minimum_rules=1
    )
    lite = compare_variant(
        "lite", baseline_dir / "lite.txt", current_dir / "lite.txt", minimum_rules=1
    )
    write_reports(full, lite)

    assert full["metrics"]["baseline_only"] == 1
    assert full["metrics"]["optimized_only"] == 1
    assert lite["metrics"]["baseline_allow_rules"] == 1
    assert lite["metrics"]["optimized_allow_rules"] == 1
    assert (report_dir / "lite-baseline-only-domains.txt").read_text() == (
        "! No upstream-only Lite block domains in this comparison.\n"
    )
    assert "## Full" in (report_dir / "comparison.md").read_text()
    assert "## Lite" in (report_dir / "comparison.md").read_text()


def test_parse_filter_rejects_wrong_title_missing_version_and_small_files(tmp_path):
    path = tmp_path / "bad.txt"
    _write_filter(path, "! Title: Wrong", "v1", ["||one.example^"])
    with pytest.raises(SystemExit, match="Unexpected title"):
        parse_filter(path, "! Title: AdBlock DNS", 1)

    _write_filter(path, "! Title: AdBlock DNS", "", ["||one.example^"])
    with pytest.raises(SystemExit, match="version marker"):
        parse_filter(path, "! Title: AdBlock DNS", 1)

    _write_filter(path, "! Title: AdBlock DNS", "v1", ["||one.example^"])
    with pytest.raises(SystemExit, match="unexpectedly small"):
        parse_filter(path, "! Title: AdBlock DNS", 2)


def test_parse_filter_rejects_non_domain_and_duplicate_rules(tmp_path):
    path = tmp_path / "bad-rules.txt"
    _write_filter(
        path,
        "! Title: AdBlock DNS",
        "v1",
        ["||one.example^", "||two.example^$third-party"],
    )
    with pytest.raises(SystemExit, match="non-domain rules"):
        parse_filter(path, "! Title: AdBlock DNS", 1)

    _write_filter(
        path,
        "! Title: AdBlock DNS",
        "v1",
        ["||one.example^", "||one.example^"],
    )
    with pytest.raises(SystemExit, match="duplicate rules"):
        parse_filter(path, "! Title: AdBlock DNS", 1)


def test_parse_filter_accepts_domain_and_exception_rules(tmp_path):
    path = tmp_path / "valid.txt"
    _write_filter(
        path,
        "! Title: AdBlock DNS",
        "v1",
        ["||ads.example^", "@@||safe.example^", "||*-analytics*.huami.com^"],
    )

    parsed = parse_filter(path, "! Title: AdBlock DNS", 1)

    assert parsed["version"] == "v1"
    assert len(parsed["rules"]) == 3


def test_parse_filter_rejects_dns_service_record_labels_as_hostnames(tmp_path):
    path = tmp_path / "service-record.txt"
    _write_filter(path, "! Title: AdBlock DNS", "v1", ["||_domainkey.example.com^"])
    with pytest.raises(SystemExit, match="non-domain rules"):
        parse_filter(path, "! Title: AdBlock DNS", 1)


def test_parse_filter_accepts_supported_dns_wildcard_patterns(tmp_path):
    path = tmp_path / "wildcards.txt"
    _write_filter(
        path, "! Title: AdBlock DNS", "v1",
        ["||*-analytics*.huami.com^", "||*-sdk.rum.aliyuncs.com^", "@@||safe*.example.com^"],
    )
    parsed = parse_filter(path, "! Title: AdBlock DNS", 1)
    assert len(parsed["rules"]) == 3
