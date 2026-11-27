import json
from pathlib import Path

from scripts.build_licenses import ROOT, load_and_validate


def test_source_license_manifest_covers_all_enabled_sources_and_candidates():
    manifest = load_and_validate()
    sources = json.loads((ROOT / "sources.json").read_text(encoding="utf-8"))
    active = {item["name"] for item in sources["sources"] if item.get("enabled", True)}
    records = {item["name"]: item for item in manifest["sources"]}
    assert active <= set(records)
    assert len(records) == 18
    assert sum(item["role"] == "production" for item in records.values()) == 6
    assert sum(item["role"] == "browser_supplement" for item in records.values()) == 7
    assert sum(item["role"] == "candidate_only" for item in records.values()) == 5


def test_ad_rules_candidate_data_is_not_redistributed_without_upstream_license_clearance():
    manifest = load_and_validate()
    item = next(
        item for item in manifest["sources"]
        if item["name"] == "CHN: AdRules DNS List (AdGuard Registry candidate only)"
    )
    assert item["role"] == "candidate_only"
    assert item["redistribute_audit_data"] is False
    assert item["license_file"] is None


def test_every_redistributed_source_has_a_preserved_license_text():
    manifest = load_and_validate()
    for item in manifest["sources"]:
        if item["redistribute_audit_data"]:
            assert item["license_file"]
            assert (ROOT / item["license_file"]).is_file()
