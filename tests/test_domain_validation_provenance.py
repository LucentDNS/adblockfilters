import hashlib
import json

import pytest

from adblock import verify_domain_validation_provenance
from readme import Rule


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _prepare(tmp_path):
    source_dir = tmp_path / "source"
    domain_dir = tmp_path / "domain"
    source_dir.mkdir()
    domain_dir.mkdir()

    rule = Rule("AdGuard DNS filter", "dns", "https://example.com/list.txt", "2026/11/24")
    source_path = source_dir / rule.filename
    source_path.write_text("||ads.example.com^\n", encoding="utf-8")
    myblock_path = source_dir / "myblock.txt"
    myblock_path.write_text("||custom.example^\n", encoding="utf-8")
    domain_path = domain_dir / "domain.txt"
    domain_path.write_text("ads.example.com\ncustom.example\n", encoding="utf-8")

    provenance = {
        "sources": [{
            "name": rule.name,
            "type": rule.type,
            "url": rule.url,
            "latest": rule.latest,
            "sha256": _sha256(source_path),
        }],
        "myblock_sha256": _sha256(myblock_path),
        "unique_validation_domains": 2,
        "domain_file_sha256": _sha256(domain_path),
    }
    (domain_dir / "domain-input-provenance.json").write_text(
        json.dumps(provenance), encoding="utf-8"
    )
    return [rule], source_dir, domain_dir, source_path


def test_validation_provenance_accepts_exact_source_snapshots(tmp_path):
    rules, source_dir, domain_dir, _ = _prepare(tmp_path)

    assert verify_domain_validation_provenance(rules, str(source_dir), str(domain_dir))


def test_validation_provenance_rejects_changed_source_snapshot(tmp_path):
    rules, source_dir, domain_dir, source_path = _prepare(tmp_path)
    source_path.write_text("||new-ads.example.com^\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="changed after validation"):
        verify_domain_validation_provenance(rules, str(source_dir), str(domain_dir))


def test_validation_provenance_rejects_changed_domain_input(tmp_path):
    rules, source_dir, domain_dir, _ = _prepare(tmp_path)
    (domain_dir / "domain.txt").write_text("different.example\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="domain count mismatch|domain.txt changed"):
        verify_domain_validation_provenance(rules, str(source_dir), str(domain_dir))


def test_validation_provenance_rejects_changed_myblock_snapshot(tmp_path):
    rules, source_dir, domain_dir, _ = _prepare(tmp_path)
    (source_dir / "myblock.txt").write_text(
        "||changed-custom.example^\n", encoding="utf-8"
    )

    with pytest.raises(RuntimeError, match="myblock.txt changed after DNS validation"):
        verify_domain_validation_provenance(rules, str(source_dir), str(domain_dir))


def test_validation_provenance_rejects_same_count_but_changed_domain_input(tmp_path):
    rules, source_dir, domain_dir, _ = _prepare(tmp_path)
    (domain_dir / "domain.txt").write_text(
        "different.example\ncustom.example\n", encoding="utf-8"
    )

    with pytest.raises(RuntimeError, match="domain.txt changed after DNS validation"):
        verify_domain_validation_provenance(rules, str(source_dir), str(domain_dir))


def test_refresh_preserves_dns_snapshot_used_for_validation(tmp_path, monkeypatch):
    import adblock

    rules, source_dir, domain_dir, source_path = _prepare(tmp_path)
    original = source_path.read_bytes()

    class FakeUpdater:
        def __init__(self, rule_list):
            self.rule_list = rule_list

        def update(self, path):
            assert self.rule_list == []
            return True, self.rule_list

    monkeypatch.setattr(adblock, "Updater", FakeUpdater)

    updated, returned_rules = adblock.update_sources_preserving_validated_dns(
        rules, str(source_dir), str(domain_dir)
    )

    assert updated is True
    assert returned_rules == rules
    assert source_path.read_bytes() == original
    assert returned_rules[0].latest == "2026/11/24"
    assert verify_domain_validation_provenance(rules, str(source_dir), str(domain_dir))


def test_refresh_updates_browser_sources_without_replacing_validated_dns_sources(tmp_path, monkeypatch):
    import adblock

    dns_rules, source_dir, domain_dir, dns_source_path = _prepare(tmp_path)
    dns_original = dns_source_path.read_bytes()
    browser_rule = Rule(
        "AdGuard Base filter", "filter",
        "https://example.org/base.txt", "2026/11/24"
    )
    browser_source_path = source_dir / browser_rule.filename
    browser_source_path.write_text("old browser snapshot\n", encoding="utf-8")
    rules = dns_rules + [browser_rule]

    class FakeUpdater:
        def __init__(self, rule_list):
            self.rule_list = rule_list

        def update(self, path):
            assert self.rule_list == [browser_rule]
            browser_source_path.write_text("new browser snapshot\n", encoding="utf-8")
            browser_rule.latest = "2026/11/25"
            return True, self.rule_list

    monkeypatch.setattr(adblock, "Updater", FakeUpdater)

    updated, returned_rules = adblock.update_sources_preserving_validated_dns(
        rules, str(source_dir), str(domain_dir)
    )

    assert updated is True
    assert returned_rules == rules
    assert dns_source_path.read_bytes() == dns_original
    assert browser_source_path.read_text(encoding="utf-8") == "new browser snapshot\n"
    assert dns_rules[0].latest == "2026/11/24"
    assert browser_rule.latest == "2026/11/25"
    assert verify_domain_validation_provenance(rules, str(source_dir), str(domain_dir))


def test_validation_provenance_missing_fails_closed(tmp_path):
    rules, source_dir, domain_dir, _ = _prepare(tmp_path)
    (domain_dir / "domain-input-provenance.json").unlink()

    with pytest.raises(RuntimeError, match="provenance is missing"):
        verify_domain_validation_provenance(rules, str(source_dir), str(domain_dir))
