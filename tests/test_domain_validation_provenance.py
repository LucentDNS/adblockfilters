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

    rule = Rule("AdGuard DNS filter", "dns", "https://example.com/list.txt", "")
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


def test_refresh_preserves_dns_snapshot_used_for_validation(tmp_path, monkeypatch):
    import adblock

    rules, source_dir, domain_dir, source_path = _prepare(tmp_path)
    original = source_path.read_bytes()

    class FakeUpdater:
        def __init__(self, rule_list):
            self.rule_list = rule_list

        def update(self, path):
            source_path.write_text("||changed-after-validation.example^\\n", encoding="utf-8")
            return True, self.rule_list

    monkeypatch.setattr(adblock, "Updater", FakeUpdater)

    updated, returned_rules = adblock.update_sources_preserving_validated_dns(
        rules, str(source_dir), str(domain_dir)
    )

    assert updated is True
    assert returned_rules == rules
    assert source_path.read_bytes() == original
    assert verify_domain_validation_provenance(rules, str(source_dir), str(domain_dir))
