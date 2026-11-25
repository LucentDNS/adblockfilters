import hashlib
import json
import tarfile
from pathlib import Path

import pytest

from readme import Rule
from scripts import validated_sources


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _prepare_state(tmp_path, monkeypatch):
    root = tmp_path
    domain_dir = root / ".cache" / "domain"
    source_dir = root / ".cache" / "source"
    rules_dir = root / "rules"
    domain_dir.mkdir(parents=True)
    source_dir.mkdir(parents=True)
    rules_dir.mkdir()

    rule = Rule("Test DNS source", "dns", "https://example.test/list.txt", "2026/11/25")
    source_bytes = b"||ads.example.test^\n"
    source_path = source_dir / rule.filename
    source_path.write_bytes(source_bytes)
    source_hash = hashlib.sha256(source_bytes).hexdigest()

    myblock_path = rules_dir / "myblock.txt"
    myblock_path.write_text("||custom.example.test^\n", encoding="utf-8")
    domain_path = domain_dir / "domain.txt"
    domain_path.write_text(
        "ads.example.test\ncustom.example.test\n", encoding="utf-8"
    )
    black_path = domain_dir / "black.txt"
    black_path.write_text("! no invalid domains\n", encoding="utf-8")
    china_path = domain_dir / "china.txt"
    china_path.write_text("ads.example.test\n", encoding="utf-8")
    marker_path = domain_dir / "dns-validation-bootstrap-complete-v2.txt"
    marker_path.write_text("fresh validation\n", encoding="utf-8")

    archive_path = domain_dir / "validated-dns-sources.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(source_path, arcname=rule.filename)

    provenance_path = domain_dir / "domain-input-provenance.json"
    provenance = {
        "sources": [
            {
                "name": rule.name,
                "type": rule.type,
                "url": rule.url,
                "sha256": source_hash,
            }
        ],
        "myblock_sha256": _sha256(myblock_path),
        "validation_logic_sha256": "logic-hash",
        "unique_validation_domains": 2,
        "domain_file_sha256": _sha256(domain_path),
        "validation_state": {
            "black_sha256": _sha256(black_path),
            "china_sha256": _sha256(china_path),
            "domain_sha256": _sha256(domain_path),
            "bootstrap_marker_sha256": _sha256(marker_path),
            "source_archive_sha256": _sha256(archive_path),
        },
    }
    provenance_path.write_text(json.dumps(provenance), encoding="utf-8")

    class FakeReadMe:
        def __init__(self, _path):
            pass

        def getRules(self):
            return [rule]

    monkeypatch.setattr(validated_sources, "ROOT", root)
    monkeypatch.setattr(validated_sources, "DOMAIN_DIR", domain_dir)
    monkeypatch.setattr(validated_sources, "SOURCE_DIR", source_dir)
    monkeypatch.setattr(validated_sources, "ARCHIVE", archive_path)
    monkeypatch.setattr(validated_sources, "PROVENANCE", provenance_path)
    monkeypatch.setattr(validated_sources, "MYBLOCK_SOURCE", myblock_path)
    monkeypatch.setattr(validated_sources, "ReadMe", FakeReadMe)
    monkeypatch.setattr(
        validated_sources, "validation_logic_sha256", lambda: "logic-hash"
    )
    return domain_dir, source_dir, myblock_path, archive_path


def test_check_current_accepts_a_complete_matching_state(tmp_path, monkeypatch):
    domain_dir, _, _, _ = _prepare_state(tmp_path, monkeypatch)

    assert validated_sources.check_current()
    assert (domain_dir / "domain-input-provenance.json").is_file()


def test_check_current_rejects_changed_myblock(tmp_path, monkeypatch):
    _, _, myblock_path, _ = _prepare_state(tmp_path, monkeypatch)
    myblock_path.write_text("||changed.example.test^\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="myblock.txt"):
        validated_sources.check_current()


def test_check_current_rejects_changed_validation_logic(tmp_path, monkeypatch):
    _prepare_state(tmp_path, monkeypatch)
    monkeypatch.setattr(
        validated_sources, "validation_logic_sha256", lambda: "new-logic-hash"
    )

    with pytest.raises(SystemExit, match="validation logic changed"):
        validated_sources.check_current()


def test_check_current_rejects_mixed_release_assets(tmp_path, monkeypatch):
    domain_dir, _, _, _ = _prepare_state(tmp_path, monkeypatch)
    (domain_dir / "china.txt").write_text("different.example.test\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="china.txt"):
        validated_sources.check_current()


def test_restore_extracts_only_verified_dns_source_snapshots(tmp_path, monkeypatch):
    _, source_dir, _, _ = _prepare_state(tmp_path, monkeypatch)
    (source_dir / "Test DNS source.txt").unlink(missing_ok=True)

    validated_sources.restore()

    restored = source_dir / "Test DNS source.txt"
    assert restored.read_text(encoding="utf-8") == "||ads.example.test^\n"
