#!/usr/bin/env python3
"""Package and restore the exact DNS/Hosts source snapshots used for DNS validation."""
import hashlib
import json
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from readme import ReadMe  # noqa: E402 - project-root bootstrap above

SOURCE_DIR = ROOT / ".cache" / "source"
DOMAIN_DIR = ROOT / ".cache" / "domain"
ARCHIVE = DOMAIN_DIR / "validated-dns-sources.tar.gz"
PROVENANCE = DOMAIN_DIR / "domain-input-provenance.json"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_sources():
    provenance = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    rules = {
        rule.name: rule
        for rule in ReadMe(str(ROOT / "README.md")).getRules()
        if rule.type in ("host", "dns", "dnsfilter")
    }
    records = provenance.get("sources")
    if not isinstance(records, list) or set(rules) != {
        item.get("name") for item in records if isinstance(item, dict)
    }:
        raise SystemExit("DNS source list in provenance does not match README")
    result = []
    for record in records:
        rule = rules[record["name"]]
        if record.get("type") != rule.type or record.get("url") != rule.url:
            raise SystemExit(f"DNS source metadata mismatch: {rule.name}")
        result.append((rule.filename, record["sha256"]))
    return result


def package():
    DOMAIN_DIR.mkdir(parents=True, exist_ok=True)
    files = expected_sources()
    with tarfile.open(ARCHIVE, "w:gz") as archive:
        for filename, expected_hash in files:
            path = SOURCE_DIR / filename
            if not path.is_file() or sha256(path) != expected_hash:
                raise SystemExit(f"Validated source snapshot missing or changed: {filename}")
            archive.add(path, arcname=filename)
    print(f"Packaged {len(files)} validated DNS/Hosts source snapshots: {ARCHIVE}")


def restore():
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    files = expected_sources()
    expected = dict(files)
    with tarfile.open(ARCHIVE, "r:gz") as archive:
        members = {Path(member.name).name: member for member in archive.getmembers()
                   if member.isfile() and Path(member.name).name == member.name}
        if set(members) != set(expected):
            raise SystemExit("Validated DNS source archive contents do not match provenance")
        for filename, expected_hash in files:
            member = members[filename]
            source = archive.extractfile(member)
            if source is None:
                raise SystemExit(f"Cannot read validated source snapshot: {filename}")
            target = SOURCE_DIR / filename
            target.write_bytes(source.read())
            if sha256(target) != expected_hash:
                raise SystemExit(f"Restored DNS source hash mismatch: {filename}")
    print(f"Restored and verified {len(files)} validated DNS/Hosts source snapshots")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("package", "restore"):
        raise SystemExit("Usage: validated_sources.py package|restore")
    package() if sys.argv[1] == "package" else restore()
