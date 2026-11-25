#!/usr/bin/env python3
"""Package, seal, and verify the exact DNS validation state used by production builds."""
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
MYBLOCK_SOURCE = ROOT / "rules" / "myblock.txt"
VALIDATION_LOGIC_FILES = (
    ".github/workflows/blacklist.yml",
    "blacklist.py",
    "resolver.py",
    "smartdns.conf",
    "requirements.txt",
    "scripts/generate_domain_input.py",
    "scripts/validated_sources.py",
    "scripts/verify_critical_domains.py",
    "rules/direct.txt",
    "rules/ipv4_china.txt",
    "rules/myblock.txt",
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validation_logic_sha256():
    digest = hashlib.sha256()
    for relative_path in VALIDATION_LOGIC_FILES:
        path = ROOT / relative_path
        if not path.is_file():
            raise SystemExit(f"DNS validation logic file is missing: {relative_path}")
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\\0")
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\\0")
    return digest.hexdigest()


def _read_provenance():
    if not PROVENANCE.is_file():
        raise SystemExit("DNS validation provenance is missing")
    return json.loads(PROVENANCE.read_text(encoding="utf-8"))


def expected_sources():
    provenance = _read_provenance()
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


def _verify_current_inputs(provenance):
    if not MYBLOCK_SOURCE.is_file():
        raise SystemExit("Project myblock.txt is missing")
    if sha256(MYBLOCK_SOURCE) != provenance.get("myblock_sha256"):
        raise SystemExit("Current myblock.txt does not match the DNS-validated snapshot")
    expected_logic = provenance.get("validation_logic_sha256")
    if not expected_logic or expected_logic != validation_logic_sha256():
        raise SystemExit("DNS validation logic changed after the published state was generated")


def _verify_source_archive(files):
    if not ARCHIVE.is_file():
        raise SystemExit("Validated DNS source archive is missing")
    expected = dict(files)
    with tarfile.open(ARCHIVE, "r:gz") as archive:
        members = {
            Path(member.name).name: member
            for member in archive.getmembers()
            if member.isfile() and Path(member.name).name == member.name
        }
        if set(members) != set(expected):
            raise SystemExit("Validated DNS source archive contents do not match provenance")
        for filename, expected_hash in files:
            source = archive.extractfile(members[filename])
            if source is None:
                raise SystemExit(f"Cannot read validated DNS source snapshot: {filename}")
            digest = hashlib.sha256()
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
            if digest.hexdigest() != expected_hash:
                raise SystemExit(f"Validated DNS source archive hash mismatch: {filename}")


def package():
    DOMAIN_DIR.mkdir(parents=True, exist_ok=True)
    provenance = _read_provenance()
    files = expected_sources()
    _verify_current_inputs(provenance)
    with tarfile.open(ARCHIVE, "w:gz") as archive:
        for filename, expected_hash in files:
            path = SOURCE_DIR / filename
            if not path.is_file() or sha256(path) != expected_hash:
                raise SystemExit(f"Validated source snapshot missing or changed: {filename}")
            archive.add(path, arcname=filename)
    print(f"Packaged {len(files)} validated DNS/Hosts source snapshots: {ARCHIVE}")


def seal():
    provenance = _read_provenance()
    expected_sources()
    _verify_current_inputs(provenance)
    state_files = {
        "black_sha256": ROOT / "black.txt",
        "china_sha256": ROOT / "china.txt",
        "domain_sha256": ROOT / "domain.txt",
        "bootstrap_marker_sha256": ROOT / "dns-validation-bootstrap-complete-v2.txt",
        "source_archive_sha256": ARCHIVE,
    }
    state = {}
    for key, path in state_files.items():
        if not path.is_file():
            raise SystemExit(f"Cannot seal incomplete DNS validation state: {path.name} is missing")
        state[key] = sha256(path)
    if state["domain_sha256"] != provenance.get("domain_file_sha256"):
        raise SystemExit("DNS validation domain input changed before state publication")
    provenance["validation_state"] = state
    PROVENANCE.write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2) + "\\n",
        encoding="utf-8",
    )
    print("Sealed DNS validation outputs, source archive, and bootstrap marker hashes")


def check_current():
    provenance = _read_provenance()
    files = expected_sources()
    _verify_current_inputs(provenance)

    state = provenance.get("validation_state")
    if not isinstance(state, dict):
        raise SystemExit("Published DNS validation state is not sealed")

    state_files = {
        "black_sha256": DOMAIN_DIR / "black.txt",
        "china_sha256": DOMAIN_DIR / "china.txt",
        "domain_sha256": DOMAIN_DIR / "domain.txt",
        "bootstrap_marker_sha256": DOMAIN_DIR / "dns-validation-bootstrap-complete-v2.txt",
        "source_archive_sha256": ARCHIVE,
    }
    for key, path in state_files.items():
        if not path.is_file() or sha256(path) != state.get(key):
            raise SystemExit(f"DNS validation state asset is missing or mismatched: {path.name}")

    domain_path = DOMAIN_DIR / "domain.txt"
    domain_count = sum(
        1 for line in domain_path.read_text(encoding="utf-8").splitlines() if line.strip()
    )
    if domain_count != provenance.get("unique_validation_domains"):
        raise SystemExit("DNS validation domain count does not match provenance")
    if sha256(domain_path) != provenance.get("domain_file_sha256"):
        raise SystemExit("DNS validation domain input hash does not match provenance")

    _verify_source_archive(files)
    print(
        f"Verified current DNS validation state: {len(files)} source snapshots, "
        f"{domain_count} domains, sealed outputs, and matching validation logic"
    )
    return True


def restore():
    check_current()
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    files = expected_sources()
    with tarfile.open(ARCHIVE, "r:gz") as archive:
        members = {
            Path(member.name).name: member
            for member in archive.getmembers()
            if member.isfile() and Path(member.name).name == member.name
        }
        for filename, expected_hash in files:
            source = archive.extractfile(members[filename])
            if source is None:
                raise SystemExit(f"Cannot read validated DNS source snapshot: {filename}")
            target = SOURCE_DIR / filename
            target.write_bytes(source.read())
            if sha256(target) != expected_hash:
                raise SystemExit(f"Restored DNS source hash mismatch: {filename}")
    print(f"Restored and verified {len(files)} validated DNS/Hosts source snapshots")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("package", "seal", "check-current", "restore"):
        raise SystemExit(
            "Usage: validated_sources.py package|seal|check-current|restore"
        )
    {
        "package": package,
        "seal": seal,
        "check-current": check_current,
        "restore": restore,
    }[sys.argv[1]]()
