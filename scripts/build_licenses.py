#!/usr/bin/env python3
"""Validate and package third-party license notices beside published artifacts."""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LICENSE_MANIFEST = ROOT / "source-licenses.json"
SOURCE_MANIFEST = ROOT / "sources.json"
NOTICE_FILE = ROOT / "THIRD-PARTY-NOTICES.md"


def load_and_validate():
    manifest = json.loads(LICENSE_MANIFEST.read_text(encoding="utf-8"))
    sources = json.loads(SOURCE_MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("version") != 1 or not isinstance(manifest.get("sources"), list):
        raise ValueError("Unsupported source-licenses.json format")

    entries = manifest["sources"]
    names = [entry.get("name") for entry in entries]
    if len(names) != len(set(names)) or any(not isinstance(name, str) or not name for name in names):
        raise ValueError("Source license names must be non-empty and unique")

    active = {
        entry["name"]: ("production" if entry["type"] in {"host", "dns", "dnsfilter"} else "browser_supplement")
        for entry in sources["sources"] if entry.get("enabled", True)
    }
    mapped = {entry["name"]: entry.get("role") for entry in entries if entry.get("role") != "candidate_only"}
    if mapped != active:
        missing = sorted(set(active) - set(mapped))
        extra = sorted(set(mapped) - set(active))
        wrong = sorted(name for name in set(active) & set(mapped) if active[name] != mapped[name])
        raise ValueError(f"Source/license manifest mismatch: missing={missing}, extra={extra}, wrong_roles={wrong}")

    for entry in entries:
        license_file = entry.get("license_file")
        redistributable = entry.get("redistribute_audit_data", False)
        if redistributable and not license_file:
            raise ValueError(f"{entry['name']} permits audit data redistribution but has no license file")
        if license_file and not (ROOT / license_file).is_file():
            raise ValueError(f"Missing license text for {entry['name']}: {license_file}")
        if entry.get("role") == "candidate_only" and not redistributable and license_file:
            raise ValueError(f"Non-redistributable candidate must not be packaged with a blanket license: {entry['name']}")
    if not NOTICE_FILE.is_file():
        raise ValueError("THIRD-PARTY-NOTICES.md is missing")
    return manifest


def package(destination: Path, manifest):
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(LICENSE_MANIFEST, destination / "source-licenses.json")
    shutil.copy2(NOTICE_FILE, destination / "THIRD-PARTY-NOTICES.md")
    license_files = sorted({entry["license_file"] for entry in manifest["sources"] if entry.get("license_file")})
    for relative in license_files:
        source = ROOT / relative
        target = destination / ("LICENSE-" + source.name)
        shutil.copy2(source, target)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--audit-dir", type=Path)
    args = parser.parse_args()
    destinations = [path for path in (args.out_dir, args.source_dir, args.audit_dir) if path is not None]
    if not destinations:
        parser.error("at least one of --out-dir, --source-dir or --audit-dir is required")
    manifest = load_and_validate()
    for destination in destinations:
        package(destination, manifest)
        print(f"Packaged {len(manifest['sources'])} source license records into {destination}")


if __name__ == "__main__":
    main()
