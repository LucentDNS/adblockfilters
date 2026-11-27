#!/usr/bin/env python3
"""Build a conservative domestic-domain set for Lite without bulk DNS lookups.

The classification is based only on .cn domains and exact/domain entries from
217heidai RoutingRules. It does not require or infer DNS liveness.
"""
import hashlib
import json
import os
from pathlib import Path

import httpx
from tld import get_tld

ROOT = Path(__file__).resolve().parents[1]
DIRECT_RULES_URL = "https://raw.githubusercontent.com/217heidai/RoutingRules/main/rules/direct.txt"
TIMEOUT = httpx.Timeout(30.0, connect=10.0)


def parse_direct_rules(content: str) -> tuple[set[str], set[str]]:
    """Return conservative full-host and registrable-domain classification sets."""
    full_domains: set[str] = set()
    domain_roots: set[str] = set()
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("full:"):
            value = line[len("full:"):].strip().lower().strip(".")
            if value:
                full_domains.add(value)
        elif line.startswith("domain:"):
            value = line[len("domain:"):].strip().lower().strip(".")
            if value:
                domain_roots.add(value)
    if not (full_domains or domain_roots):
        raise RuntimeError("China direct-domain source has no usable full:/domain: rules")
    return full_domains, domain_roots


def _download_direct_rules(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".download")
    try:
        with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
            response = client.get(DIRECT_RULES_URL)
        response.raise_for_status()
        content_type = (response.headers.get("Content-Type") or "").lower()
        if "text/plain" not in content_type:
            raise RuntimeError(f"unexpected Content-Type for China direct rules: {content_type}")
        body = response.content
        prefix = body.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
        if not body.strip() or prefix.startswith((b"<!doctype html", b"<html")):
            raise RuntimeError("China direct-domain source is empty or an HTML error page")
        temporary.write_bytes(body)
        os.replace(temporary, path)
        return body
    except Exception:
        if temporary.exists():
            temporary.unlink()
        if not path.is_file() or path.stat().st_size == 0:
            raise
        return path.read_bytes()


def _registrable_domain(domain: str) -> str | None:
    try:
        return get_tld(domain, fix_protocol=True, as_object=True).fld.lower()
    except Exception:
        return None


def classify_domains(
    domains: set[str],
    full_domains: set[str],
    domain_roots: set[str],
) -> set[str]:
    """Classify only .cn, explicit full-host, and registrable direct-domain matches."""
    direct = set()
    for domain in domains:
        normalized = domain.strip().lower().strip(".")
        if not normalized:
            continue
        if normalized.endswith(".cn") or normalized in full_domains:
            direct.add(normalized)
            continue
        fld = _registrable_domain(normalized)
        if fld and fld in domain_roots:
            direct.add(normalized)
    return direct


def generate_china_list(domain_dir: str | Path) -> dict:
    domain_dir = Path(domain_dir)
    domain_file = domain_dir / "domain.txt"
    china_file = domain_dir / "china.txt"
    direct_file = domain_dir / "rules" / "direct.txt"
    if not domain_file.is_file() or domain_file.stat().st_size == 0:
        raise RuntimeError("Current DNS source domain input is missing or empty")

    domains = {
        line.strip().lower().strip(".")
        for line in domain_file.read_text(encoding="utf-8-sig").splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "!"))
    }
    if not domains:
        raise RuntimeError("Current DNS source domain input contains no usable domains")

    direct_bytes = _download_direct_rules(direct_file)
    full_domains, domain_roots = parse_direct_rules(direct_bytes.decode("utf-8-sig", errors="replace"))
    china = classify_domains(domains, full_domains, domain_roots)
    if not china:
        raise RuntimeError(
            "Domestic Lite classification produced no domains; refusing an empty DNS Lite scope"
        )

    china_file.write_text("\n".join(sorted(china)) + "\n", encoding="utf-8")
    provenance = {
        "generator": "AdBlock conservative domestic Lite classifier",
        "classification_policy": [
            ".cn suffix",
            "217heidai RoutingRules full: exact-domain entries",
            "217heidai RoutingRules domain: registrable-domain entries",
        ],
        "direct_rules_url": DIRECT_RULES_URL,
        "direct_rules_sha256": hashlib.sha256(direct_bytes).hexdigest(),
        "current_source_domain_count": len(domains),
        "direct_classified_domain_count": len(china),
        "china_classified_domain_count": len(china),
        "china_file_sha256": hashlib.sha256(china_file.read_bytes()).hexdigest(),
    }
    (domain_dir / "china-classification.json").write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return provenance


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--domain-dir", default=str(ROOT / ".cache" / "domain"))
    args = parser.parse_args()
    result = generate_china_list(args.domain_dir)
    print(json.dumps(result, ensure_ascii=False, indent=2))
