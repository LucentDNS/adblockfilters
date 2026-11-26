#!/usr/bin/env python3
"""Build the AdBlock DNS validation input from its own selected DNS/Hosts sources."""
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from readme import ReadMe, Rule  # noqa: E402 - project-root bootstrap above
from resolver import Resolver, configure_logging  # noqa: E402 - project-root bootstrap above
from updater import Updater  # noqa: E402 - project-root bootstrap above
from scripts.validated_sources import validation_logic_sha256  # noqa: E402 - project-root bootstrap above
SOURCE_DIR = ROOT / ".cache" / "source"
DOMAIN_DIR = ROOT / ".cache" / "domain"
MYBLOCK_SOURCE = ROOT / "rules" / "myblock.txt"


def domains_from_block_dict(block_dict):
    """Convert Resolver's normalized block map to valid DNS names; omit IP literals."""
    domains = set()
    for fld, subdomains in block_dict.items():
        if not fld:
            continue
        for subdomain in subdomains:
            domain = (f"{subdomain}.{fld}" if subdomain else fld).lower().strip(".")
            if not domain or any(char.isspace() for char in domain):
                continue
            domains.add(domain)
    return domains


def main():
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    DOMAIN_DIR.mkdir(parents=True, exist_ok=True)

    all_rules = ReadMe(str(ROOT / "README.md")).getRules()
    dns_rules = [rule for rule in all_rules if rule.type in ("host", "dns", "dnsfilter")]
    if not dns_rules:
        raise SystemExit("No DNS/Hosts sources are configured in README.md")

    Updater(dns_rules).update(str(SOURCE_DIR))
    if not MYBLOCK_SOURCE.is_file() or MYBLOCK_SOURCE.stat().st_size == 0:
        raise SystemExit("Project myblock.txt is missing or empty")
    shutil.copy2(MYBLOCK_SOURCE, SOURCE_DIR / "myblock.txt")

    resolver = Resolver(str(SOURCE_DIR))
    source_counts = {}
    all_domains = set()

    for rule in dns_rules:
        if rule.type == "host":
            block_dict, _, _ = resolver.resolveHost(rule)
        elif rule.type == "dns":
            block_dict, _, _ = resolver.resolveDNS(rule)
        else:
            block_dict, _, _ = resolver.resolveFilter(rule)
        domains = domains_from_block_dict(block_dict)
        if rule.type == "host":
            resolver.explicit_block_domains.update(domains)
        if not domains:
            raise SystemExit(
                f"DNS/Hosts source {rule.name} produced no valid block domains; refusing a partial validation input"
            )
        source_counts[rule.name] = len(domains)
        all_domains.update(domains)

    custom_rule = Rule("myblock", "dns", "", "")
    custom_blocks, _, _ = resolver.resolveDNS(custom_rule)
    custom_domains = domains_from_block_dict(custom_blocks)
    source_counts["myblock"] = len(custom_domains)
    all_domains.update(custom_domains)

    # Resolver normalizes a wildcard suffix such as ||*.example.com^ to
    # example.com for rule compilation. Do not query that apex merely because
    # the wildcard exists: the apex may be NXDOMAIN while subdomains are live.
    # Keep the candidate if any source also contains an explicit exact-domain
    # block for the same name.
    wildcard_only = resolver.wildcard_block_domains - resolver.explicit_block_domains
    if wildcard_only:
        all_domains.difference_update(wildcard_only)
        print(f"Skipped wildcard-only DNS validation candidates: {len(wildcard_only)}")

    if not all_domains:
        raise SystemExit("Selected DNS/Hosts sources produced no valid block domains")

    output = DOMAIN_DIR / "domain.txt"
    output.write_text("\n".join(sorted(all_domains)) + "\n", encoding="utf-8")
    domain_file_sha256 = hashlib.sha256(output.read_bytes()).hexdigest()

    provenance = {
        "generator": "AdBlock DNS selected DNS/Hosts sources",
        "source_count": len(dns_rules),
        "sources": [
            {
                "name": rule.name,
                "type": rule.type,
                "url": rule.url,
                "latest": rule.latest,
                "sha256": hashlib.sha256((SOURCE_DIR / rule.filename).read_bytes()).hexdigest(),
                "parsed_block_domains": source_counts[rule.name],
            }
            for rule in dns_rules
        ],
        "myblock_sha256": hashlib.sha256(MYBLOCK_SOURCE.read_bytes()).hexdigest(),
        "validation_logic_sha256": validation_logic_sha256(),
        "myblock_parsed_block_domains": source_counts["myblock"],
        "unique_validation_domains": len(all_domains),
        "domain_file_sha256": domain_file_sha256,
    }
    (DOMAIN_DIR / "domain-input-provenance.json").write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"AdBlock DNS/Hosts sources: {len(dns_rules)}")
    for name, count in sorted(source_counts.items()):
        print(f"  {name}: {count}")
    print(f"Unique DNS validation domains: {len(all_domains)}")
    print(f"Output: {output}")


if __name__ == "__main__":
    configure_logging()
    main()
