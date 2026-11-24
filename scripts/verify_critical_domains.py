#!/usr/bin/env python3
"""Fail the build if essential service domains are covered by DNS block rules."""
import ipaddress
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from resolver import Resolver

CRITICAL_FILE = ROOT / "tests" / "data" / "critical-domains.txt"
DNS_OUTPUT = ROOT / ".cache" / "out" / "adblockdns.txt"
SOURCE_DIR = ROOT / ".cache" / "source"


def normalize_domain(value):
    if not value:
        return None
    if isinstance(value, tuple) and len(value) == 2:
        fld, subdomain = value
        if not fld:
            return None
        domain = f"{subdomain}.{fld}" if subdomain else fld
    else:
        domain = str(value)
    domain = domain.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        return domain or None


def is_covered(domain, rules):
    return any(domain == rule or domain.endswith("." + rule) for rule in rules)


def parse_dns_rules(path):
    resolver = Resolver(str(SOURCE_DIR))
    block_domains = set()
    allow_domains = set()

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith(("!", "#")):
            continue
        block, unblock, filt = resolver._Resolver__resolveDNS(line)
        block_domain = normalize_domain(block)
        allow_domain = normalize_domain(unblock)
        if block_domain:
            block_domains.add(block_domain)
        if allow_domain:
            allow_domains.add(allow_domain)
        if filt:
            rule_text = filt[0] if isinstance(filt, (tuple, list)) else str(filt)
            filter_domain = normalize_domain(filt[1]) if isinstance(filt, (tuple, list)) and len(filt) > 1 else None
            if filter_domain:
                if rule_text.lstrip().startswith("@@"):
                    allow_domains.add(filter_domain)
                else:
                    block_domains.add(filter_domain)

    return block_domains, allow_domains


def main():
    if not CRITICAL_FILE.is_file() or not DNS_OUTPUT.is_file():
        raise SystemExit("Critical-domain regression inputs or compiled DNS output are missing")

    critical_domains = [
        line.strip().lower()
        for line in CRITICAL_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not critical_domains:
        raise SystemExit("Critical-domain regression list is empty")

    block_domains, allow_domains = parse_dns_rules(DNS_OUTPUT)
    failures = []
    for domain in critical_domains:
        blocks = sorted(rule for rule in block_domains if domain == rule or domain.endswith("." + rule))
        allows = sorted(rule for rule in allow_domains if domain == rule or domain.endswith("." + rule))
        if blocks and not allows:
            failures.append((domain, blocks))

    if failures:
        for domain, blocks in failures:
            print(f"BLOCKED CRITICAL DOMAIN: {domain}; matching block rules: {', '.join(blocks)}")
        raise SystemExit(f"{len(failures)} critical service domains are blocked")

    print(
        f"Critical-domain regression passed: {len(critical_domains)} service roots; "
        f"{len(block_domains)} block domains; {len(allow_domains)} allow domains"
    )


if __name__ == "__main__":
    main()
