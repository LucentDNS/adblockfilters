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
FILTER_OUTPUT = ROOT / ".cache" / "out" / "adblockfilters.txt"
SOURCE_DIR = ROOT / ".cache" / "source"
MAX_DNS_RULES = 500_000


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


def parse_rules(path, browser_filter=False):
    resolver = Resolver(str(SOURCE_DIR))
    block_domains = set()
    allow_domains = set()

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith(("!", "#")):
            continue
        try:
            if browser_filter:
                block, unblock, filt = resolver._Resolver__resolveFilter(line)
            else:
                block, unblock, filt = resolver._Resolver__resolveDNS(line)
        except Exception:
            continue
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
    if not CRITICAL_FILE.is_file() or not DNS_OUTPUT.is_file() or not FILTER_OUTPUT.is_file():
        raise SystemExit("Critical-domain regression inputs or compiled DNS/browser outputs are missing")

    critical_domains = [
        line.strip().lower()
        for line in CRITICAL_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not critical_domains:
        raise SystemExit("Critical-domain regression list is empty")

    dns_rule_count = sum(
        1 for line in DNS_OUTPUT.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.lstrip().startswith("!")
    )
    if dns_rule_count > MAX_DNS_RULES:
        raise SystemExit(
            f"DNS output exceeds the 500,000-rule resource limit: {dns_rule_count}"
        )

    failures = []
    output_summaries = []
    for label, path, browser_filter in (
        ("DNS", DNS_OUTPUT, False),
        ("browser", FILTER_OUTPUT, True),
    ):
        block_domains, allow_domains = parse_rules(path, browser_filter=browser_filter)
        output_summaries.append((label, len(block_domains), len(allow_domains)))
        for domain in critical_domains:
            blocks = sorted(rule for rule in block_domains if domain == rule or domain.endswith("." + rule))
            allows = sorted(rule for rule in allow_domains if domain == rule or domain.endswith("." + rule))
            if blocks and not allows:
                failures.append((label, domain, blocks))

    if failures:
        for label, domain, blocks in failures:
            print(f"BLOCKED CRITICAL DOMAIN ({label}): {domain}; matching block rules: {', '.join(blocks)}")
        raise SystemExit(f"{len(failures)} critical service/output combinations are blocked")

    summary = "; ".join(
        f"{label}: {blocks} block domains, {allows} allow domains"
        for label, blocks, allows in output_summaries
    )
    print(
        f"Build quality gate passed: {dns_rule_count}/{MAX_DNS_RULES} DNS rules; "
        f"{len(critical_domains)} critical service roots checked in DNS and browser outputs; {summary}"
    )


if __name__ == "__main__":
    main()
