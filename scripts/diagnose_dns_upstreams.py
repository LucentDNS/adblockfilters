#!/usr/bin/env python3
"""Read-only diagnosis of per-upstream DNS response disagreements.

This tool never changes the DNS-validation database or production rule outputs.
"""
from __future__ import annotations

import argparse
import sqlite3
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import dns.resolver
from dns.exception import Timeout
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers

PORTS = (5053, 5054, 5055, 5056, 5057, 5058)
SAMPLE_SIZE = 500


def query_status(resolver: dns.resolver.Resolver, domain: str, rdtype: str) -> tuple[str, str]:
    try:
        answer = resolver.resolve(domain, rdtype)
        return ("answer" if len(answer) else "empty_answer", "")
    except NXDOMAIN:
        return "nxdomain", ""
    except NoAnswer:
        return "nodata", ""
    except Timeout:
        return "timeout", ""
    except NoNameservers as exc:
        # dnspython retains per-server failures here; preserve response codes
        # and exception classes so SERVFAIL/REFUSED can be distinguished.
        details = getattr(exc, "errors", None)
        return "no_nameservers", repr(details if details else exc)[:1000]
    except Exception as exc:  # Keep the exception class for diagnosis, not policy.
        return "other_error", type(exc).__name__


def inspect_one(domain: str, port: int) -> tuple[str, int, str, str, str, str]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = port
    resolver.timeout = 2.0
    resolver.lifetime = 4.0
    a_status, a_error = query_status(resolver, domain, "A")
    aaaa_status, aaaa_error = query_status(resolver, domain, "AAAA")
    return domain, port, a_status, a_error, aaaa_status, aaaa_error


def load_sample(db_path: Path, sample_size: int) -> list[str]:
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT domain
            FROM T_DOMAIN
            WHERE (ipList IS NULL OR ipList = '')
              AND isBlock = 0
            ORDER BY RANDOM()
            LIMIT ?
            """,
            (sample_size,),
        ).fetchall()
    return [row[0] for row in rows]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, default=Path("domain.db"))
    parser.add_argument("--sample-size", type=int, default=SAMPLE_SIZE)
    args = parser.parse_args()

    if not args.database.is_file() or args.database.stat().st_size == 0:
        raise SystemExit(f"Missing or empty database: {args.database}")
    if args.sample_size < 1:
        raise SystemExit("--sample-size must be positive")

    domains = load_sample(args.database, args.sample_size)
    if not domains:
        raise SystemExit("No non-blocked empty-answer domains found in the checkpoint database")

    print(f"Read-only DNS upstream diagnostic; sample={len(domains)}")
    print("Ports: 5053=DNSPod, 5054=Baidu, 5055=China Unicom, 5056=Google, 5057=Quad9 unfiltered, 5058=Cloudflare")
    print("No result from this diagnostic is used to block or unblock a domain.")

    jobs = ((domain, port) for domain in domains for port in PORTS)
    per_port: dict[int, Counter[str]] = {port: Counter() for port in PORTS}
    per_query: dict[int, dict[str, Counter[str]]] = {
        port: {"A": Counter(), "AAAA": Counter()} for port in PORTS
    }
    errors: dict[int, Counter[str]] = {port: Counter() for port in PORTS}
    error_samples: dict[int, list[str]] = {port: [] for port in PORTS}
    per_domain_status: dict[str, list[tuple[int, str, str]]] = {domain: [] for domain in domains}
    with ThreadPoolExecutor(max_workers=60) as pool:
        futures = [pool.submit(inspect_one, domain, port) for domain, port in jobs]
        for future in as_completed(futures):
            domain, port, a_status, a_error, aaaa_status, aaaa_error = future.result()
            per_query[port]["A"][a_status] += 1
            per_query[port]["AAAA"][aaaa_status] += 1
            per_domain_status[domain].append((port, a_status, aaaa_status))
            for rdtype, status, detail in (("A", a_status, a_error), ("AAAA", aaaa_status, aaaa_error)):
                if detail:
                    errors[port][f"{rdtype}:{detail[:180]}"] += 1
                if status == "no_nameservers" and len(error_samples[port]) < 8:
                    error_samples[port].append(f"{domain} {rdtype}: {detail[:500]}")
            if "answer" in (a_status, aaaa_status):
                pair = "has_address"
            elif a_status == aaaa_status == "nxdomain":
                pair = "both_nxdomain"
            elif a_status == aaaa_status == "nodata":
                pair = "both_nodata"
            else:
                pair = "inconclusive_or_mixed"
            per_port[port][pair] += 1

    no_nameserver_fanout: Counter[int] = Counter()
    cross_provider: Counter[str] = Counter()
    for domain, results in per_domain_status.items():
        no_nameserver_fanout[sum(a == "no_nameservers" or aaaa == "no_nameservers" for _, a, aaaa in results)] += 1
        statuses = [status for _, a, aaaa in results for status in (a, aaaa)]
        if "answer" in statuses:
            cross_provider["has_address_from_any_provider"] += 1
        elif all(status == "nxdomain" for status in statuses):
            cross_provider["all_12_queries_nxdomain"] += 1
        elif all(status == "nodata" for status in statuses):
            cross_provider["all_12_queries_nodata"] += 1
        else:
            cross_provider["mixed_or_inconclusive"] += 1

    print(f"\nCross-provider summary: {dict(sorted(cross_provider.items()))}")
    print(f"Domains with NoNameservers from N providers: {dict(sorted(no_nameserver_fanout.items()))}")

    for port in PORTS:
        print(f"\nPORT {port}")
        print(f"  A:    {dict(sorted(per_query[port]['A'].items()))}")
        print(f"  AAAA: {dict(sorted(per_query[port]['AAAA'].items()))}")
        print(f"  pair: {dict(sorted(per_port[port].items()))}")
        if errors[port]:
            print(f"  error_details_top5: {errors[port].most_common(5)}")
        if error_samples[port]:
            print(f"  no_nameserver_examples: {error_samples[port]}")

    # Probe alternative domestic resolvers directly. These results are diagnostic
    # only and do not replace any production upstream without a reviewed change.
    candidates = {
        "ByteDance 180.184.1.1": "180.184.1.1",
        "114DNS 114.114.114.114 (filtering; comparison only)": "114.114.114.114",
        "114DNS 114.114.114.114": "114.114.114.114",
        "AliDNS 223.6.6.6": "223.6.6.6",
        "China Unicom alternate 123.123.123.123": "123.123.123.123",
        "Gansu Telecom 202.100.64.68": "202.100.64.68",
        "Gansu Telecom 61.178.0.93": "61.178.0.93",
        "China Unicom 123.125.81.6": "123.125.81.6",
        "Huawei DNS 122.112.208.1": "122.112.208.1",
        "Huawei DNS 139.9.23.90": "139.9.23.90",
        "Yamu DNS 1.1.8.8": "1.1.8.8",
    }
    probe_domains = ("baidu.com", "qq.com", "example.com", "cloudflare.com", "google.com")
    print("\\nCandidate resolver positive probes:")
    for label, address in candidates.items():
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [address]
        resolver.port = 53
        resolver.timeout = 2.0
        resolver.lifetime = 5.0
        probe_results = {}
        for domain in probe_domains:
            status, detail = query_status(resolver, domain, "A")
            probe_results[domain] = status if not detail else f"{status}:{detail[:120]}"
        print(f"  {label} ({address}): {probe_results}")

    candidate_domains = domains[:200]
    for label, address in candidates.items():
        counts: dict[str, Counter[str]] = {"A": Counter(), "AAAA": Counter()}
        def inspect_candidate(domain: str) -> tuple[str, str, str, str]:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [address]
            resolver.port = 53
            resolver.timeout = 2.0
            resolver.lifetime = 5.0
            a_status, a_error = query_status(resolver, domain, "A")
            aaaa_status, aaaa_error = query_status(resolver, domain, "AAAA")
            return a_status, a_error, aaaa_status, aaaa_error

        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = [pool.submit(inspect_candidate, domain) for domain in candidate_domains]
            for future in as_completed(futures):
                a_status, a_error, aaaa_status, aaaa_error = future.result()
                counts["A"][a_status] += 1
                counts["AAAA"][aaaa_status] += 1
        print(f"\\nCandidate {label} ({address}) sample={len(candidate_domains)}")
        print(f"  A:    {dict(sorted(counts['A'].items()))}")
        print(f"  AAAA: {dict(sorted(counts['AAAA'].items()))}")

    print("\nDiagnostic complete. This is evidence gathering only; no DNS state was modified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
