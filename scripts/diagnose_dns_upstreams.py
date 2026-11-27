#!/usr/bin/env python3
"""Read-only diagnosis of per-upstream DNS response disagreements.

This tool never changes the DNS-validation database or production rule outputs.
"""
from __future__ import annotations

import argparse
import random
import sqlite3
from collections import Counter, defaultdict
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
    except NoNameservers:
        return "no_nameservers", ""
    except Exception as exc:  # Keep the exception class for diagnosis, not policy.
        return "other_error", type(exc).__name__


def inspect_one(domain: str, port: int) -> tuple[str, int, str, str, str]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = port
    resolver.timeout = 2.0
    resolver.lifetime = 4.0
    a_status, a_error = query_status(resolver, domain, "A")
    aaaa_status, aaaa_error = query_status(resolver, domain, "AAAA")
    return domain, port, a_status, aaaa_status, ";".join(x for x in (a_error, aaaa_error) if x)


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
    print("Ports: 5053=DNSPod, 5054=Baidu, 5055=AliDNS, 5056=Google, 5057=Quad9, 5058=Cloudflare")
    print("No result from this diagnostic is used to block or unblock a domain.")

    jobs = ((domain, port) for domain in domains for port in PORTS)
    per_port: dict[int, Counter[str]] = {port: Counter() for port in PORTS}
    per_query: dict[int, dict[str, Counter[str]]] = {
        port: {"A": Counter(), "AAAA": Counter()} for port in PORTS
    }
    errors: dict[int, Counter[str]] = {port: Counter() for port in PORTS}
    with ThreadPoolExecutor(max_workers=60) as pool:
        futures = [pool.submit(inspect_one, domain, port) for domain, port in jobs]
        for future in as_completed(futures):
            domain, port, a_status, aaaa_status, error = future.result()
            per_query[port]["A"][a_status] += 1
            per_query[port]["AAAA"][aaaa_status] += 1
            if error:
                errors[port][error] += 1
            if "answer" in (a_status, aaaa_status):
                pair = "has_address"
            elif a_status == aaaa_status == "nxdomain":
                pair = "both_nxdomain"
            elif a_status == aaaa_status == "nodata":
                pair = "both_nodata"
            else:
                pair = "inconclusive_or_mixed"
            per_port[port][pair] += 1

    for port in PORTS:
        print(f"\nPORT {port}")
        print(f"  A:    {dict(sorted(per_query[port]['A'].items()))}")
        print(f"  AAAA: {dict(sorted(per_query[port]['AAAA'].items()))}")
        print(f"  pair: {dict(sorted(per_port[port].items()))}")
        if errors[port]:
            print(f"  exception_types: {dict(sorted(errors[port].items()))}")

    print("\nDiagnostic complete. This is evidence gathering only; no DNS state was modified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
