#!/usr/bin/env python3
"""Read-only comparison of candidate domestic recursive DNS resolvers."""
from __future__ import annotations

import argparse
import sqlite3
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import dns.resolver
from dns.exception import Timeout
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers

CANDIDATES = {
    "Gansu Telecom 202.100.64.68": "202.100.64.68",
    "Gansu Telecom 61.178.0.93": "61.178.0.93",
    "China Unicom 123.125.81.6": "123.125.81.6",
    "Huawei DNS 122.112.208.1": "122.112.208.1",
    "Huawei DNS 139.9.23.90": "139.9.23.90",
}
POSITIVE_PROBES = ("baidu.com", "qq.com", "example.com", "cloudflare.com", "google.com")


def query_status(address: str, domain: str, rdtype: str) -> tuple[str, str]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [address]
    resolver.port = 53
    resolver.timeout = 1.5
    resolver.lifetime = 3.0
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
        return "no_nameservers", repr(getattr(exc, "errors", None) or exc)[:400]
    except Exception as exc:
        return "other_error", type(exc).__name__


def sample_domains(database: Path, limit: int) -> list[str]:
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            """
            SELECT domain
            FROM T_DOMAIN
            WHERE (ipList IS NULL OR ipList = '')
              AND isBlock = 0
            ORDER BY RANDOM()
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [row[0] for row in rows]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, default=Path("domain.db"))
    parser.add_argument("--sample-size", type=int, default=100)
    args = parser.parse_args()
    if not args.database.is_file() or args.database.stat().st_size == 0:
        raise SystemExit(f"Missing or empty checkpoint database: {args.database}")

    domains = sample_domains(args.database, args.sample_size)
    if not domains:
        raise SystemExit("No non-blocked unresolved domains available for sampling")

    print(f"Read-only domestic resolver comparison; sample={len(domains)}")
    print("Only candidate response statistics are reported; no DNS state is modified.")

    for label, address in CANDIDATES.items():
        print(f"\n{label} ({address})")
        probes = {domain: query_status(address, domain, "A")[0] for domain in POSITIVE_PROBES}
        print(f"  positive_probes_A: {probes}")

        counts: dict[str, Counter[str]] = {"A": Counter(), "AAAA": Counter()}
        errors: Counter[str] = Counter()

        def inspect(domain: str) -> tuple[str, str, str, str]:
            a_status, a_error = query_status(address, domain, "A")
            aaaa_status, aaaa_error = query_status(address, domain, "AAAA")
            return a_status, a_error, aaaa_status, aaaa_error

        with ThreadPoolExecutor(max_workers=40) as pool:
            futures = [pool.submit(inspect, domain) for domain in domains]
            for future in as_completed(futures):
                a_status, a_error, aaaa_status, aaaa_error = future.result()
                counts["A"][a_status] += 1
                counts["AAAA"][aaaa_status] += 1
                if a_error:
                    errors[f"A:{a_error[:180]}"] += 1
                if aaaa_error:
                    errors[f"AAAA:{aaaa_error[:180]}"] += 1

        print(f"  A:    {dict(sorted(counts['A'].items()))}")
        print(f"  AAAA: {dict(sorted(counts['AAAA'].items()))}")
        if errors:
            print(f"  error_details_top5: {errors.most_common(5)}")

    print("\nComparison complete. No resolver was added to production.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
