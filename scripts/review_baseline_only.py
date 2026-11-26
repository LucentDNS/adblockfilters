"""Report-only DNS review of legacy baseline deltas; never mutates production rules."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
DEFAULT_UPSTREAM_PORTS = (5053, 5054, 5055, 5056, 5057)


def valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253 or "/" in domain or "*" in domain:
        return False
    labels = domain.split(".")
    return len(labels) >= 2 and all(
        1 <= len(label) <= 63 and DOMAIN_LABEL.fullmatch(label) for label in labels
    )


def read_candidates(path: Path) -> tuple[list[str], list[str], int]:
    domains: set[str] = set()
    invalid: list[str] = []
    candidate_count = 0

    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.partition("#")[0].strip()
        if not line or line.startswith("!"):
            continue
        candidate_count += 1
        domain = line.lower()
        if domain.endswith("."):
            domain = domain[:-1]
        if valid_domain(domain):
            domains.add(domain)
        else:
            invalid.append(line)

    return sorted(domains), invalid, candidate_count


def classify_rrtype_results(statuses: list[str]) -> str:
    if "resolved" in statuses:
        return "resolved"
    if len(statuses) == 2 and all(status == "not_found" for status in statuses):
        return "not_found"
    if len(statuses) == 2 and all(status == "no_address" for status in statuses):
        return "no_address"
    return "unknown"


def classify_groups(statuses: list[str]) -> str:
    if "resolved" in statuses:
        return "resolved"
    if len(statuses) == len(DEFAULT_UPSTREAM_PORTS) and all(
        status == "not_found" for status in statuses
    ):
        return "nxdomain"
    if len(statuses) == len(DEFAULT_UPSTREAM_PORTS) and all(
        status == "no_address" for status in statuses
    ):
        return "no_address"
    return "inconclusive"


async def resolve_group(
    domain: str,
    port: int,
    timeout: float,
    lifetime: float,
) -> dict[str, Any]:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = port
    resolver.timeout = timeout
    resolver.lifetime = lifetime

    query_statuses: list[str] = []
    addresses: set[str] = set()

    for rdtype in ("A", "AAAA"):
        try:
            answer = await resolver.resolve(
                domain,
                rdtype,
                search=False,
                raise_on_no_answer=False,
            )
            found_address = False
            if answer.rrset is not None:
                for record in answer:
                    address = getattr(record, "address", None)
                    if address:
                        addresses.add(address)
                        found_address = True
            query_statuses.append("resolved" if found_address else "no_address")
        except dns.resolver.NXDOMAIN:
            query_statuses.append("not_found")
        except dns.resolver.NoAnswer:
            query_statuses.append("no_address")
        except dns.exception.DNSException:
            query_statuses.append("unknown")

    if addresses:
        return {"status": "resolved", "addresses": sorted(addresses)}
    status = classify_rrtype_results(query_statuses)
    return {"status": status, "addresses": []}


async def review_candidates(
    domains: list[str],
    ports: tuple[int, ...],
    timeout: float,
    lifetime: float,
    concurrency: int,
) -> list[dict[str, Any]]:
    semaphore = asyncio.Semaphore(concurrency)

    async def review_one(domain: str) -> dict[str, Any]:
        async with semaphore:
            upstreams = await asyncio.gather(
                *(resolve_group(domain, port, timeout, lifetime) for port in ports)
            )
        status = classify_groups([result["status"] for result in upstreams])
        return {
            "domain": domain,
            "status": status,
            "upstreams": [
                {"port": port, **result} for port, result in zip(ports, upstreams, strict=True)
            ],
        }

    return await asyncio.gather(*(review_one(domain) for domain in domains))


def write_reports(
    results: list[dict[str, Any]],
    invalid: list[str],
    output_dir: Path,
    candidate_count: int,
) -> dict[str, int]:
    output_dir.mkdir(parents=True, exist_ok=True)
    counts = Counter(result["status"] for result in results)
    summary = {
        "candidate_count": candidate_count,
        "valid_unique_domains": len(results),
        "invalid_lines": len(invalid),
        "resolved": counts["resolved"],
        "nxdomain_all_five_upstreams": counts["nxdomain"],
        "no_address_both_groups": counts["no_address"],
        "inconclusive": counts["inconclusive"],
    }

    payload = {"summary": summary, "results": results, "invalid_lines": invalid}
    (output_dir / "results.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    report_files = (
        ("resolved", "resolved.txt"),
        ("nxdomain", "nxdomain-all-five-upstreams.txt"),
        ("no_address", "no-address-both-groups.txt"),
        ("inconclusive", "inconclusive.txt"),
    )
    for status, filename in report_files:
        lines = sorted(
            result["domain"] for result in results if result["status"] == status
        )
        (output_dir / filename).write_text(
            "\n".join(lines) + ("\n" if lines else ""),
            encoding="utf-8",
            newline="\n",
        )

    (output_dir / "invalid-lines.txt").write_text(
        "\n".join(invalid) + ("\n" if invalid else ""),
        encoding="utf-8",
        newline="\n",
    )
    summary_lines = [
        "# Legacy upstream-only DNS candidate review",
        "",
        "Report only: this review does not add or remove production rules.",
        "NXDOMAIN requires all five independent upstreams to return NXDOMAIN for both A and AAAA.",
        "",
        *[f"- {key}: {value}" for key, value in summary.items()],
        "",
    ]
    (output_dir / "summary.md").write_text(
        "\n".join(summary_lines),
        encoding="utf-8",
        newline="\n",
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Report-only DNS review of upstream-only domains omitted from current sources."
        )
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--ports", type=int, nargs=5, default=DEFAULT_UPSTREAM_PORTS,
        help="five local SmartDNS ports, one per independent upstream",
    )
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--lifetime", type=float, default=5.0)
    parser.add_argument("--concurrency", type=int, default=100)
    args = parser.parse_args()

    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1")
    if args.timeout <= 0 or args.lifetime <= 0:
        parser.error("--timeout and --lifetime must be positive")
    if len(set(args.ports)) != len(DEFAULT_UPSTREAM_PORTS) or any(
        port < 1 or port > 65535 for port in args.ports
    ):
        parser.error("--ports must contain five distinct valid TCP/UDP ports")

    domains, invalid, candidate_count = read_candidates(args.input)
    results = asyncio.run(
        review_candidates(
            domains,
            tuple(args.ports),
            args.timeout,
            args.lifetime,
            args.concurrency,
        )
    )
    summary = write_reports(results, invalid, args.output_dir, candidate_count)
    print("Legacy baseline-only DNS review (report only)")
    for key, value in summary.items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
