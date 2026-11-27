#!/usr/bin/env python3
"""Read-only SmartDNS forwarding diagnosis for CNNIC SDNS."""
from __future__ import annotations

import dns.resolver
from dns.exception import Timeout
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers

DOMAINS = (
    "baidu.com",
    "qq.com",
    "example.com",
    "cloudflare.com",
    "google.com",
    "adblock-dns-probe-20261125.example.invalid",
)
RESOLVERS = (
    ("CNNIC direct", "1.2.4.8", 53),
    ("SmartDNS current", "127.0.0.1", 5055),
    ("SmartDNS bootstrap", "127.0.0.1", 5059),
    ("SmartDNS ECS", "127.0.0.1", 5060),
    ("SmartDNS bootstrap+ECS", "127.0.0.1", 5061),
)


def query(address: str, port: int, domain: str, rdtype: str) -> str:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [address]
    resolver.port = port
    resolver.timeout = 1.5
    resolver.lifetime = 3.0
    try:
        answer = resolver.resolve(domain, rdtype)
        values = ",".join(str(item) for item in list(answer)[:3])
        return f"ANSWER({values})"
    except NXDOMAIN:
        return "NXDOMAIN"
    except NoAnswer:
        return "NODATA"
    except NoNameservers as exc:
        return f"NO_NAMESERVERS({str(exc)[:180]})"
    except Timeout:
        return "TIMEOUT"
    except Exception as exc:
        return f"ERROR({type(exc).__name__}:{str(exc)[:120]})"


def main() -> int:
    print("Read-only SmartDNS/CNNIC forwarding diagnostic")
    print("No DNS state, checkpoint, whitelist, or production output is modified.")
    for label, address, port in RESOLVERS:
        print(f"\n{label}: {address}:{port}")
        for domain in DOMAINS:
            a = query(address, port, domain, "A")
            aaaa = query(address, port, domain, "AAAA")
            print(f"  {domain}: A={a}; AAAA={aaaa}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
