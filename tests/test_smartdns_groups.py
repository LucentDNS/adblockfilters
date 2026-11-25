from pathlib import Path

from blacklist import BlackList


def test_smartdns_config_exposes_two_independent_resolver_groups():
    config = Path("smartdns.conf").read_text(encoding="utf-8")

    assert "bind 127.0.0.1:5053 -group domestic" in config
    assert "bind 127.0.0.1:5054 -group global" in config

    domestic = [
        line for line in config.splitlines()
        if line.startswith("server-tls ") and "-group domestic" in line
    ]
    global_servers = [
        line for line in config.splitlines()
        if line.startswith("server-tls ") and "-group global" in line
    ]
    assert len(domestic) >= 6
    assert len(global_servers) >= 6


def test_dns_validation_constructs_both_smartdns_resolvers(monkeypatch):
    instance = BlackList.__new__(BlackList)
    instance._BlackList__maxTask = 1
    ports = []

    class FakeDNSResolver:
        def __init__(self):
            self.nameservers = None
            self.port = None
            self.timeout = None
            self.lifetime = None
            ports.append(self)

    monkeypatch.setattr("blacklist.DNSResolver", FakeDNSResolver)

    instance._BlackList__testDomain({}, ["127.0.0.1"], 5053)

    assert [resolver.port for resolver in ports] == [5053, 5054]
    assert all(resolver.nameservers == ["127.0.0.1"] for resolver in ports)
