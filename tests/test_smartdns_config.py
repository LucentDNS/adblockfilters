from pathlib import Path


def test_dns_validation_uses_six_isolated_non_filtering_upstreams():
    from blacklist import DNS_VALIDATION_PORTS

    config = Path(__file__).parents[1].joinpath("smartdns.conf").read_text(encoding="utf-8")
    groups = (
        "domestic_dnspod", "domestic_baidu", "domestic_alidns",
        "global_google", "global_quad9", "global_cloudflare",
    )
    server_prefixes = ("server ", "server-tls ", "server-https ")
    for port, group in zip(DNS_VALIDATION_PORTS, groups, strict=True):
        assert f"bind 127.0.0.1:{port} -group {group}" in config
        servers = [
            line for line in config.splitlines()
            if line.startswith(server_prefixes) and f"-group {group} " in line
        ]
        assert len(servers) == 1, f"{group} must map to exactly one upstream"
        assert "-exclude-default-group" in servers[0]

    for provider in (
        "119.29.29.29", "180.76.76.76", "223.5.5.5",
        "8.8.8.8", "9.9.9.10", "1.1.1.1",
    ):
        assert provider in config

    assert config.count("-exclude-default-group") == 6
    assert "force-AAAA-SOA" not in config
    assert "-force-aaaa-soa" not in config
    assert "9.9.9.11" not in config
    assert "101.226.4.6" not in config
    assert "114.114.114.114" not in config
    assert "180.184.1.1" not in config

def test_dns_validation_constructs_six_smartdns_resolvers(monkeypatch):
    from blacklist import BlackList

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

    from blacklist import DNS_VALIDATION_PORTS

    assert [resolver.port for resolver in ports] == list(DNS_VALIDATION_PORTS)
    assert all(resolver.nameservers == ["127.0.0.1"] for resolver in ports)


def test_dns_validation_workflow_pins_and_verifies_smartdns_binary():
    workflow = (
        Path(__file__).parents[1] / ".github" / "workflows" / "blacklist.yml"
    ).read_text(encoding="utf-8")

    assert "Release48.4" in workflow
    expected_sha256 = (
        "4cc1b8f9db10110e1212d981cfee7eb89a3c80f5766760e3b5f7541c8da8b546"
    )
    assert f"SMARTDNS_SHA256: {expected_sha256}" in workflow
    assert "x86_64-debian-all.deb" in workflow
    assert "sha256sum --check -" in workflow
    assert "dpkg-deb --extract" in workflow
    assert "wget --https-only --timeout=30 --tries=3 --waitretry=2" in workflow


def test_ci_workflows_install_dev_tools_and_run_static_analysis():
    root = Path(__file__).parents[1]
    for name in ("audit-sources.yml", "update.yml", "blacklist.yml"):
        workflow = (
            root / ".github" / "workflows" / name
        ).read_text(encoding="utf-8")
        assert "python -m pip install -r requirements-dev.txt" in workflow
        assert "python -m ruff check --no-cache ." in workflow
        assert "python -m ruff check --no-cache --select F401 scripts tests" in workflow


def test_full_and_lite_upstream_baselines_are_validated_before_comparison():
    root = Path(__file__).parents[1]
    workflow = (root / ".github" / "workflows" / "update.yml").read_text(
        encoding="utf-8"
    )
    script = (root / "scripts" / "compare_baseline.py").read_text(
        encoding="utf-8"
    )

    assert "adblockdns.txt" in workflow
    assert "adblockdnslite.txt" in workflow
    assert "python scripts/compare_baseline.py" in workflow
    assert '"! Title: AdBlock DNS"' in script
    assert '"! Title: AdBlock DNS Lite"' in script
    assert "lite-baseline-only-domains.txt" in script
    assert "baseline_allow_rules" in script


def test_dns_validation_state_is_sealed_before_publication():
    root = Path(__file__).parents[1]
    workflow = (root / ".github" / "workflows" / "blacklist.yml").read_text(
        encoding="utf-8"
    )
    generator = (root / "scripts" / "generate_domain_input.py").read_text(
        encoding="utf-8"
    )
    state_script = (root / "scripts" / "validated_sources.py").read_text(
        encoding="utf-8"
    )

    assert '"validation_logic_sha256": validation_logic_sha256()' in generator
    assert "def validation_logic_sha256()" in state_script
    assert "def seal()" in state_script
    assert "def check_current()" in state_script
    assert "python scripts/validated_sources.py seal" in workflow


def test_smartdns_startup_waits_for_listeners_not_upstream_dns_answers():
    workflow = (
        Path(__file__).parents[1] / ".github" / "workflows" / "blacklist.yml"
    ).read_text(encoding="utf-8")

    assert 'SMARTDNS_LOG="$SMARTDNS_PATH/smartdns.log"' in workflow
    assert 'SMARTDNS_ROOT="$(dirname "$SMARTDNS_BIN")"' in workflow
    assert 'cd "$SMARTDNS_ROOT"' in workflow
    launch_command = (
        'nohup ./smartdns -f -x -c "$SMARTDNS_PATH/smartdns.conf" '
        '> "$SMARTDNS_LOG" 2>&1 &'
    )
    assert launch_command in workflow
    assert 'kill -0 "$SMARTDNS_PID"' in workflow
    assert all(str(port) in workflow for port in (5053, 5054, 5055, 5056, 5057, 5058))
    assert "sock.recvfrom(1024)" not in workflow
    assert 'cat "$SMARTDNS_LOG"' in workflow



def test_maintained_python_code_receives_full_ruff_lint():
    workflow = (
        Path(__file__).parents[1] / ".github" / "workflows" / "audit-sources.yml"
    ).read_text(encoding="utf-8")

    assert (
        "python -m ruff check --no-cache --select E4,E7,E9,F scripts tests"
        in workflow
    )

def test_dns_validation_health_check_verifies_a_and_aaaa_nxdomain():
    workflow = (
        Path(__file__).parents[1] / ".github" / "workflows" / "blacklist.yml"
    ).read_text(encoding="utf-8")

    assert 'for rdtype in ("A", "AAAA"):' in workflow
    assert 'resolver.resolve(probe, rdtype)' in workflow
