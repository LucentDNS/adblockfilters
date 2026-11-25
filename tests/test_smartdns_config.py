from pathlib import Path

def test_dns_validation_uses_separate_non_filtering_regional_groups():
    config = Path(__file__).parents[1].joinpath("smartdns.conf").read_text(encoding="utf-8")

    assert "bind 127.0.0.1:5053 -group domestic" in config
    assert "bind 127.0.0.1:5054 -group global" in config

    domestic = [
        line for line in config.splitlines()
        if line.startswith(("server ", "server-tls ", "server-https ")) and "-group domestic" in line
    ]
    global_servers = [
        line for line in config.splitlines()
        if line.startswith(("server ", "server-tls ", "server-https ")) and "-group global" in line
    ]
    assert len(domestic) >= 3
    assert len(global_servers) >= 3

    for provider in (
        "https://doh.pub/dns-query",
        "180.76.76.76",
        "180.184.1.1",
        "8.8.8.8",
        "9.9.9.10",
        "1.1.1.1",
    ):
        assert provider in config

    assert "-tls-host-verify doh.pub" in config
    assert config.count("-exclude-default-group") == 6
    assert "9.9.9.11" not in config  # Quad9 threat-blocking resolver
    assert "101.226.4.6" not in config  # 360 security-filtering DNS
    assert "114.114.114.114" not in config  # 114DNS standard resolver has ad filtering

def test_dns_validation_constructs_both_smartdns_resolvers(monkeypatch):
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

    assert [resolver.port for resolver in ports] == [5053, 5054]
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

def test_upstream_baseline_is_validated_before_comparison():
    workflow = (
        Path(__file__).parents[1] / ".github" / "workflows" / "update.yml"
    ).read_text(encoding="utf-8")

    assert 'baseline_title != "! Title: AdBlock DNS"' in workflow
    assert "baseline_version" in workflow
    assert "len(baseline_rules) < 100000" in workflow
    assert "invalid_rules" in workflow
    assert '"baseline_version": baseline_version' in workflow

def test_smartdns_startup_waits_for_listeners_not_upstream_dns_answers():
    workflow = (
        Path(__file__).parents[1] / ".github" / "workflows" / "blacklist.yml"
    ).read_text(encoding="utf-8")

    assert 'SMARTDNS_LOG="$SMARTDNS_PATH/smartdns.log"' in workflow
    launch_command = (
        'nohup "$SMARTDNS_BIN" -f -x -c "$SMARTDNS_PATH/smartdns.conf" '
        '> "$SMARTDNS_LOG" 2>&1 &'
    )
    assert launch_command in workflow
    assert 'kill -0 "$SMARTDNS_PID"' in workflow
    assert "127\\.0\\.0\\.1:5053" in workflow
    assert "127\\.0\\.0\\.1:5054" in workflow
    assert "sock.recvfrom(1024)" not in workflow
    assert 'cat "$SMARTDNS_LOG"' in workflow
