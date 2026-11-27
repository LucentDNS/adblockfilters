import json
from pathlib import Path

from app.adguard import AdGuard
from app.adguardhome import AdGuardHome
from app.dnsmasq import DNSMasq
from app.smartdns import SmartDNS
from app.mosdns import MosDNS
from app.invizible import InviZible
from app.singbox import SingBox
from app.v2ray import V2ray
from app.hosts import Hosts


def generate_lite(generator_cls, tmp_path, filename):
    generator = generator_cls(
        ["parent.example.com"],
        [],
        {},
        [],
        [],
        {"cn.example.com"},
        str(tmp_path / filename),
        "test",
    )
    generator.blockListLite = ["cn.example.com"]
    generator.generate(isLite=True)
    return Path(generator.fileNameLite).read_text(encoding="utf-8")


def test_adguard_home_lite_uses_upstream_compatible_domain_suffix_rule(tmp_path):
    output = generate_lite(AdGuardHome, tmp_path, "adblockdns.txt")
    assert "||cn.example.com^" in output
    assert "\ncn.example.com\n" not in output



def test_adguard_home_lite_keeps_upstream_block_and_allow_syntax(tmp_path):
    generator = AdGuardHome(
        ["blocked.example.com"],
        ["safe.example.com"],
        {},
        [],
        [],
        {"blocked.example.com"},
        str(tmp_path / "adblockdns.txt"),
        "test",
    )
    generator.blockListLite = ["blocked.example.com"]
    generator.generate(isLite=True)
    output = Path(generator.fileNameLite).read_text(encoding="utf-8")

    assert "! Title: AdBlock DNS Lite" in output
    assert "||blocked.example.com^" in output
    assert "@@||safe.example.com^" in output
    assert "\\nblocked.example.com\\n" not in output

def test_adguard_home_emits_scoped_dns_wildcards_in_full_and_lite(tmp_path):
    block_pattern = "||ads*-normal-hl.zijieapi.com^"
    second_block_pattern = "||ping.*.sogou.com^"
    allow_pattern = "@@||profile*.se.360.cn^"
    generator = AdGuardHome(
        ["blocked.example.com"],
        ["safe.example.com", "ads123.example.com"],
        {},
        [],
        [],
        {"blocked.example.com"},
        str(tmp_path / "adblockdns.txt"),
        "test",
        dnsPatternBlockList=[block_pattern, second_block_pattern],
        dnsPatternAllowList=[allow_pattern],
        dnsPatternBlockListLite=[block_pattern],
        dnsPatternAllowListLite=[allow_pattern],
        wildcardWhiteExceptionsLite=["ads123.example.com"],
    )

    generator.generate()
    full = Path(generator.fileName).read_text(encoding="utf-8")
    assert block_pattern in full
    assert second_block_pattern in full
    assert allow_pattern in full
    assert "@@||ads123.example.com^" in full
    assert "! Wildcard block rules: 2" in full
    assert "! Wildcard allow rules: 1" in full

    generator.generate(isLite=True)
    lite = Path(generator.fileNameLite).read_text(encoding="utf-8")
    assert block_pattern in lite
    assert allow_pattern in lite
    assert "@@||ads123.example.com^" in lite
    assert second_block_pattern not in lite
    assert "! Wildcard block rules: 1" in lite
    assert "! Wildcard allow rules: 1" in lite


def test_dnsmasq_lite_uses_exact_host_record(tmp_path):
    output = generate_lite(DNSMasq, tmp_path, "adblockdnsmasq.conf")
    assert "host-record=cn.example.com,0.0.0.0,::" in output
    assert "local=/cn.example.com/" not in output


def test_smartdns_lite_uses_exact_main_domain_rule(tmp_path):
    output = generate_lite(SmartDNS, tmp_path, "adblocksmartdns.conf")
    assert "address /-.cn.example.com/#" in output
    assert "address /cn.example.com/#" not in output


def test_mosdns_lite_uses_full_exact_domain_rule(tmp_path):
    output = generate_lite(MosDNS, tmp_path, "adblockmosdns.txt")
    assert "full:cn.example.com" in output
    assert "\ncn.example.com\n" not in output


def test_invizible_lite_uses_dnscrypt_exact_domain_prefix(tmp_path):
    output = generate_lite(InviZible, tmp_path, "adblockdomain.txt")
    assert "\n=cn.example.com\n" in output
    assert "\ncn.example.com\n" not in output


def test_hosts_lite_uses_exact_host_mapping(tmp_path):
    output = generate_lite(Hosts, tmp_path, "adblockhosts.txt")
    assert "0.0.0.0\tcn.example.com" in output


def test_singbox_lite_uses_exact_domain_key(tmp_path):
    output = generate_lite(SingBox, tmp_path, "adblocksingbox.json")
    rules = json.loads(output)["rules"]
    assert rules[0]["domain"] == ["cn.example.com"]
    assert "domain_suffix" not in rules[0]


def test_v2ray_lite_uses_full_exact_domain_rule(tmp_path):
    output = generate_lite(V2ray, tmp_path, "adblockv2ray.txt")
    assert "full:cn.example.com @ads" in output
    assert "\ncn.example.com @ads\n" not in output


def test_loon_lite_uses_exact_domain_rule(tmp_path):
    from app.loon import Loon
    output = generate_lite(Loon, tmp_path, "adblockloon.list")
    assert "DOMAIN,cn.example.com,REJECT" in output
    assert "DOMAIN-SUFFIX,cn.example.com" not in output


def test_mihomo_lite_uses_exact_domain_payload(tmp_path):
    from app.mihomo import Mihomo
    output = generate_lite(Mihomo, tmp_path, "adblockmihomo.yaml")
    assert "  - 'cn.example.com'" in output
    assert "  - '+.cn.example.com'" not in output


def test_quantumultx_lite_uses_exact_host_rule(tmp_path):
    from app.quantumultx import QuantumultX
    output = generate_lite(QuantumultX, tmp_path, "adblockqx.conf")
    assert "host,cn.example.com,reject" in output
    assert "host-suffix,cn.example.com,reject" not in output


def test_shadowrocket_lite_uses_exact_domain_rule(tmp_path):
    from app.shadowrocket import Shadowrocket
    output = generate_lite(Shadowrocket, tmp_path, "adblockclash.list")
    assert "DOMAIN,cn.example.com,REJECT-DROP" in output
    assert "DOMAIN-SUFFIX,cn.example.com,REJECT-DROP" not in output


def test_shadowrocket_module_lite_uses_exact_domain_rule(tmp_path):
    from app.shadowrocket_module import ShadowrocketModule
    output = generate_lite(ShadowrocketModule, tmp_path, "adblockshadowrocket.sgmodule")
    assert "DOMAIN,cn.example.com,REJECT-DROP" in output
    assert "DOMAIN-SUFFIX,cn.example.com,REJECT-DROP" not in output


def test_surge_lite_uses_exact_domain_set_entry(tmp_path):
    from app.surge import Surge
    output = generate_lite(Surge, tmp_path, "adblocksurge.list")
    assert "\ncn.example.com\n" in output
    assert "\n.cn.example.com\n" not in output



def test_dnsmasq_full_uses_specific_server_allow_override(tmp_path):
    generator = DNSMasq(
        ["parent.example.com"],
        ["safe.parent.example.com"],
        {},
        [],
        [],
        set(),
        str(tmp_path / "adblockdnsmasq.txt"),
        "test",
    )
    generator.generate(isLite=False)
    output = Path(generator.fileName).read_text(encoding="utf-8")
    assert "local=/parent.example.com/" in output
    assert "server=/safe.parent.example.com/#" in output


def test_invizible_full_emits_a_separate_dnscrypt_allowlist(tmp_path):
    generator = InviZible(
        ["parent.example.com"],
        ["safe.parent.example.com", "project-safe.example.net"],
        {},
        [],
        [],
        set(),
        str(tmp_path / "adblockdomain.txt"),
        "test",
    )
    generator.generate(isLite=False)
    allow_path = tmp_path / "adblockdomainallow.txt"
    output = allow_path.read_text(encoding="utf-8")
    assert "safe.parent.example.com" in output
    assert "project-safe.example.net" in output



def test_dnsmasq_full_parent_allow_removes_more_specific_block(tmp_path):
    generator = DNSMasq(
        ["ads.parent.example.com"],
        ["parent.example.com"],
        {},
        [],
        [],
        set(),
        str(tmp_path / "adblockdnsmasq.txt"),
        "test",
    )
    generator.generate(isLite=False)
    output = Path(generator.fileName).read_text(encoding="utf-8")
    assert "local=/ads.parent.example.com/" not in output
    assert "server=/parent.example.com/#" in output


def test_smartdns_full_preserves_specific_allow_and_parent_allow(tmp_path):
    generator = SmartDNS(
        ["parent.example.com", "ads.parent.example.net"],
        ["safe.parent.example.com", "parent.example.net"],
        {},
        [],
        [],
        set(),
        str(tmp_path / "adblocksmartdns.conf"),
        "test",
    )
    generator.generate(isLite=False)
    output = Path(generator.fileName).read_text(encoding="utf-8")
    assert "address /parent.example.com/#" in output
    assert "address /safe.parent.example.com/-" in output
    assert "address /ads.parent.example.net/#" not in output
    assert "address /parent.example.net/-" in output



def test_adguard_filter_metadata_matches_daily_update_schedule(tmp_path):
    dns_generator = AdGuardHome(
        ["blocked.example.com"],
        ["safe.example.com"],
        {},
        [],
        [],
        {"blocked.example.com"},
        str(tmp_path / "adblockdns.txt"),
        "test",
    )
    dns_generator.blockListLite = ["blocked.example.com"]
    dns_generator.generate()
    dns_full = Path(dns_generator.fileName).read_text(encoding="utf-8")
    dns_generator.generate(isLite=True)
    dns_lite = Path(dns_generator.fileNameLite).read_text(encoding="utf-8")

    browser_generator = AdGuard(
        [],
        [],
        {"||ads.example.com^": "ads.example.com"},
        ["||ads.example.com^"],
        [],
        {"ads.example.com"},
        str(tmp_path / "adblockfilters.txt"),
        "test",
    )
    browser_generator.filterListLite = ["||ads.example.com^"]
    browser_generator.generate()
    browser_full = Path(browser_generator.fileName).read_text(encoding="utf-8")
    browser_generator.generate(isLite=True)
    browser_lite = Path(browser_generator.fileNameLite).read_text(encoding="utf-8")

    for output in (dns_full, dns_lite, browser_full, browser_lite):
        assert "! Expires: 1 day" in output
        assert "每日自动更新一次" in output
        assert "8 个小时" not in output
