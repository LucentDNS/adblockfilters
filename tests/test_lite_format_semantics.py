import json
from pathlib import Path

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


def test_adguard_home_lite_uses_exact_domain_rule(tmp_path):
    output = generate_lite(AdGuardHome, tmp_path, "adblockdns.txt")
    assert "\ncn.example.com\n" in output
    assert "||cn.example.com^" not in output


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
