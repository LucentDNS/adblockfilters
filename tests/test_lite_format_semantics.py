from pathlib import Path

from app.adguard import AdGuard
from app.adguardhome import AdGuardHome


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
    assert "\\ncn.example.com\\n" not in output


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

    generator.generate(isLite=True)
    lite = Path(generator.fileNameLite).read_text(encoding="utf-8")
    assert block_pattern in lite
    assert allow_pattern in lite
    assert "@@||ads123.example.com^" in lite
    assert second_block_pattern not in lite


def test_adguard_browser_generator_preserves_full_and_lite_outputs(tmp_path):
    generator = AdGuard(
        ["blocked.example.com"],
        ["safe.example.com"],
        {},
        [],
        [],
        {"blocked.example.com"},
        str(tmp_path / "adblockfilters.txt"),
        "test",
    )
    generator.blockListLite = ["blocked.example.com"]
    generator.generateAll()

    full = Path(generator.fileName).read_text(encoding="utf-8")
    lite = Path(generator.fileNameLite).read_text(encoding="utf-8")
    assert "blocked.example.com" in full
    assert "blocked.example.com" in lite
