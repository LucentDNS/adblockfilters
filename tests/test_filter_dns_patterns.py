from filter import Filter, _get_wildcard_white_exceptions
from readme import Rule
from resolver import Resolver


def test_only_scoped_patterns_from_dns_sources_enter_adguard_dns_patterns(tmp_path):
    source_dir = tmp_path / "sources"
    source_dir.mkdir()

    dns_rule = Rule("DNS test", "dns", "https://example.test/dns.txt", "live")
    browser_rule = Rule("Browser test", "filter", "https://example.test/filter.txt", "live")

    (source_dir / dns_rule.filename).write_text(
        "\n".join(
            [
                "||ads*-normal-hl.zijieapi.com^",
                "@@||profile*.se.360.cn^",
                "||typed.example.com^$dnstype=A",
                "||typed-ads*.example.net^$dnstype=A,AAAA",
                "@@||typed-safe*.example.org^$dnstype=AAAA",
                "||important.example.com^$important",
                "||client.example.com^$client=phone",
                "||ad-*.com^",
                "/^.+stat\\.kugou\\.com/",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (source_dir / browser_rule.filename).write_text(
        "||browser*.example.com^\n",
        encoding="utf-8",
    )
    (source_dir / "myblock.txt").write_text("", encoding="utf-8")

    parser = Filter(
        [dns_rule, browser_rule],
        path=str(tmp_path),
        outPath=str(tmp_path),
        sourcePath=str(source_dir),
    )
    block, allow, filter_rules, dns_pattern_blocks, dns_pattern_allows = (
        parser._Filter__getFilters()
    )

    assert block == {}
    assert allow == {}
    assert dns_pattern_blocks == {
        "||ads*-normal-hl.zijieapi.com^": "zijieapi.com",
        "||typed.example.com^$dnstype=A": "example.com",
        "||typed-ads*.example.net^$dnstype=A,AAAA": "example.net",
    }
    assert dns_pattern_allows == {
        "@@||profile*.se.360.cn^": "360.cn",
        "@@||typed-safe*.example.org^$dnstype=AAAA": "example.org",
    }
    assert "||important.example.com^$important" not in dns_pattern_blocks
    assert "||client.example.com^$client=phone" not in dns_pattern_blocks
    assert "||ad-*.com^" not in dns_pattern_blocks
    assert "/^.+stat\\.kugou\\.com/" not in dns_pattern_blocks
    assert "||browser*.example.com^" not in dns_pattern_blocks
    assert "||browser*.example.com^" in filter_rules



def test_wildcard_dns_block_rules_generate_exact_whitelist_exceptions():
    white_domains = {
        "ads123.example.com",
        "sub.ads123.example.com",
        "safe.example.com",
        "ping.x.sogou.com",
        "typed.example.com",
    }
    patterns = {
        "||ads*.example.com^",
        "||ping.*.sogou.com^",
        "||typed.example.com^$dnstype=A",
    }

    assert _get_wildcard_white_exceptions(white_domains, patterns) == {
        "ads123.example.com",
        "sub.ads123.example.com",
        "ping.x.sogou.com",
        "typed.example.com",
    }


def test_dns_pattern_parser_preserves_only_safe_dnstype_modifier(tmp_path):
    resolver = Resolver(str(tmp_path))

    assert resolver.resolveDNSPattern("||ads.example.com^$dnstype=A") == (
        "block",
        "example.com",
    )
    assert resolver.resolveDNSPattern("@@||safe.example.com^$dnstype=AAAA") == (
        "allow",
        "example.com",
    )
    assert resolver.resolveDNSPattern("||ads*.example.com^$dnstype=A,AAAA") == (
        "block",
        "example.com",
    )

    # Do not widen or reinterpret rules whose modifiers need different semantics.
    assert resolver.resolveDNSPattern("||ads.example.com^$important") is None
    assert resolver.resolveDNSPattern("||ads.example.com^$client=phone") is None
    assert resolver.resolveDNSPattern("||ads.example.*^$dnstype=A") is None
    assert resolver.resolveDNSPattern("||*.com^$dnstype=A") is None
