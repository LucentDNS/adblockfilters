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
                "||typed-ads*.example.net^$dnstype=A|AAAA",
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
        "||typed-ads*.example.net^$dnstype=A|AAAA": "example.net",
    }
    # DNS source allows are source-local and must not be published as
    # project-wide allow patterns.
    assert dns_pattern_allows == {}
    assert "||important.example.com^$important" not in dns_pattern_blocks
    assert "||client.example.com^$client=phone" not in dns_pattern_blocks
    assert "||ad-*.com^" not in dns_pattern_blocks
    assert "/^.+stat\\.kugou\\.com/" not in dns_pattern_blocks
    assert "||browser*.example.com^" not in dns_pattern_blocks
    assert "||browser*.example.com^" in filter_rules
    # DNS-only source rules that the DNS parser cannot safely represent must not
    # be copied into the browser subscription as a fallback.
    assert "||important.example.com^$important" not in filter_rules
    assert "||client.example.com^$client=phone" not in filter_rules
    assert "/^.+stat\\.kugou\\.com/" not in filter_rules



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
    assert resolver.resolveDNSPattern("||ads*.example.com^$dnstype=A|AAAA") == (
        "block",
        "example.com",
    )
    assert resolver.resolveDNSPattern("||ads.example.com^$dnstype=~A|~CNAME") == (
        "block",
        "example.com",
    )
    assert resolver.resolveDNSPattern("||ads.example.com^$dnstype=~A|AAAA") is None

    # Do not widen or reinterpret rules whose modifiers need different semantics.
    assert resolver.resolveDNSPattern("||ads.example.com^$important") is None
    assert resolver.resolveDNSPattern("||ads.example.com^$client=phone") is None
    assert resolver.resolveDNSPattern("||ads.example.*^$dnstype=A") is None
    assert resolver.resolveDNSPattern("||*.com^$dnstype=A") is None


def test_source_local_pattern_allow_does_not_cancel_another_source_block():
    from filter import _apply_source_local_pattern_allows

    source_a_blocks = {"||ads.example.com^": "example.com"}
    source_a_allows = {"@@||example.com^": "example.com"}
    source_b_blocks = {"||ads.example.com^": "example.com"}

    assert _apply_source_local_pattern_allows(
        source_a_blocks, source_a_allows
    ) == {}
    assert _apply_source_local_pattern_allows(
        source_b_blocks, {}
    ) == source_b_blocks


def test_pattern_allow_only_covers_compatible_modifier_scope():
    from filter import _pattern_allow_covers_block

    assert _pattern_allow_covers_block(
        "@@||example.com^", "||ads.example.com^$dnstype=A"
    )
    assert _pattern_allow_covers_block(
        "@@||example.com^$dnstype=A", "||ads.example.com^$dnstype=A"
    )
    assert not _pattern_allow_covers_block(
        "@@||example.com^$dnstype=AAAA", "||ads.example.com^$dnstype=A"
    )
    assert not _pattern_allow_covers_block(
        "@@||ads*.example.com^", "||ads.example.com^"
    )


def test_get_filters_keeps_other_sources_block_after_source_local_allow(tmp_path):
    source_dir = tmp_path / "sources"
    source_dir.mkdir()
    source_a = Rule("Source A", "dns", "https://example.test/a.txt", "live")
    source_b = Rule("Source B", "dns", "https://example.test/b.txt", "live")

    (source_dir / source_a.filename).write_text(
        "ads.example.com\\n@@||example.com^\\n", encoding="utf-8"
    )
    (source_dir / source_b.filename).write_text(
        "ads.example.com\\n", encoding="utf-8"
    )
    (source_dir / "myblock.txt").write_text("", encoding="utf-8")

    parser = Filter(
        [source_a, source_b],
        path=str(tmp_path),
        outPath=str(tmp_path),
        sourcePath=str(source_dir),
    )
    block, allow, _, _, _ = parser._Filter__getFilters()

    assert block == {"example.com": {"ads"}}
    assert allow == {}
