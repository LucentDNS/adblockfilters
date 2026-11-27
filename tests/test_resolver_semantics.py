from resolver import Resolver


def test_path_specific_dns_block_is_not_promoted_to_domain_block():
    resolver = Resolver(".")
    block, unblock, filt = resolver._Resolver__resolveDNS("||example.org/path^")

    assert block is None
    assert unblock is None
    assert filt == ("||example.org/path^", "example.org")


def test_path_specific_dns_allow_is_not_promoted_to_domain_allow():
    resolver = Resolver(".")
    block, unblock, filt = resolver._Resolver__resolveDNS("@@||example.org/path^")

    assert block is None
    assert unblock is None
    assert filt == ("@@||example.org/path^", "example.org")


def test_anchored_domain_allow_is_preserved_as_allow():
    resolver = Resolver(".")
    block, unblock, filt = resolver._Resolver__resolveDNS("@@||sponsor.nitropay.com^|")

    assert block is None
    assert unblock == ("nitropay.com", "sponsor")
    assert filt is None


def test_generic_filter_options_do_not_depend_on_known_option_allowlist():
    resolver = Resolver(".")
    for rule in (
        "||example.org^$removeparam",
        "||example.org^$future-option",
        "@@||example.org^$future-option",
    ):
        parsed, domain = resolver._Resolver__resolveFilterDomain(rule)
        assert parsed == rule
        assert domain == "example.org"


def test_unterminated_domain_allow_is_retained_as_filter():
    resolver = Resolver(".")
    block, unblock, filt = resolver._Resolver__resolveDNS("@@||example.org/path")

    assert block is None
    assert unblock is None
    assert filt == ("@@||example.org/path", "example.org")


def test_project_googleusercontent_exception_is_path_scoped_and_valid():
    from pathlib import Path

    root = Path(__file__).parents[1]
    rules = (root / "rules" / "myblock.txt").read_text(encoding="utf-8")
    expected = "@@||clients2.googleusercontent.com/crx/blobs/Ad_*^"

    assert expected in rules
    assert "@@||lients2.googleusercontent.com/crx/blobs/Ad_*" not in rules

    resolver = Resolver(".")
    block, unblock, filt = resolver._Resolver__resolveDNS(expected)

    assert block is None
    assert unblock is None
    assert filt == (expected, "clients2.googleusercontent.com")


def test_non_adblock_wildcard_is_not_promoted_to_dns_pattern():
    resolver = Resolver(".")
    rule = "*-ad.sm.cn*"

    block, unblock, filt = resolver._Resolver__resolveDNS(rule)

    assert block is None
    assert unblock is None
    assert filt == (rule, None)

def test_scoped_dns_wildcard_block_is_recognized_for_adguard_output():
    resolver = Resolver(".")
    rule = "||ads*-normal-hl.zijieapi.com^"

    block, unblock, filt = resolver._Resolver__resolveDNS(rule)

    assert block is None
    assert unblock is None
    assert filt == (rule, None)
    assert resolver.resolveDNSPattern(rule) == ("block", "zijieapi.com")


def test_scoped_dns_wildcard_allow_is_recognized_for_adguard_output():
    resolver = Resolver(".")
    rule = "@@||profile*.se.360.cn^"

    assert resolver.resolveDNSPattern(rule) == ("allow", "360.cn")


def test_scoped_dns_wildcard_inside_subdomain_label_is_recognized():
    resolver = Resolver(".")
    rule = "||ping.*.sogou.com^"

    assert resolver.resolveDNSPattern(rule) == ("block", "sogou.com")


def test_broad_dns_wildcards_and_regex_are_excluded():
    resolver = Resolver(".")

    assert resolver.resolveDNSPattern("||ad-*.com^") is None
    assert resolver.resolveDNSPattern("||admob.*^") is None
    assert resolver.resolveDNSPattern("/^.+stat\\.kugou\\.com/") is None
    assert resolver.resolveDNSPattern("||fxhpaoxqyajvmdg.") is None


def test_stale_legacy_blogspot_trojan_hosts_are_not_kept_without_current_evidence():
    from pathlib import Path

    root = Path(__file__).parents[1]
    rules = (root / "rules" / "myblock.txt").read_text(encoding="utf-8")

    assert "||2006mindfreaklike.blogspot.com^" not in rules
    assert "||girlownedbypolicelike.blogspot.com^" not in rules
    assert "||blogspot.com^" not in rules
