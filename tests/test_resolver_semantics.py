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
