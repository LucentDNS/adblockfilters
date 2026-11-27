from filter import _build_exact_block_list, _build_lite_block_list
from resolver import Resolver
from scripts.audit_sources import dns_pattern_matches_domain, parse_lite_dns_rules


def test_lite_keeps_domestic_child_after_full_parent_compression():
    block_domains = {
        "example.com",
        "api.example.com",
        "ads.example.net",
        "dead.example.org",
    }
    china_domains = {
        "api.example.com",
        "ads.example.net",
        "dead.example.org",
    }
    allow_domains = {"example.net"}
    blacklist = {"dead.example.org"}

    assert _build_lite_block_list(
        block_domains, china_domains, allow_domains, blacklist
    ) == ["api.example.com"]


def test_lite_does_not_promote_a_non_domestic_parent_or_allowlisted_host():
    block_domains = {"example.com", "api.example.com", "safe.example.com"}
    china_domains = {"api.example.com", "safe.example.com"}
    allow_domains = {"safe.example.com"}
    blacklist = set()

    assert _build_lite_block_list(
        block_domains, china_domains, allow_domains, blacklist
    ) == ["api.example.com"]



def test_lite_respects_project_whitelist_parent_and_case_insensitive_domains():
    assert _build_lite_block_list(
        {"tracker.example.com", "ads.example.net"},
        {"TRACKER.EXAMPLE.COM", "ads.example.net"},
        {"example.com"},
        set(),
    ) == ["ads.example.net"]



def test_hosts_full_exact_list_retains_children_after_suffix_compression():
    assert _build_exact_block_list(
        {"example.com", "api.example.com", "ads.example.net"},
        set(),
        set(),
    ) == ["ads.example.net", "api.example.com", "example.com"]


def test_hosts_full_exact_list_respects_parent_allowlist():
    assert _build_exact_block_list(
        {"example.com", "api.example.com", "other.example.net"},
        {"example.com"},
        set(),
    ) == ["other.example.net"]


def test_lite_scope_audit_recognizes_valid_dns_pattern_rules(tmp_path):
    resolver = Resolver(str(tmp_path))
    parsed = parse_lite_dns_rules(
        [
            "||ads.example.com^",
            "||ads*.example.net^",
            "||typed.example.org^$dnstype=A",
            "@@||safe.example.com^",
            "@@||safe*.example.net^$dnstype=AAAA",
        ],
        resolver,
    )

    assert parsed["suffix_blocks"] == {"ads.example.com"}
    assert parsed["pattern_blocks"] == {
        "||ads*.example.net^": "example.net",
        "||typed.example.org^$dnstype=A": "example.org",
    }
    assert parsed["allows"] == {"safe.example.com"}
    assert parsed["pattern_allows"] == {
        "@@||safe*.example.net^$dnstype=AAAA": "example.net"
    }


def test_lite_scope_wildcard_matching_does_not_overstate_dnstype_coverage():
    assert dns_pattern_matches_domain(
        "||ads*.example.net^", "ads123.example.net"
    )
    assert not dns_pattern_matches_domain(
        "||ads*.example.net^", "safe.example.net"
    )
    assert not dns_pattern_matches_domain(
        "||typed.example.org^$dnstype=A", "typed.example.org"
    )
