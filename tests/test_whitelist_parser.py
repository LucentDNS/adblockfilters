from filter import Filter


def parse_whitelist(entries):
    instance = Filter.__new__(Filter)
    return instance._Filter__getWhiteDict(set(entries))


def test_plain_domain_exception_is_normalized_to_domain():
    result = parse_whitelist({"nimiq.com"})
    assert result == {"nimiq.com": {""}}


def test_adguard_domain_exception_without_modifiers_is_normalized():
    result = parse_whitelist({"||nimiq.com^"})
    assert result == {"nimiq.com": {""}}


def test_subdomain_exception_without_modifiers_is_normalized():
    result = parse_whitelist({"||pool.nimiq.watch^"})
    assert result == {"nimiq.watch": {"pool"}}


def test_modifier_bearing_browser_exception_is_not_a_dns_whitelist():
    result = parse_whitelist({"||nimiq.com^$third-party"})
    assert result == {}


def test_browser_path_and_wildcard_patterns_are_not_dns_whitelist_domains():
    result = parse_whitelist({"*/ad_", "||ad.", "youtube.com#%#scriptlet('example')"})
    assert result == {}


def test_whitelisted_subdomain_gets_exception_when_parent_is_blocked():
    instance = Filter.__new__(Filter)
    white_dict = parse_whitelist({"cdn.branch.io"})
    assert instance._Filter__getWhiteExceptions(white_dict, ["branch.io"]) == [
        "cdn.branch.io"
    ]


def test_unblocked_whitelist_domain_does_not_add_redundant_exception():
    instance = Filter.__new__(Filter)
    white_dict = parse_whitelist({"cdn.branch.io"})
    assert instance._Filter__getWhiteExceptions(white_dict, ["tracker.example.com"]) == []


def test_lite_filter_keeps_exact_china_domains_and_unrestricted_generic_rules():
    from app.adguard import AdGuard

    china = {"ad.qq.com"}
    rules = {
        "||ad.qq.com^": "ad.qq.com",
        "||ad.google.com^": "ad.google.com",
        "##.sponsored": None,
    }
    generator = AdGuard([], [], rules, list(rules), [], china, "out.txt", "test")

    assert generator.filterListLite == ["||ad.qq.com^", "##.sponsored"]
