from filter import Filter


def parse_whitelist(entries):
    instance = Filter.__new__(Filter)
    return instance._Filter__getWhiteDict(set(entries))


def test_adguard_domain_exception_is_normalized_to_domain():
    result = parse_whitelist({"||nimiq.com^$third-party"})
    assert result == {"nimiq.com": {""}}


def test_subdomain_exception_is_normalized_to_subdomain():
    result = parse_whitelist({"||pool.nimiq.watch^$third-party"})
    assert result == {"nimiq.watch": {"pool"}}


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
