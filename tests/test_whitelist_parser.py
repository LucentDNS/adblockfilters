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
