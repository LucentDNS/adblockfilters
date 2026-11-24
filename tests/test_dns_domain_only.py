from filter import Filter
from scripts.audit_sources import full_domain


def test_dns_domain_sort_excludes_ip_literals():
    generator = Filter([], ".")
    block_list, all_domains = generator._Filter__domainSort(
        {
            "example.com": {""},
            "203.0.113.8": {""},
            "198.51.100.4:443": {""},
            "2001:db8::1": {""},
        },
        set(),
        {},
    )
    assert block_list == ["example.com"]
    assert all_domains == {"example.com"}


def test_browser_ip_filter_is_kept_but_not_added_to_dns_domain_backup():
    generator = Filter([], ".")
    _, filter_list, domain_set = generator._Filter__filterSort(
        {
            "||203.0.113.8^": "203.0.113.8",
            "||example.com^": "example.com",
        },
        set(),
        set(),
        set(),
        set(),
    )
    assert "||203.0.113.8^" in filter_list
    assert "||example.com^" in filter_list
    assert domain_set == {"example.com"}


def test_source_audit_excludes_ip_literals_from_domain_counts():
    assert full_domain(("203.0.113.8", "")) is None
    assert full_domain(("198.51.100.4:443", "")) is None
    assert full_domain(("2001:db8::1", "")) is None
    assert full_domain(("example.com", "")) == "example.com"
