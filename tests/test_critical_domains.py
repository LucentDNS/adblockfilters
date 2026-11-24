from scripts.verify_critical_domains import is_covered, normalize_domain


def test_parent_domain_rule_covers_its_subdomains():
    assert is_covered("login.example.com", {"example.com"})


def test_child_domain_rule_does_not_cover_parent_domain():
    assert not is_covered("example.com", {"login.example.com"})


def test_exact_allow_or_block_domain_normalizes():
    assert normalize_domain(("example.com", "")) == "example.com"
    assert normalize_domain(("example.com", "api")) == "api.example.com"
    assert normalize_domain(("", "192.0.2.1")) is None
