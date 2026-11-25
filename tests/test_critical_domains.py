from scripts.verify_critical_domains import (
    is_covered,
    normalize_domain,
    parse_domain_wide_browser_rule,
)


def test_parent_domain_rule_covers_its_subdomains():
    assert is_covered("login.example.com", {"example.com"})


def test_child_domain_rule_does_not_cover_parent_domain():
    assert not is_covered("example.com", {"login.example.com"})


def test_exact_allow_or_block_domain_normalizes():
    assert normalize_domain(("example.com", "")) == "example.com"
    assert normalize_domain(("example.com", "api")) == "api.example.com"
    assert normalize_domain(("", "192.0.2.1")) is None


def test_exact_domain_wide_browser_block_is_detected():
    assert parse_domain_wide_browser_rule("||alipay.com^") == ("alipay.com", False)
    assert parse_domain_wide_browser_rule("||alipay.com") == ("alipay.com", False)


def test_important_and_document_browser_blocks_are_domain_wide():
    assert parse_domain_wide_browser_rule("||alipay.com^$important") == ("alipay.com", False)
    assert parse_domain_wide_browser_rule("||alipay.com^$document") == ("alipay.com", False)


def test_global_browser_allow_exception_is_detected():
    assert parse_domain_wide_browser_rule("@@||alipay.com^") == ("alipay.com", True)


def test_path_specific_browser_rules_do_not_block_service_root():
    assert parse_domain_wide_browser_rule("||alipay.com/service/clear.png?") is None
    assert parse_domain_wide_browser_rule("||toutiao.com^*/user_log/") is None
    assert parse_domain_wide_browser_rule("||oppo.com/api/country") is None


def test_cosmetic_and_scriptlet_rules_do_not_block_service_root():
    assert parse_domain_wide_browser_rule("douyin.com###videoSideBar") is None
    assert parse_domain_wide_browser_rule("douyin.com#%#//scriptlet('example')") is None


def test_request_type_and_third_party_modifiers_are_not_domain_wide():
    assert parse_domain_wide_browser_rule("||alipay.com^$script,third-party") is None
    assert parse_domain_wide_browser_rule("||alipay.com^$image") is None
    assert parse_domain_wide_browser_rule("||alipay.com^$domain=example.com") is None


def test_wildcard_subdomain_rule_does_not_match_service_root():
    parsed = parse_domain_wide_browser_rule("||api.ad.xiaomi.com^")
    assert parsed == ("api.ad.xiaomi.com", False)
    assert not is_covered("xiaomi.com", {parsed[0]})


def test_disabled_badfilter_rule_is_ignored():
    assert parse_domain_wide_browser_rule("||alipay.com^$badfilter") is None


def test_critical_service_regression_list_is_unique_and_broad():
    from pathlib import Path

    path = Path(__file__).parent / "data" / "critical-domains.txt"
    domains = [
        line.strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    assert len(domains) >= 100
    assert len(domains) == len(set(domains))
    assert "google.com" in domains
    assert "microsoft.com" in domains
    assert "github.com" in domains
    assert "qq.com" in domains


def test_manual_phishing_regression_domains_are_present_in_project_block_rules():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    expected_path = root / "tests" / "data" / "manual-block-domains.txt"
    rules_path = root / "rules" / "myblock.txt"
    expected = {
        line.strip().lower()
        for line in expected_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    rules = {
        line.strip().lower()
        for line in rules_path.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("||") and line.strip().endswith("^")
    }
    actual = {rule[2:-1] for rule in rules}

    assert expected
    assert len(expected) == len([
        line.strip().lower()
        for line in expected_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ])
    assert expected <= actual
