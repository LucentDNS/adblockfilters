from scripts.generate_china_list import classify_domains, parse_direct_rules


def test_direct_rule_parser_uses_only_full_and_domain_entries():
    full, domains = parse_direct_rules(
        """
        # China direct rules
        full:api.example.com
        domain:service.example.net
        regexp:.*ignored.*
        keyword:also-ignored
        """
    )

    assert full == {"api.example.com"}
    assert domains == {"service.example.net"}


def test_conservative_lite_classifier_uses_cn_full_domain_and_prior_dns_positive():
    current = {
        "service.cn",
        "api.example.com",
        "child.service.example.net",
        "global.example.org",
        "stale.example.cn",
    }
    full = {"api.example.com"}
    roots = {"example.net"}
    previous_dns = {"global.example.org", "stale-not-current.example.com"}

    china, direct, retained = classify_domains(
        current, full, roots, previous_dns
    )

    assert direct == {
        "service.cn",
        "api.example.com",
        "child.service.example.net",
        "stale.example.cn",
    }
    assert retained == set()
    assert china == direct


def test_previous_dns_positive_classification_is_intersected_with_current_sources():
    current = {"service.cn", "live.example.com"}
    previous = {"live.example.com", "removed.example.com"}

    china, direct, retained = classify_domains(
        current, set(), set(), previous
    )

    assert direct == {"service.cn"}
    assert retained == {"live.example.com"}
    assert china == {"service.cn", "live.example.com"}
