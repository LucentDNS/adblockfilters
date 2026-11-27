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


def test_conservative_lite_classifier_uses_cn_full_and_domain_rules():
    current = {
        "service.cn",
        "api.example.com",
        "child.service.example.net",
        "global.example.org",
    }
    full = {"api.example.com"}
    roots = {"example.net"}
    china = classify_domains(current, full, roots)

    assert china == {
        "service.cn",
        "api.example.com",
        "child.service.example.net",
    }
