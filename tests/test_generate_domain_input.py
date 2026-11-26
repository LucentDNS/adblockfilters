from scripts.generate_domain_input import domains_from_block_dict


def test_domain_input_uses_normalized_block_domains_only():
    block_dict = {
        "example.com": {"", "www", "api"},
        "ads.example.net": {""},
        "": {"192.0.2.10"},
    }

    assert domains_from_block_dict(block_dict) == {
        "example.com",
        "www.example.com",
        "api.example.com",
        "ads.example.net",
    }


def test_wildcard_only_apex_is_not_used_as_dns_liveness_candidate():
    from scripts.generate_domain_input import exclude_wildcard_only_domains

    domains = {"wild.example.com", "exact.example.net", "normal.example"}
    wildcard = {"wild.example.com", "exact.example.net"}
    explicit = {"exact.example.net"}

    assert exclude_wildcard_only_domains(domains, wildcard, explicit) == {
        "exact.example.net",
        "normal.example",
    }


def test_resolver_tracks_wildcard_and_explicit_dns_block_domains_separately(tmp_path):
    from readme import Rule
    from resolver import Resolver

    (tmp_path / "wildcard.txt").write_text(
        "||*.wild.example.com^\n||exact.example.net^\n", encoding="utf-8"
    )
    resolver = Resolver(str(tmp_path))
    block, _, _ = resolver.resolveDNS(Rule("wildcard", "dns", "", ""))

    assert "wild.example.com" in resolver.wildcard_block_domains
    assert "exact.example.net" in resolver.explicit_block_domains
    assert block == {"example.com": {"wild"}, "example.net": {"exact"}}
