from pathlib import Path


def test_upstream_dns_allow_exceptions_are_preserved():
    path = Path(__file__).parents[1] / "rules" / "white.txt"
    entries = {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert "@@||content.ingbank.pl^" in entries
    assert "@@||alllaw.112.2o7.net^" in entries


def test_curated_dns_supplement_rules_are_present():
    path = Path(__file__).parents[1] / "rules" / "myblock.txt"
    entries = {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("!")
    }

    assert "||fb_servpub-a.akamaihd.net^" in entries


def test_dns_resolver_accepts_underscore_label_in_known_tracking_domain():
    from resolver import Resolver

    block, unblock, filter_rule = Resolver("unused")._Resolver__resolveDNS(
        "||fb_servpub-a.akamaihd.net^"
    )

    assert block is not None
    assert unblock is None
    assert filter_rule is None
