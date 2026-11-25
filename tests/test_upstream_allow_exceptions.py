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


def test_manual_dns_supplement_rules_use_dns_label_syntax():
    import re

    path = Path(__file__).parents[1] / "rules" / "myblock.txt"
    pattern = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        if line.startswith("@@||") and line.endswith("^") and ("*" in line or "/" in line):
            # Wildcard/path-scoped exceptions are browser-filter rules, not DNS names.
            continue
        if line.startswith("@@||") and line.endswith("^"):
            domain = line[4:-1]
        elif line.startswith("||") and line.endswith("^") and "*" not in line and "/" not in line:
            domain = line[2:-1]
        else:
            raise AssertionError(f"Unsupported manual DNS rule syntax: {line}")

        assert len(domain) <= 253, domain
        labels = domain.split(".")
        assert len(labels) >= 2, domain
        assert all(1 <= len(label) <= 63 and pattern.fullmatch(label) for label in labels), domain
