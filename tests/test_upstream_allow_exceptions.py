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

    assert "||fb_servpub-a.akamaihd.net^" not in entries
    assert "||oth.str.mdt.qq.com^" in entries


def test_manual_dns_supplement_rules_use_supported_dns_syntax():
    import re

    from resolver import Resolver

    path = Path(__file__).parents[1] / "rules" / "myblock.txt"
    pattern = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    resolver = Resolver("unused")

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        if line.startswith("@@||") and line.endswith("^") and "/" in line:
            # Path-scoped exceptions remain browser-only.
            continue
        if "*" in line:
            assert resolver.resolveDNSPattern(line) is not None, (
                f"Unsupported or overly broad manual DNS wildcard: {line}"
            )
            continue
        if line.startswith("@@||") and line.endswith("^"):
            domain = line[4:-1]
        elif line.startswith("||") and line.endswith("^"):
            domain = line[2:-1]
        else:
            raise AssertionError(f"Unsupported manual DNS rule syntax: {line}")

        assert len(domain) <= 253, domain
        labels = domain.split(".")
        assert len(labels) >= 2, domain
        assert all(1 <= len(label) <= 63 and pattern.fullmatch(label) for label in labels), domain



def test_manual_block_rules_precede_browser_allow_exceptions():
    path = Path(__file__).parents[1] / "rules" / "myblock.txt"
    lines = path.read_text(encoding="utf-8").splitlines()
    allow_section = lines.index("! 放行规则")

    assert all(
        index < allow_section
        for index, line in enumerate(lines)
        if line.strip().startswith("||")
    )
    assert (
        "! The following wildcard/path-scoped exceptions are browser-filter rules, "
        "not DNS-domain rules."
    ) in lines
