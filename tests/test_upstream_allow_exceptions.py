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



def test_manual_dns_supplement_rules_use_hostname_compatible_labels():
    import re
    from pathlib import Path

    path = Path(__file__).parents[1] / "rules" / "myblock.txt"
    rules = [
        line.strip()[2:-1]
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("||") and line.strip().endswith("^")
    ]
    label_pattern = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)

    assert rules
    assert all(all(label_pattern.fullmatch(label) for label in domain.split(".")) for domain in rules)
