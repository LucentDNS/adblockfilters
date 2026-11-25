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
