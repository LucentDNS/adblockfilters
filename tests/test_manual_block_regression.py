from pathlib import Path
import re


ROOT = Path(__file__).parents[1]


def test_high_confidence_manual_block_domains_remain_blocked():
    fixture = ROOT / "tests" / "data" / "manual-block-domains.txt"
    required = {
        line.strip().lower()
        for line in fixture.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    rules = (ROOT / "rules" / "myblock.txt").read_text(encoding="utf-8")
    blocked = set(re.findall(r"^\|\|([a-z0-9.-]+)\^$", rules, re.MULTILINE))

    assert required, "Manual block regression fixture must not be empty"
    assert len(required) == sum(
        1 for line in fixture.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ), "Manual block regression fixture contains duplicate domains"
    missing = sorted(required - blocked)
    untracked = sorted(blocked - required)
    assert not missing, "Manual block domains missing from myblock.txt: " + ", ".join(missing)
    assert not untracked, "Manual block domains missing from regression fixture: " + ", ".join(untracked)


def test_curated_manual_blocks_override_dns_nxdomain_blacklist():
    from filter import _remove_manual_blocks_from_blacklist

    blacklist = {
        "dead-upstream.example",
        "phishing.example",
        "sub.phishing.example",
        "unrelated.example",
    }
    manual_blocks = {
        "example": {"phishing"},
        "tracker.example": {""},
    }

    assert _remove_manual_blocks_from_blacklist(blacklist, manual_blocks) == {
        "dead-upstream.example",
        "unrelated.example",
    }
