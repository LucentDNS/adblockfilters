import json
import re
from pathlib import Path

import pytest

from readme import ReadMe, Rule


def test_repository_source_manifest_is_unique_and_https_only():
    root = Path(__file__).parents[1]
    rules = ReadMe(str(root / "README.md")).getRules()
    manifest = json.loads((root / "sources.json").read_text(encoding="utf-8"))
    readme = (root / "README.md").read_text(encoding="utf-8")

    assert manifest["version"] == 1
    assert len(manifest["sources"]) >= 1
    assert "## 上游来源" not in readme
    assert len(rules) == len(manifest["sources"])
    assert all(rule.type in {"filter", "dnsfilter", "dns", "host"} for rule in rules)
    assert all(rule.url.startswith("https://") for rule in rules)
    assert len({rule.name for rule in rules}) == len(rules)
    assert len({rule.filename for rule in rules}) == len(rules)
    assert len({rule.url for rule in rules}) == len(rules)


def test_sources_without_verified_redistribution_terms_are_excluded():
    root = Path(__file__).parents[1]
    manifest = json.loads((root / "sources.json").read_text(encoding="utf-8"))
    names = {source["name"] for source in manifest["sources"]}

    # Re-add only after the upstream provides explicit redistribution terms.
    assert not names.intersection(
        {"AdRules DNS List", "xinggsf mv", "jiekouAD", "OISD Small"}
    )


def test_source_manifest_rejects_filename_collisions(tmp_path):
    path = tmp_path / "README.md"
    path.write_text(
        "| A/B | dns | [upstream](https://example.com/a.txt) | now |\n"
        "| A:B | dns | [upstream](https://example.com/b.txt) | now |\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate upstream source filename"):
        ReadMe(str(path)).getRules()


def test_source_manifest_rejects_unknown_source_type(tmp_path):
    path = tmp_path / "README.md"
    path.write_text(
        "| Example | unknown | [upstream](https://example.com/a.txt) | now |\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Unsupported upstream source type"):
        ReadMe(str(path)).getRules()


def test_source_manifest_rejects_plain_http(tmp_path):
    path = tmp_path / "README.md"
    path.write_text(
        "| Example | dns | [upstream](http://example.com/a.txt) | now |\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must use HTTPS"):
        ReadMe(str(path)).getRules()


def test_readme_direct_subscriptions_are_unique_and_complete():
    root = Path(__file__).parents[1]
    readme = (root / "README.md").read_text(encoding="utf-8")
    subscriptions = re.findall(
        r"\[[^\]]+\]\(https://raw\.githubusercontent\.com/[^/]+/[^/]+/dist/([^)]+)\)",
        readme,
    )

    expected = {
        "adblockdns.txt",
        "adblockdnslite.txt",
        "adblockfilters.txt",
        "adblockfilterslite.txt",
    }
    assert len(subscriptions) == 4
    assert len(subscriptions) == len(set(subscriptions))
    assert set(subscriptions) == expected


def test_release_asset_filename_is_github_safe_and_stable():
    assert Rule("CJX's Annoyance List", "filter", "", "").filename == "CJX.s_Annoyance_List.txt"
    assert Rule("AWAvenue Ads Rule (Only.Ads)", "dns", "", "").filename == "AWAvenue_Ads_Rule_.Only.Ads.txt"
    assert Rule("AdGuard DNS filter", "dnsfilter", "", "").filename == "AdGuard_DNS_filter.txt"


def test_legacy_source_table_parser_skips_other_markdown_tables(tmp_path):
    readme_path = tmp_path / "README.md"
    readme_path.write_text(
        "| Version | URL |\n"
        "|---|---|\n"
        "| DNS | https://example.com/list.txt |\n"
        "| Source | Type | Link | Updated |\n"
        "| Example | dns | [upstream](https://example.org/source.txt) | today |\n",
        encoding="utf-8",
    )

    rules = ReadMe(str(readme_path)).getRules()

    assert len(rules) == 1
    assert rules[0].name == "Example"
    assert rules[0].url == "https://example.org/source.txt"


def test_readme_upstream_attribution_matches_the_source_manifest():
    root = Path(__file__).parents[1]
    readme = (root / "README.md").read_text(encoding="utf-8")
    manifest = json.loads((root / "sources.json").read_text(encoding="utf-8"))
    section = readme.split("## 集成的上游规则源", 1)[1].split("## 许可与归属", 1)[0]
    linked_urls = re.findall(r"— \[来源\]\((https://[^)]+)\)", section)
    expected_urls = [source["url"] for source in manifest["sources"]]

    assert len(linked_urls) == len(expected_urls) == len(manifest["sources"])
    assert len(linked_urls) == len(set(linked_urls))
    assert set(linked_urls) == set(expected_urls)
