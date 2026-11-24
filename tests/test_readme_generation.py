from readme import ReadMe, Rule


def test_regenerated_readme_omits_obsolete_migration_announcement(tmp_path):
    readme_path = tmp_path / "README.md"
    readme = ReadMe(str(readme_path))

    readme.regenerate()

    generated = readme_path.read_text(encoding="utf-8")
    assert "重要公告" not in generated
    assert "20261120" not in generated
    assert "raw.githubusercontent.com/LucentDNS/adblockfilters/dist/" in generated
    assert generated.splitlines()[0] == "# DNS Adblock Filters"
    assert generated.count("https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdns.txt") == 1
    assert "每日自动构建" in generated


def test_release_asset_filename_is_github_safe_and_stable():
    assert Rule("CJX's Annoyance List", "filter", "", "").filename == "CJX.s_Annoyance_List.txt"
    assert Rule("AWAvenue Ads Rule (Only.Ads)", "dns", "", "").filename == "AWAvenue_Ads_Rule_.Only.Ads.txt"
    assert Rule("AdGuard DNS filter", "dnsfilter", "", "").filename == "AdGuard_DNS_filter.txt"


def test_get_rules_skips_subscription_tables_with_different_column_counts(tmp_path):
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
