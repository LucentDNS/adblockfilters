from readme import ReadMe, Rule


def test_regenerated_readme_omits_obsolete_migration_announcement(tmp_path):
    readme_path = tmp_path / "README.md"
    readme = ReadMe(str(readme_path))

    readme.regenerate()

    generated = readme_path.read_text(encoding="utf-8")
    assert "重要公告" not in generated
    assert "20261120" not in generated
    assert "raw.githubusercontent.com/LucentDNS/adblockfilters/dist/" in generated


def test_release_asset_filename_is_github_safe_and_stable():
    assert Rule("CJX's Annoyance List", "filter", "", "").filename == "CJX.s_Annoyance_List.txt"
    assert Rule("AWAvenue Ads Rule (Only.Ads)", "dns", "", "").filename == "AWAvenue_Ads_Rule_.Only.Ads.txt"
    assert Rule("AdGuard DNS filter", "dnsfilter", "", "").filename == "AdGuard_DNS_filter.txt"
