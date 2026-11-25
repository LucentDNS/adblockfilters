from readme import ReadMe, Rule


def test_regenerated_readme_lists_only_validated_release_outputs(tmp_path):
    readme_path = tmp_path / "README.md"
    readme = ReadMe(str(readme_path))

    readme.regenerate()

    generated = readme_path.read_text(encoding="utf-8")
    assert "## 重要公告" not in generated
    assert "20261120" not in generated
    assert "217heidai/adblockfilters" in generated
    assert "## 正式订阅（仅列出构建验证通过的产物）" in generated
    assert "myblock.txt（补充拦截）" in generated
    assert "white.txt（放行例外）" in generated
    assert "raw.githubusercontent.com/LucentDNS/adblockfilters/dist/" in generated
    assert generated.splitlines()[0] == "# AdBlock DNS Filters"
    # The raw subscription URL is also embedded inside each of the three
    # mirror URLs. Assert the Markdown's original-link target, not substring
    # occurrences across the complete document.
    assert generated.count(
        "[原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdns.txt)"
    ) == 1
    assert "每 8 小时自动构建" in generated
    import re
    subscriptions = re.findall(
        r"\[原始链接\]\(https://raw\.githubusercontent\.com/[^/]+/[^/]+/dist/([^)]+)\)",
        generated,
    )
    assert len(subscriptions) == 34
    assert len(subscriptions) == len(set(subscriptions))
    for mirror in ("gh-proxy.com", "ghfast.top", "ghproxy.net"):
        assert generated.count(f"https://{mirror}/https://raw.githubusercontent.com/") == 34


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
