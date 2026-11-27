from readme import Rule


def test_production_refresh_updates_all_configured_sources_without_dns_provenance(
    tmp_path, monkeypatch
):
    import adblock

    dns_rule = Rule(
        "AdGuard DNS filter", "dns", "https://example.com/list.txt", "2026/11/24"
    )
    browser_rule = Rule(
        "AdGuard Base filter", "filter", "https://example.org/base.txt", "2026/11/24"
    )
    rules = [dns_rule, browser_rule]
    calls = {}

    class FakeReadMe:
        def __init__(self, _path):
            pass

        def getRules(self):
            return rules

        def getRulesNames(self):
            return "test sources"

    class FakeUpdater:
        def __init__(self, rule_list):
            calls["rules"] = rule_list

        def update(self, path):
            calls["path"] = path
            return True, rules

    class FakeFilter:
        def __init__(self, rule_list, domain_path, out_path, source_path):
            calls["filter_args"] = (rule_list, domain_path, out_path, source_path)

        def generate(self, _names):
            calls["generated"] = True

    monkeypatch.setattr(adblock, "ReadMe", FakeReadMe)
    monkeypatch.setattr(adblock, "Updater", FakeUpdater)
    monkeypatch.setattr(adblock, "Filter", FakeFilter)
    monkeypatch.setattr(adblock, "update_tld_names", lambda: None)
    monkeypatch.chdir(tmp_path)

    instance = adblock.ADBlock()
    instance.refresh()

    assert calls["rules"] == rules
    assert calls["path"] == instance.sourceDir
    assert calls["generated"] is True
