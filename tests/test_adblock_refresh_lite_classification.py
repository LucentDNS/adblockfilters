from pathlib import Path


def test_refresh_builds_once_to_collect_domains_then_again_with_domestic_lite_scope(tmp_path, monkeypatch):
    import adblock

    calls = {"filter_generate": 0}

    class FakeReadMe:
        def __init__(self, _path):
            pass

        def getRules(self):
            return []

        def getRulesNames(self):
            return "test sources"

    class FakeUpdater:
        def __init__(self, rules):
            self.rules = rules

        def update(self, _path):
            return False, self.rules

    class FakeFilter:
        def __init__(self, _rules, domain_dir, _out_dir, _source_dir):
            self.domain_dir = Path(domain_dir)

        def generate(self, _names):
            calls["filter_generate"] += 1
            if calls["filter_generate"] == 1:
                (self.domain_dir / "domain.txt").write_text(
                    "service.example.cn\n", encoding="utf-8"
                )
            else:
                assert (self.domain_dir / "china.txt").read_text(
                    encoding="utf-8"
                ) == "service.example.cn\n"

    def fake_generate_china_list(domain_dir):
        path = Path(domain_dir) / "china.txt"
        path.write_text("service.example.cn\n", encoding="utf-8")
        return {
            "china_classified_domain_count": 1,
            "direct_classified_domain_count": 1,
            "retained_previous_dns_classified_domain_count": 0,
        }

    monkeypatch.setattr(adblock, "ReadMe", FakeReadMe)
    monkeypatch.setattr(adblock, "Updater", FakeUpdater)
    monkeypatch.setattr(adblock, "Filter", FakeFilter)
    monkeypatch.setattr(adblock, "generate_china_list", fake_generate_china_list)
    monkeypatch.chdir(tmp_path)

    adblock.ADBlock().refresh()

    assert calls["filter_generate"] == 2
