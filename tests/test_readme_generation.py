from readme import ReadMe


def test_regenerated_readme_omits_obsolete_migration_announcement(tmp_path):
    readme_path = tmp_path / "README.md"
    readme = ReadMe(str(readme_path))

    readme.regenerate()

    generated = readme_path.read_text(encoding="utf-8")
    assert "重要公告" not in generated
    assert "20261120" not in generated
    assert "raw.githubusercontent.com/LucentDNS/adblockfilters/dist/" in generated
