import json

import pytest

from readme import ReadMe


def _manifest(tmp_path, sources):
    readme = tmp_path / "README.md"
    readme.write_text("# test\n", encoding="utf-8")
    (tmp_path / "sources.json").write_text(
        json.dumps({"version": 1, "sources": sources}),
        encoding="utf-8",
    )
    return readme


def _source(name, **extra):
    return {
        "name": name,
        "type": "dns",
        "url": f"https://example.com/{name}.txt",
        "latest": "2026/11/26",
        **extra,
    }


def test_manifest_defaults_sources_to_enabled(tmp_path):
    readme = _manifest(tmp_path, [_source("default"), _source("enabled", enabled=True)])

    rules = ReadMe(str(readme)).getRules()

    assert [rule.name for rule in rules] == ["default", "enabled"]


def test_manifest_skips_temporarily_disabled_source(tmp_path):
    readme = _manifest(
        tmp_path,
        [_source("active"), _source("paused", enabled=False)],
    )

    rules = ReadMe(str(readme)).getRules()

    assert [rule.name for rule in rules] == ["active"]


@pytest.mark.parametrize("enabled", ["false", 0, 1, None, []])
def test_manifest_rejects_non_boolean_enabled_value(tmp_path, enabled):
    readme = _manifest(tmp_path, [_source("invalid", enabled=enabled)])

    with pytest.raises(ValueError, match="enabled must be a boolean"):
        ReadMe(str(readme)).getRules()


def test_manifest_rejects_unknown_source_fields(tmp_path):
    readme = _manifest(tmp_path, [_source("invalid", enabld=False)])

    with pytest.raises(ValueError, match="may optionally contain enabled"):
        ReadMe(str(readme)).getRules()


def test_manifest_rejects_all_sources_disabled(tmp_path):
    readme = _manifest(tmp_path, [_source("paused", enabled=False)])

    with pytest.raises(ValueError, match="at least one enabled source"):
        ReadMe(str(readme)).getRules()
