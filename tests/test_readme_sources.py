import json
from pathlib import Path

import pytest

from readme import ReadMe


def test_repository_source_manifest_is_unique_and_https_only():
    root = Path(__file__).parents[1]
    rules = ReadMe(str(root / "README.md")).getRules()
    manifest = json.loads((root / "sources.json").read_text(encoding="utf-8"))
    readme = (root / "README.md").read_text(encoding="utf-8")

    assert manifest["version"] == 1
    assert len(manifest["sources"]) == 15
    assert "## 上游来源" not in readme
    assert len(rules) == 15
    assert all(rule.type in {"filter", "dnsfilter", "dns", "host"} for rule in rules)
    assert all(rule.url.startswith("https://") for rule in rules)
    assert len({rule.name for rule in rules}) == len(rules)
    assert len({rule.filename for rule in rules}) == len(rules)
    assert len({rule.url for rule in rules}) == len(rules)


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
