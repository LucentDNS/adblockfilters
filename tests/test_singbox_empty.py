import json

from app.singbox import SingBox


def test_singbox_writes_valid_empty_full_and_lite_files(tmp_path):
    output = tmp_path / "adblocksingbox.json"
    generator = SingBox([], [], {}, [], [], set(), str(output), "test")

    generator.generateAll()

    full = json.loads(output.read_text(encoding="utf-8"))
    lite_path = tmp_path / "adblocksingboxlite.json"
    lite = json.loads(lite_path.read_text(encoding="utf-8"))

    assert full["version"] == 3
    assert full["rules"][0]["domain_suffix"] == []
    assert lite["version"] == 3
    assert lite["rules"][0]["domain_suffix"] == []
