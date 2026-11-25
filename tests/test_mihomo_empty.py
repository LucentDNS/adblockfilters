from app.mihomo import Mihomo


def test_mihomo_writes_explicit_empty_payload_for_full_and_lite(tmp_path):
    output = tmp_path / "adblockmihomo.yaml"
    generator = Mihomo([], [], {}, [], [], set(), str(output), "test")

    generator.generateAll()

    full = output.read_text(encoding="utf-8")
    lite = (tmp_path / "adblockmihomolite.yaml").read_text(encoding="utf-8")

    assert "payload:\n" in full and "  []\n" in full
    assert "payload:\n" in lite and "  []\n" in lite
