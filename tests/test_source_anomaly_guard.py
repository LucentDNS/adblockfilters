from pathlib import Path

from scripts.check_source_anomalies import active_rule_count, find_anomalies


def _write(path: Path, count: int) -> None:
    path.write_text(
        "! generated test list\n"
        + "".join(f"||host-{index}.example^\n" for index in range(count)),
        encoding="utf-8",
    )


def test_detects_catastrophic_source_shrinkage(tmp_path: Path) -> None:
    previous = tmp_path / "previous"
    current = tmp_path / "current"
    previous.mkdir()
    current.mkdir()
    _write(previous / "source.txt", 500)
    _write(current / "source.txt", 200)

    anomalies = find_anomalies(previous, current)

    assert len(anomalies) == 1
    assert "500 -> 200" in anomalies[0]


def test_allows_normal_source_changes(tmp_path: Path) -> None:
    previous = tmp_path / "previous"
    current = tmp_path / "current"
    previous.mkdir()
    current.mkdir()
    _write(previous / "source.txt", 500)
    _write(current / "source.txt", 350)

    assert find_anomalies(previous, current) == []


def test_ignores_small_sources_and_comments(tmp_path: Path) -> None:
    previous = tmp_path / "previous"
    current = tmp_path / "current"
    previous.mkdir()
    current.mkdir()
    _write(previous / "small.txt", 100)
    _write(current / "small.txt", 0)
    (previous / "comments.txt").write_text("! comment\n# comment\n", encoding="utf-8")
    (current / "comments.txt").write_text("! comment\n# comment\n", encoding="utf-8")

    assert active_rule_count(previous / "comments.txt") == 0
    assert find_anomalies(previous, current) == []
