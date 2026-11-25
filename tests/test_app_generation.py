import pytest

from app.base import APPBase


class RecordingGenerator(APPBase):
    def __init__(self, fail_on_lite=False):
        self.calls = []
        self.fail_on_lite = fail_on_lite
        super().__init__([], [], {}, [], [], set(), "out/example.txt", "test")

    def generate(self, isLite=False):
        self.calls.append(isLite)
        if isLite and self.fail_on_lite:
            raise RuntimeError("synthetic generator failure")


def test_generate_all_emits_full_and_lite_even_when_lists_are_empty():
    generator = RecordingGenerator()

    generator.generateAll()

    assert generator.calls == [False, True]


def test_generate_all_propagates_format_generator_failure():
    generator = RecordingGenerator(fail_on_lite=True)

    with pytest.raises(RuntimeError, match="synthetic generator failure"):
        generator.generateAll()

    assert generator.calls == [False, True]

class AllowListGenerator(APPBase):
    def __init__(self):
        super().__init__(
            [],
            ["safe.example.com"],
            {},
            [],
            [],
            set(),
            "out/example.txt",
            "test",
        )

    def generate(self, isLite=False):
        pass


def test_lite_preserves_non_china_allow_exceptions():
    generator = AllowListGenerator()

    assert generator.unblockListLite == ["safe.example.com"]


def test_manual_threat_regression_domains_are_present_in_project_block_rules():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    expected_path = root / "tests" / "data" / "manual-block-domains.txt"
    rules_path = root / "rules" / "myblock.txt"
    expected_lines = [
        line.strip().lower()
        for line in expected_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    rules = {
        line.strip().lower()[2:-1]
        for line in rules_path.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("||") and line.strip().endswith("^")
    }

    assert expected_lines
    assert len(expected_lines) == len(set(expected_lines))
    assert set(expected_lines) <= rules
