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
