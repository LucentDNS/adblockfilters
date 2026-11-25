import pytest

from blacklist import BlackList


def test_generate_fails_when_domain_input_is_unavailable(monkeypatch):
    instance = BlackList.__new__(BlackList)

    def fail_domain_input():
        raise RuntimeError("domain source unavailable")

    monkeypatch.setattr(instance, "_BlackList__getDomainDict", fail_domain_input)

    with pytest.raises(RuntimeError, match="domain source unavailable"):
        instance.generate()


def test_generate_blacklist_write_errors_are_not_suppressed(tmp_path):
    instance = BlackList.__new__(BlackList)
    instance._BlackList__blacklistFile = str(tmp_path / "missing" / "black.txt")

    with pytest.raises(OSError):
        instance._BlackList__generateBlackList(["dead.example"])


def test_generate_china_list_write_errors_are_not_suppressed(tmp_path):
    instance = BlackList.__new__(BlackList)
    instance._BlackList__ChinalistFile = str(tmp_path / "missing" / "china.txt")

    with pytest.raises(OSError):
        instance._BlackList__generateChinaList(["example.cn"])


def test_china_direct_source_must_exist_or_have_a_valid_cache(tmp_path, monkeypatch):
    instance = BlackList.__new__(BlackList)
    instance._BlackList__directlistFile = str(tmp_path / "direct.txt")
    instance._BlackList__directlistUrl = "https://example.invalid/direct.txt"
    monkeypatch.setattr(instance, "_BlackList__download", lambda *_: False)

    with pytest.raises(RuntimeError, match="missing or empty"):
        instance._BlackList__getDomainSet_CN()


def test_blacklist_abnormal_threshold_blocks_mass_dns_failure():
    from blacklist import _blacklist_abnormal

    assert _blacklist_abnormal(195001, 390000) is True
    assert _blacklist_abnormal(195000, 390000) is False
    assert _blacklist_abnormal(61000, 390000) is False
    assert _blacklist_abnormal(0, 0) is False


def test_empty_blacklist_overwrites_stale_previous_state(tmp_path):
    path = tmp_path / "black.txt"
    path.write_text("stale.example\n", encoding="utf-8")
    instance = BlackList.__new__(BlackList)
    instance._BlackList__blacklistFile = str(path)

    instance._BlackList__generateBlackList([])

    assert path.read_text(encoding="utf-8") == ""


def test_empty_china_list_overwrites_stale_previous_state(tmp_path):
    path = tmp_path / "china.txt"
    path.write_text("stale.example.cn\n", encoding="utf-8")
    instance = BlackList.__new__(BlackList)
    instance._BlackList__ChinalistFile = str(path)

    instance._BlackList__generateChinaList([])

    assert path.read_text(encoding="utf-8") == ""
