import pytest

from blacklist import BlackList


def test_generate_fails_when_domain_input_is_unavailable(monkeypatch):
    instance = BlackList.__new__(BlackList)

    def fail_domain_input():
        raise RuntimeError("domain source unavailable")

    instance._BlackList__db = object()
    monkeypatch.setattr("blacklist._apply_dns_block_policy_version", lambda _database: 0)
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


def _fake_http_client(monkeypatch, *, content_type, body):
    import blacklist as blacklist_module

    class Response:
        headers = {"Content-Type": content_type}
        content = body

        @staticmethod
        def raise_for_status():
            return None

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        @staticmethod
        def get(_url):
            return Response()

    monkeypatch.setattr(blacklist_module.httpx, "Client", Client)


def test_non_text_dns_source_response_is_rejected_without_replacing_cache(tmp_path, monkeypatch):
    instance = BlackList.__new__(BlackList)
    target = tmp_path / "direct.txt"
    target.write_text("domain:qq.com\n", encoding="utf-8")
    _fake_http_client(monkeypatch, content_type="text/html; charset=utf-8", body=b"<html>error</html>")

    assert instance._BlackList__download(str(target), "https://example.invalid/direct.txt") is False
    assert target.read_text(encoding="utf-8") == "domain:qq.com\n"
    assert not (tmp_path / "direct.txt.download").exists()


def test_empty_text_dns_source_response_is_rejected_without_replacing_cache(tmp_path, monkeypatch):
    instance = BlackList.__new__(BlackList)
    target = tmp_path / "ipv4_china.txt"
    target.write_text("1.0.1.0-1.0.3.255\n", encoding="utf-8")
    _fake_http_client(monkeypatch, content_type="text/plain; charset=utf-8", body=b"")

    assert instance._BlackList__download(str(target), "https://example.invalid/ipv4_china.txt") is False
    assert target.read_text(encoding="utf-8") == "1.0.1.0-1.0.3.255\n"
    assert not (tmp_path / "ipv4_china.txt.download").exists()


def test_html_error_page_with_text_plain_header_is_rejected(tmp_path, monkeypatch):
    instance = BlackList.__new__(BlackList)
    target = tmp_path / "direct.txt"
    target.write_text("domain:qq.com\n", encoding="utf-8")
    _fake_http_client(monkeypatch, content_type="text/plain", body=b"<!DOCTYPE html><html>error</html>")

    assert instance._BlackList__download(str(target), "https://example.invalid/direct.txt") is False
    assert target.read_text(encoding="utf-8") == "domain:qq.com\n"
    assert not (tmp_path / "direct.txt.download").exists()


def test_valid_text_response_atomically_replaces_cache(tmp_path, monkeypatch):
    instance = BlackList.__new__(BlackList)
    target = tmp_path / "direct.txt"
    target.write_text("domain:old.example\n", encoding="utf-8")
    _fake_http_client(monkeypatch, content_type="text/plain; charset=utf-8", body=b"domain:new.example\n")

    assert instance._BlackList__download(str(target), "https://example.invalid/direct.txt") is True
    assert target.read_text(encoding="utf-8") == "domain:new.example\n"
    assert not (tmp_path / "direct.txt.download").exists()
