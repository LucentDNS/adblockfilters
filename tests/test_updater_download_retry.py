import asyncio

import httpx
import pytest

from updater import Updater


class SequenceClient:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    async def get(self, url):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def response(status, url):
    return httpx.Response(
        status,
        request=httpx.Request("GET", url),
        headers={"Retry-After": "0"},
        content=b"rules",
    )


def no_wait(monkeypatch):
    async def sleep(_seconds):
        return None

    monkeypatch.setattr("updater.asyncio.sleep", sleep)


def test_raw_github_retries_temporary_http_status(monkeypatch):
    no_wait(monkeypatch)
    url = "https://raw.githubusercontent.com/example/rules/main/list.txt"
    client = SequenceClient([response(503, url), response(200, url)])

    result = asyncio.run(Updater([])._Updater__GetDownloadResponse(client, url))

    assert result.status_code == 200
    assert client.calls == 2


def test_raw_github_retries_transient_network_error(monkeypatch):
    no_wait(monkeypatch)
    url = "https://raw.githubusercontent.com/example/rules/main/list.txt"
    request = httpx.Request("GET", url)
    client = SequenceClient([
        httpx.ConnectTimeout("temporary timeout", request=request),
        response(200, url),
    ])

    result = asyncio.run(Updater([])._Updater__GetDownloadResponse(client, url))

    assert result.status_code == 200
    assert client.calls == 2


def test_non_raw_source_is_not_retried(monkeypatch):
    no_wait(monkeypatch)
    url = "https://example.com/list.txt"
    client = SequenceClient([response(503, url), response(200, url)])

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(Updater([])._Updater__GetDownloadResponse(client, url))

    assert client.calls == 1


def test_raw_github_does_not_retry_permanent_http_status(monkeypatch):
    no_wait(monkeypatch)
    url = "https://raw.githubusercontent.com/example/rules/main/list.txt"
    client = SequenceClient([response(404, url), response(200, url)])

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(Updater([])._Updater__GetDownloadResponse(client, url))

    assert client.calls == 1
