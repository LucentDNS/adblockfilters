from blacklist import (
    DNS_BLOCK_POLICY_VERSION,
    DOMAIN,
    DomainDatabase,
    _apply_dns_block_policy_version,
    _needs_dns_validation,
)


def test_policy_upgrade_resets_only_cached_nxdomain_decisions(tmp_path):
    database = DomainDatabase(str(tmp_path / "domain.db"))
    database.updateALL(
        [
            (
                "blocked.example",
                "blocked.example",
                None,
                None,
                None,
                1,
                0,
                100,
                None,
                "example",
            ),
            (
                "resolved.example",
                "resolved.example",
                None,
                None,
                None,
                0,
                1,
                200,
                "203.0.113.10",
                "example",
            ),
        ]
    )

    assert _apply_dns_block_policy_version(database) == 1
    rows = {row[0]: row for row in database.getAll()}

    assert rows["blocked.example"][6] == 0
    assert rows["blocked.example"][8] == 0
    assert rows["blocked.example"][9] is None
    assert rows["resolved.example"][6] == 0
    assert rows["resolved.example"][8] == 200
    assert rows["resolved.example"][9] == "203.0.113.10"
    assert database.getMeta("dns_block_policy_version") == DNS_BLOCK_POLICY_VERSION
    database.close()


def test_policy_upgrade_is_idempotent(tmp_path):
    database = DomainDatabase(str(tmp_path / "domain.db"))
    database.setMeta("dns_block_policy_version", DNS_BLOCK_POLICY_VERSION)
    database.updateALL(
        [
            (
                "blocked.example",
                "blocked.example",
                None,
                None,
                None,
                1,
                0,
                100,
                None,
                "example",
            )
        ]
    )

    assert _apply_dns_block_policy_version(database) == 0
    row = next(iter(database.getAll()))
    assert row[6] == 1
    assert row[8] == 100
    database.close()


def test_inconclusive_dns_results_use_the_negative_retry_cooldown(monkeypatch):
    now = 1_000_000
    monkeypatch.setattr("blacklist.time.time", lambda: now)
    domain = DOMAIN("unknown.example", tld="example", fld="unknown.example", timeStamp=1)

    domain.setCheckedAtNow()
    last_checked = domain.getTimeStamp()

    assert not _needs_dns_validation([], last_checked, now + 5 * 60 * 60)
    assert _needs_dns_validation([], last_checked, now + 6 * 60 * 60 + 1)


def test_positive_dns_cache_keeps_its_long_refresh_window():
    now = 2_000_000
    assert not _needs_dns_validation(["203.0.113.10"], now, now + 35 * 86400)
    assert _needs_dns_validation(["203.0.113.10"], now, now + 36 * 86400 + 1)
