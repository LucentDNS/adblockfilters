import pytest

from blacklist import _ip_in_ranges, _merge_ip_ranges


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        (167772161, True),   # 10.0.0.1
        (167772160, True),   # start of 10.0.0.0/8
        (184549375, True),   # end of 10.0.0.0/8
        (184549376, False),  # immediately after 10.0.0.0/8
        (3232235521, True),  # 192.168.0.1
        (134744072, False), # 8.8.8.8
        (0, False),
    ],
)
def test_ip_in_ranges_boundaries_and_known_addresses(ip, expected):
    starts = [167772160, 3232235520]
    ends = [184549375, 3232301055]
    assert _ip_in_ranges(ip, starts, ends) is expected


def test_merge_ip_ranges_sorts_and_merges_overlapping_or_adjacent_ranges():
    starts, ends = _merge_ip_ranges([
        (50, 60),
        (10, 20),
        (15, 30),
        (31, 40),
        (100, 110),
    ])

    assert starts == [10, 50, 100]
    assert ends == [40, 60, 110]
    assert _ip_in_ranges(35, starts, ends) is True
    assert _ip_in_ranges(45, starts, ends) is False


def test_merge_ip_ranges_rejects_invalid_ipv4_bounds():
    with pytest.raises(ValueError, match="Invalid IPv4 range"):
        _merge_ip_ranges([(100, 50)])
    with pytest.raises(ValueError, match="Invalid IPv4 range"):
        _merge_ip_ranges([(-1, 10)])
    with pytest.raises(ValueError, match="Invalid IPv4 range"):
        _merge_ip_ranges([(0, 0x100000000)])
