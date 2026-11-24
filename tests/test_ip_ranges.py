import pytest

from blacklist import _ip_in_ranges


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
