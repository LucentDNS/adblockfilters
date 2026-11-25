from pathlib import Path


def test_dns_validation_uses_separate_non_filtering_regional_groups():
    config = Path(__file__).parents[1].joinpath("smartdns.conf").read_text(encoding="utf-8")

    assert "bind 127.0.0.1:5053 -group domestic" in config
    assert "bind 127.0.0.1:5054 -group global" in config

    for provider in (
        "https://doh.pub/dns-query",
        "180.76.76.76",
        "180.184.1.1",
        "8.8.8.8",
        "9.9.9.10",
        "1.1.1.1",
    ):
        assert provider in config

    assert config.count("-exclude-default-group") == 6
    assert "9.9.9.11" not in config  # Quad9 threat-blocking resolver
    assert "101.226.4.6" not in config  # 360 security-filtering DNS
    assert "114.114.114.114" not in config  # 114DNS standard resolver has ad filtering
