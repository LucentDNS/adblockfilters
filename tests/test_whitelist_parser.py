from filter import Filter


def parse_whitelist(entries):
    instance = Filter.__new__(Filter)
    return instance._Filter__getWhiteDict(set(entries))


def test_plain_domain_exception_is_normalized_to_domain():
    result = parse_whitelist({"nimiq.com"})
    assert result == {"nimiq.com": {""}}


def test_adguard_domain_exception_without_modifiers_is_normalized():
    result = parse_whitelist({"||nimiq.com^"})
    assert result == {"nimiq.com": {""}}


def test_subdomain_exception_without_modifiers_is_normalized():
    result = parse_whitelist({"||pool.nimiq.watch^"})
    assert result == {"nimiq.watch": {"pool"}}


def test_modifier_bearing_browser_exception_is_not_a_dns_whitelist():
    result = parse_whitelist({"||nimiq.com^$third-party"})
    assert result == {}


def test_browser_path_and_wildcard_patterns_are_not_dns_whitelist_domains():
    result = parse_whitelist({"*/ad_", "||ad.", "youtube.com#%#scriptlet('example')"})
    assert result == {}


def test_whitelisted_subdomain_gets_exception_when_parent_is_blocked():
    instance = Filter.__new__(Filter)
    white_dict = parse_whitelist({"cdn.branch.io"})
    assert instance._Filter__getWhiteExceptions(white_dict, ["branch.io"]) == [
        "cdn.branch.io"
    ]


def test_unblocked_whitelist_domain_does_not_add_redundant_exception():
    instance = Filter.__new__(Filter)
    white_dict = parse_whitelist({"cdn.branch.io"})
    assert instance._Filter__getWhiteExceptions(white_dict, ["tracker.example.com"]) == []


def test_lite_filter_keeps_exact_china_domains_and_unrestricted_generic_rules():
    from app.adguard import AdGuard

    china = {"ad.qq.com"}
    rules = {
        "||ad.qq.com^": "ad.qq.com",
        "||ad.google.com^": "ad.google.com",
        "##.sponsored": None,
    }
    generator = AdGuard([], [], rules, list(rules), [], china, "out.txt", "test")

    assert generator.filterListLite == ["||ad.qq.com^", "##.sponsored"]


def test_lite_filter_domain_scopes_only_keep_china_or_unrestricted_rules():
    from app.adguard import AdGuard

    china = {"ad.qq.com", "qq.com"}
    rules = {
        "||ad.qq.com^": "ad.qq.com",
        "||ad.google.com^": "ad.google.com",
        "||tracker^$script,domain=mail.qq.com|~login.qq.com": None,
        "||tracker^$script,domain=google.com": None,
        "||tracker^$script,domain=~qq.com": None,
        "||tracker^$script": None,
    }
    generator = AdGuard([], [], rules, list(rules), [], china, "out.txt", "test")

    assert set(generator.filterListLite) == {
        "||ad.qq.com^",
        "||tracker^$script,domain=mail.qq.com|~login.qq.com",
        "||tracker^$script,domain=~qq.com",
        "||tracker^$script",
    }


def test_microsoft_defender_core_mobile_endpoints_are_exact_whitelist_entries():
    from pathlib import Path

    root = Path(__file__).parents[1]
    entries = {
        line.strip()
        for line in (root / "rules" / "white.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "!"))
    }
    expected = {
        "mobile.events.data.microsoft.com",
        "au-mobile.events.data.microsoft.com",
        "eu-mobile.events.data.microsoft.com",
        "uk-mobile.events.data.microsoft.com",
        "us-mobile.events.data.microsoft.com",
    }

    assert expected <= entries
    assert "events.data.microsoft.com" not in entries

    parsed = parse_whitelist(entries)
    normalized = {
        (f"{subdomain}.{fld}" if subdomain else fld)
        for fld, subdomains in parsed.items()
        for subdomain in subdomains
    }
    assert expected <= normalized


def test_service_whitelist_entries_are_scoped_to_confirmed_hosts():
    from pathlib import Path

    root = Path(__file__).parents[1]
    entries = {
        line.strip()
        for line in (root / "rules" / "white.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "!"))
    }
    expected_360_hosts = {
        "sdk.live.360.cn",
        "video-cloudcontrol.iot.360.cn",
        "mdm.openapi.360.cn",
        "fastconn-api.iot.360.cn",
        "app.home.360.cn",
        "video-licenseauth.iot.360.cn",
        "dp.push.dc.360.cn",
    }

    assert expected_360_hosts <= entries
    assert "ai.shouji.360.cn" in entries
    assert "sms.ads.heytapmobi.com" in entries
    assert "360.cn" not in entries
    assert "shouji.360.cn" not in entries
    assert "ads.heytapmobi.com" not in entries
    assert "tanx.com" not in entries
    assert "17u.cn" not in entries
    assert "wx.17u.cn" in entries
    assert "go.sohu.com" not in entries
    assert "txt.go.sohu.com" in entries
    assert "apps.coloros.com" not in entries
    assert "iwisdom.apps.coloros.com" in entries
    assert "browser.miui.com" not in entries
    assert "upqzfile.com" not in entries
    assert "v6.pic.upqzfile.com" in entries
    assert {
        "api.browser.miui.com",
        "httpdns.browser.miui.com",
        "r.browser.miui.com",
        "security.browser.miui.com",
    } <= entries
