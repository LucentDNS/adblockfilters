from scripts.audit_sources import covered_by_whitelist


def test_project_whitelist_covers_exact_domain_and_children():
    whitelist = {"heads-fa.spotify.com", "example.com"}
    assert covered_by_whitelist("heads-fa.spotify.com", whitelist)
    assert covered_by_whitelist("cdn.example.com", whitelist)
    assert not covered_by_whitelist("api.spotify.com", whitelist)
    assert not covered_by_whitelist("example.net", whitelist)
from scripts.audit_sources import unexplained_absent_baseline_domains


def test_absent_baseline_domains_already_whitelisted_are_not_reported_unexplained():
    source_absent = {
        "https-filtering-check.adtidy.org",
        "api.statsig.com",
        "did.kr",
    }
    blacklist = {"did.kr"}
    whitelist = {"https-filtering-check.adtidy.org"}
    source_allow = set()

    assert unexplained_absent_baseline_domains(
        source_absent, blacklist, whitelist, source_allow
    ) == {"api.statsig.com"}


def test_absent_baseline_domains_covered_by_parent_whitelist_are_explained():
    source_absent = {"cdn.example.com", "api.other.com"}
    whitelist_covered = {
        domain for domain in source_absent
        if covered_by_whitelist(domain, {"example.com"})
    }

    assert unexplained_absent_baseline_domains(
        source_absent, set(), whitelist_covered, set()
    ) == {"api.other.com"}
