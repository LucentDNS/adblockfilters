from scripts.audit_sources import covered_by_whitelist


def test_project_whitelist_covers_exact_domain_and_children():
    whitelist = {"heads-fa.spotify.com", "example.com"}
    assert covered_by_whitelist("heads-fa.spotify.com", whitelist)
    assert covered_by_whitelist("cdn.example.com", whitelist)
    assert not covered_by_whitelist("api.spotify.com", whitelist)
    assert not covered_by_whitelist("example.net", whitelist)
