from filter import _build_exact_block_list, _build_lite_block_list


def test_lite_keeps_domestic_child_after_full_parent_compression():
    block_domains = {
        "example.com",
        "api.example.com",
        "ads.example.net",
        "dead.example.org",
    }
    china_domains = {
        "api.example.com",
        "ads.example.net",
        "dead.example.org",
    }
    allow_domains = {"example.net"}
    blacklist = {"dead.example.org"}

    assert _build_lite_block_list(
        block_domains, china_domains, allow_domains, blacklist
    ) == ["api.example.com"]


def test_lite_does_not_promote_a_non_domestic_parent_or_allowlisted_host():
    block_domains = {"example.com", "api.example.com", "safe.example.com"}
    china_domains = {"api.example.com", "safe.example.com"}
    allow_domains = {"safe.example.com"}
    blacklist = set()

    assert _build_lite_block_list(
        block_domains, china_domains, allow_domains, blacklist
    ) == ["api.example.com"]



def test_lite_respects_project_whitelist_parent_and_case_insensitive_domains():
    assert _build_lite_block_list(
        {"tracker.example.com", "ads.example.net"},
        {"TRACKER.EXAMPLE.COM", "ads.example.net"},
        {"example.com"},
        set(),
    ) == ["ads.example.net"]



def test_hosts_full_exact_list_retains_children_after_suffix_compression():
    assert _build_exact_block_list(
        {"example.com", "api.example.com", "ads.example.net"},
        set(),
        set(),
    ) == ["ads.example.net", "api.example.com", "example.com"]


def test_hosts_full_exact_list_respects_parent_allowlist():
    assert _build_exact_block_list(
        {"example.com", "api.example.com", "other.example.net"},
        {"example.com"},
        set(),
    ) == ["other.example.net"]
