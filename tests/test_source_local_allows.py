from filter import _apply_source_local_allows


def test_source_allow_does_not_cancel_another_sources_block():
    source_a_blocks = {"example.com": {""}}
    source_a_allows = {"example.com": {""}}
    source_b_blocks = {"example.com": {""}}

    source_a_effective = _apply_source_local_allows(
        source_a_blocks, source_a_allows
    )
    source_b_effective = _apply_source_local_allows(
        source_b_blocks, {}
    )

    # A's own block is excepted, but B's independent block survives aggregation.
    assert source_a_effective == {}
    assert source_b_effective == {"example.com": {""}}
    assert source_a_effective.get("example.com", set()) | source_b_effective.get(
        "example.com", set()
    ) == {""}


def test_parent_allow_is_scoped_to_descendants_within_source():
    blocks = {
        "example.com": {"", "ads"},
        "other.net": {"tracker"},
    }
    allows = {"example.com": {""}}

    assert _apply_source_local_allows(blocks, allows) == {
        "other.net": {"tracker"}
    }


def test_subdomain_allow_does_not_cancel_parent_or_siblings():
    blocks = {
        "example.com": {"", "ads", "cdn"},
    }
    allows = {"example.com": {"ads"}}

    assert _apply_source_local_allows(blocks, allows) == {
        "example.com": {"", "cdn"}
    }
