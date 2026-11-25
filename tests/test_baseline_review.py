from pathlib import Path

from scripts.review_baseline_only import (
    classify_groups,
    classify_rrtype_results,
    read_candidates,
    valid_domain,
)


def test_only_two_group_nxdomain_is_classified_as_dead():
    assert classify_groups(["not_found", "not_found"]) == "nxdomain"
    assert classify_groups(["not_found", "no_address"]) == "inconclusive"
    assert classify_groups(["not_found", "unknown"]) == "inconclusive"


def test_any_successful_dns_group_keeps_domain_active():
    assert classify_groups(["resolved", "not_found"]) == "resolved"
    assert classify_groups(["unknown", "resolved"]) == "resolved"


def test_no_address_requires_both_groups():
    assert classify_groups(["no_address", "no_address"]) == "no_address"
    assert classify_groups(["no_address", "unknown"]) == "inconclusive"


def test_mixed_a_and_aaaa_nxdomain_responses_are_inconclusive():
    assert classify_rrtype_results(["not_found", "not_found"]) == "not_found"
    assert classify_rrtype_results(["not_found", "no_address"]) == "unknown"
    assert classify_rrtype_results(["no_address", "unknown"]) == "unknown"
    assert classify_rrtype_results(["resolved", "not_found"]) == "resolved"


def test_candidate_parser_normalizes_deduplicates_and_rejects_patterns(tmp_path: Path):
    path = tmp_path / "baseline-only.txt"
    path.write_text(
        "! generated report\nExample.COM\nexample.com\n*.example.net\n"
        "invalid-domain\nmail.example.org.\n",
        encoding="utf-8",
    )

    domains, invalid, candidate_count = read_candidates(path)

    assert domains == ["example.com", "mail.example.org"]
    assert invalid == ["*.example.net", "invalid-domain"]
    assert candidate_count == 5


def test_domain_validator_rejects_empty_and_non_domain_inputs():
    assert valid_domain("valid.example")
    assert not valid_domain("localhost")
    assert not valid_domain("bad..example")
    assert not valid_domain("bad.example.")
    assert not valid_domain("*.example")
    assert not valid_domain("example/path")
