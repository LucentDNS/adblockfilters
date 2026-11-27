from blacklist import DNS_VALIDATION_BATCH_SIZE, _iter_batches


def test_dns_validation_batch_size_is_bounded():
    assert 0 < DNS_VALIDATION_BATCH_SIZE <= 1000


def test_dns_validation_batches_cover_all_domains_without_oversized_batches():
    domains = list(range(403_703))
    batches = list(_iter_batches(domains, DNS_VALIDATION_BATCH_SIZE))
    assert len(batches) == (len(domains) + DNS_VALIDATION_BATCH_SIZE - 1) // DNS_VALIDATION_BATCH_SIZE
    assert all(0 < len(batch) <= DNS_VALIDATION_BATCH_SIZE for batch in batches)
    assert [item for batch in batches for item in batch] == domains


def test_dns_validation_batch_iterator_rejects_zero_batch_size():
    try:
        list(_iter_batches([1], 0))
    except ValueError as exc:
        assert "positive" in str(exc)
    else:
        raise AssertionError("zero batch size must fail")
