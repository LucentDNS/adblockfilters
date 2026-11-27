from blacklist import DNS_VALIDATION_BATCH_SIZE


def test_dns_validation_batch_size_is_bounded():
    assert 0 < DNS_VALIDATION_BATCH_SIZE <= 1000


def test_dns_validation_batching_does_not_scale_task_count_with_input_size():
    total_domains = 403_703
    batch_count = (total_domains + DNS_VALIDATION_BATCH_SIZE - 1) // DNS_VALIDATION_BATCH_SIZE
    assert batch_count > 1
    assert DNS_VALIDATION_BATCH_SIZE < total_domains
