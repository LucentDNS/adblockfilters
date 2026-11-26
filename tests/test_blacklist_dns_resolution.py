import asyncio

from dns.resolver import NXDOMAIN, NoAnswer

from blacklist import (
    BlackList,
    DNS_NEGATIVE_RECHECK_SECONDS,
    DNS_VALIDATION_PORTS,
    DNS_POSITIVE_REFRESH_SECONDS,
    _needs_dns_validation,
)


class FakeResolver:
    def __init__(self, answers):
        self.answers = answers

    async def resolve(self, qname, rdtype):
        value = self.answers.get(rdtype)
        if isinstance(value, Exception):
            raise value
        if value is None:
            raise LookupError(f"no {rdtype} record")
        return value


def _fake_resolvers(answers):
    upstreams = answers if isinstance(answers, list) else [answers] * len(DNS_VALIDATION_PORTS)
    return [FakeResolver(group) for group in upstreams]


def resolve(answers):
    instance = BlackList.__new__(BlackList)
    return asyncio.run(instance._BlackList__resolve(_fake_resolvers(answers), "example.test"))


class DummyDomain:
    def __init__(self, initially_blocked=False, ip_list=None):
        self.domain = "example.test"
        self.ip = None
        self.port = None
        self.ip_list = list(ip_list or [])
        self.timestamp = 100
        self.blocked = initially_blocked

    def setIPList(self, values):
        self.ip_list = values

    def getIPList(self):
        return self.ip_list

    def setBlock(self, value):
        self.blocked = value

    def setCheckedAtNow(self):
        self.timestamp = 200


def pingx(answers, initially_blocked=False):
    instance = BlackList.__new__(BlackList)
    domain = DummyDomain(initially_blocked)
    asyncio.run(instance._BlackList__pingx(
        _fake_resolvers(answers), domain, asyncio.Semaphore(1)
    ))
    return domain


def test_aaaa_only_domain_is_not_marked_unresolved():
    assert resolve({"A": NoAnswer(), "AAAA": ["2001:db8::1"]}) == (
        ["2001:db8::1"], "resolved"
    )


def test_a_and_aaaa_answers_are_both_retained():
    assert resolve({"A": ["192.0.2.1"], "AAAA": ["2001:db8::1"]}) == (
        ["192.0.2.1", "2001:db8::1"], "resolved"
    )


def test_duplicate_answers_are_removed():
    assert resolve({"A": ["192.0.2.1"], "AAAA": ["192.0.2.1"]}) == (
        ["192.0.2.1"], "resolved"
    )


def test_one_query_failure_does_not_discard_other_family():
    assert resolve({"A": TimeoutError("A timeout"), "AAAA": ["2001:db8::1"]}) == (
        ["2001:db8::1"], "resolved"
    )


def test_two_successful_nodata_responses_are_definitive():
    assert resolve({"A": NoAnswer(), "AAAA": NoAnswer()}) == ([], "no_address")


def test_nxdomain_and_timeout_for_different_record_types_are_inconclusive():
    assert resolve({"A": NXDOMAIN(), "AAAA": TimeoutError("AAAA timeout")}) == (
        [], "unknown"
    )


def test_all_five_upstreams_must_return_nxdomain_for_both_record_types():
    assert resolve({"A": NXDOMAIN(), "AAAA": NXDOMAIN()}) == ([], "not_found")


def test_two_transient_failures_are_unknown_not_dead():
    assert resolve({"A": TimeoutError("A timeout"), "AAAA": TimeoutError("AAAA timeout")}) == (
        [], "unknown"
    )


def test_nodata_plus_timeout_is_unknown_not_dead():
    assert resolve({"A": NoAnswer(), "AAAA": TimeoutError("AAAA timeout")}) == (
        [], "unknown"
    )


def test_other_resolver_errors_are_unknown():
    assert resolve({"A": LookupError("resolver failure"), "AAAA": LookupError("resolver failure")}) == (
        [], "unknown"
    )

def test_nodata_for_a_and_aaaa_does_not_blacklist_a_valid_name():
    domain = pingx({"A": NoAnswer(), "AAAA": NoAnswer()}, initially_blocked=True)
    assert domain.blocked is False


def test_nxdomain_is_blacklisted_only_when_both_record_types_are_nxdomain():
    domain = pingx({"A": NXDOMAIN(), "AAAA": NXDOMAIN()})
    assert domain.blocked is True


def test_unknown_dns_result_preserves_previous_state():
    domain = pingx(
        {"A": TimeoutError("A timeout"), "AAAA": TimeoutError("AAAA timeout")},
        initially_blocked=True
    )
    assert domain.blocked is True


def test_inconclusive_dns_does_not_extend_a_positive_cache_timestamp():
    instance = BlackList.__new__(BlackList)
    domain = DummyDomain(ip_list=["192.0.2.10"])
    resolvers = _fake_resolvers(
        {"A": TimeoutError("A timeout"), "AAAA": TimeoutError("AAAA timeout")}
    )

    asyncio.run(instance._BlackList__pingx(resolvers, domain, asyncio.Semaphore(1)))

    assert domain.ip_list == ["192.0.2.10"]
    assert domain.timestamp == 100


def test_inconclusive_dns_sets_retry_cooldown_for_empty_cache():
    domain = pingx(
        {"A": TimeoutError("A timeout"), "AAAA": TimeoutError("AAAA timeout")}
    )
    assert domain.ip_list == []
    assert domain.timestamp == 200




def test_new_domains_are_validated_immediately():
    assert _needs_dns_validation([], 100, 100, is_new=True) is True


def test_recent_negative_answers_are_not_repeated_in_duplicate_runs():
    assert _needs_dns_validation([], 100, 100 + 300, is_new=False) is False


def test_negative_answers_are_rechecked_after_cooldown():
    assert _needs_dns_validation(
        [], 100, 100 + DNS_NEGATIVE_RECHECK_SECONDS + 1, is_new=False
    ) is True


def test_positive_answers_are_refreshed_after_36_days():
    assert _needs_dns_validation(
        ["192.0.2.1"], 100, 100 + DNS_POSITIVE_REFRESH_SECONDS + 1
    ) is True


def test_recent_positive_answers_are_not_rechecked():
    assert _needs_dns_validation(["192.0.2.1"], 100, 100 + 3600) is False


def test_domain_input_normalizes_leading_dots_and_ip_literals(tmp_path):
    source = tmp_path / "domain.txt"
    source.write_text(".51.77.227.98\n.Example.COM.\n", encoding="utf-8")

    instance = BlackList.__new__(BlackList)
    instance._BlackList__domainlistFile = str(source)
    domains = instance._BlackList__getDomainDict()

    assert set(domains) == {"51.77.227.98", "example.com"}
    assert domains["51.77.227.98"].ip == "51.77.227.98"
    assert domains["example.com"].fld == "example.com"


def test_domain_input_deduplicates_normalized_variants(tmp_path):
    source = tmp_path / "domain.txt"
    source.write_text(".Example.COM\nexample.com.\nEXAMPLE.com\n", encoding="utf-8")

    instance = BlackList.__new__(BlackList)
    instance._BlackList__domainlistFile = str(source)
    domains = instance._BlackList__getDomainDict()

    assert list(domains) == ["example.com"]


def test_nxdomain_plus_valid_other_family_keeps_domain():
    assert resolve({"A": NXDOMAIN(), "AAAA": ["2001:db8::1"]}) == (
        ["2001:db8::1"], "resolved"
    )


def resolve_upstreams(*answers):
    if len(answers) == 1:
        answers = answers * len(DNS_VALIDATION_PORTS)
    instance = BlackList.__new__(BlackList)
    resolvers = [FakeResolver(answer) for answer in answers]
    return asyncio.run(instance._BlackList__resolve(resolvers, "example.test"))


def test_nxdomain_requires_all_five_independent_upstreams():
    dead = {"A": NXDOMAIN(), "AAAA": NXDOMAIN()}
    assert resolve_upstreams(*([dead] * 5)) == ([], "not_found")


def test_one_resolver_returning_an_address_prevents_blacklisting():
    dead = {"A": NXDOMAIN(), "AAAA": NXDOMAIN()}
    alive = {"A": ["192.0.2.10"], "AAAA": NoAnswer()}
    assert resolve_upstreams(*([dead] * 4 + [alive])) == (["192.0.2.10"], "resolved")


def test_one_resolver_nodata_prevents_nxdomain_classification():
    dead = {"A": NXDOMAIN(), "AAAA": NXDOMAIN()}
    nodata = {"A": NoAnswer(), "AAAA": NoAnswer()}
    assert resolve_upstreams(*([dead] * 4 + [nodata])) == ([], "unknown")


def test_one_resolver_timeout_prevents_nxdomain_classification():
    dead = {"A": NXDOMAIN(), "AAAA": NXDOMAIN()}
    timeout = {"A": TimeoutError("A timeout"), "AAAA": TimeoutError("AAAA timeout")}
    assert resolve_upstreams(*([dead] * 4 + [timeout])) == ([], "unknown")


def test_no_address_requires_all_five_upstreams_to_agree():
    nodata = {"A": NoAnswer(), "AAAA": NoAnswer()}
    assert resolve_upstreams(*([nodata] * 6)) == ([], "no_address")
    dead = {"A": NXDOMAIN(), "AAAA": NXDOMAIN()}
    assert resolve_upstreams(*([nodata] * 4 + [dead])) == ([], "unknown")


def test_missing_upstream_is_inconclusive_not_dead():
    dead = {"A": NXDOMAIN(), "AAAA": NXDOMAIN()}
    instance = BlackList.__new__(BlackList)
    resolvers = [FakeResolver(dead) for _ in range(4)]
    assert asyncio.run(instance._BlackList__resolve(resolvers, "example.test")) == (
        [], "unknown"
    )


def test_dns_upstream_disagreement_preserves_previous_unblocked_state():
    dead = {"A": NXDOMAIN(), "AAAA": NXDOMAIN()}
    unavailable = {"A": TimeoutError("A timeout"), "AAAA": TimeoutError("AAAA timeout")}
    domain = pingx([dead] * 4 + [unavailable], initially_blocked=False)
    assert domain.blocked is False
