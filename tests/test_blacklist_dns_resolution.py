import asyncio

from dns.resolver import NXDOMAIN, NoAnswer

from blacklist import BlackList


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


def resolve(answers):
    instance = BlackList.__new__(BlackList)
    return asyncio.run(instance._BlackList__resolve(FakeResolver(answers), "example.test"))


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


def test_nxdomain_is_definitive_even_if_other_family_times_out():
    assert resolve({"A": NXDOMAIN(), "AAAA": TimeoutError("AAAA timeout")}) == (
        [], "not_found"
    )


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
