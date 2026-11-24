import asyncio

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
    assert resolve({"A": None, "AAAA": ["2001:db8::1"]}) == ["2001:db8::1"]


def test_a_and_aaaa_answers_are_both_retained():
    assert resolve({"A": ["192.0.2.1"], "AAAA": ["2001:db8::1"]}) == [
        "192.0.2.1", "2001:db8::1"
    ]


def test_duplicate_answers_are_removed():
    assert resolve({"A": ["192.0.2.1"], "AAAA": ["192.0.2.1"]}) == ["192.0.2.1"]


def test_one_query_failure_does_not_discard_other_family():
    assert resolve({"A": TimeoutError("A timeout"), "AAAA": ["2001:db8::1"]}) == [
        "2001:db8::1"
    ]


def test_no_address_records_returns_empty_list():
    assert resolve({"A": None, "AAAA": None}) == []
