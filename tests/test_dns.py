from unittest.mock import patch

from styxrecon.dns import RECORD_TYPES, lookup


def test_dns_lookup_queries_supported_types_and_returns_text_values():
    class Answer:
        def to_text(self):
            return "192.0.2.10"

    with patch("styxrecon.dns.dns.resolver.resolve", return_value=[Answer()]) as resolve:
        result = lookup("example.com")

    assert list(result) == RECORD_TYPES
    assert all(isinstance(result[record_type], list) for record_type in RECORD_TYPES)
    assert all(result[record_type] == ["192.0.2.10"] for record_type in RECORD_TYPES)
    assert resolve.call_count == len(RECORD_TYPES)


def test_dns_lookup_keeps_failed_record_types_and_continues():
    def resolve(_domain, record_type):
        if record_type == "AAAA":
            raise RuntimeError("no AAAA answer")
        return [type("Answer", (), {"to_text": lambda self: record_type})()]

    with patch("styxrecon.dns.dns.resolver.resolve", side_effect=resolve):
        result = lookup("example.com")

    assert result["A"] == ["A"]
    assert result["AAAA"] == []
    assert result["MX"] == ["MX"]
