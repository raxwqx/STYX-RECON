import dns.exception
import dns.resolver
import pytest

from styxrecon import dns as dns_module
from styxrecon.dns import RECORD_TYPES, lookup, normalize_target


class FakeRecord:
    def __init__(self, text: str):
        self._text = text

    def to_text(self) -> str:
        return self._text


class FakeAnswer:
    def __init__(self, values):
        self._values = [FakeRecord(value) for value in (values or [])]
        self.rrset = object() if values else None

    def __iter__(self):
        return iter(self._values)


def test_lookup_normalizes_target_and_collects_sorted_unique_values(monkeypatch):
    calls = []

    def fake_resolve(target, record_type, timeout):
        calls.append((target, record_type, timeout))
        return FakeAnswer([f"z-{record_type}", f"a-{record_type}", f"a-{record_type}"])

    monkeypatch.setattr(dns_module, "_resolve", fake_resolve)

    report = lookup(" Example.COM. ", timeout=3.5)

    assert report.target == "example.com"
    assert report.exists is True
    assert report.resolved is True
    assert report.ok is True
    assert report.warnings == []
    assert list(report.records) == list(RECORD_TYPES)
    for record_type in RECORD_TYPES:
        assert report.records[record_type] == [f"a-{record_type}", f"z-{record_type}"]
    assert calls[0] == ("example.com", "A", 3.5)
    assert len(calls) == len(RECORD_TYPES)


def test_lookup_returns_empty_records_for_no_answer(monkeypatch):
    monkeypatch.setattr(
        dns_module,
        "_resolve",
        lambda target, record_type, timeout: FakeAnswer([]),
    )

    report = lookup("example.com")

    assert report.ok is False
    assert report.resolved is False
    assert all(values == [] for values in report.records.values())
    assert report.warnings == []


def test_lookup_reports_nxdomain_and_stops(monkeypatch):
    calls = []

    def fake_resolve(target, record_type, timeout):
        calls.append(record_type)
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns_module, "_resolve", fake_resolve)

    report = lookup("missing.example")

    assert report.exists is False
    assert report.ok is False
    assert calls == ["A"]
    assert "NXDOMAIN" in report.warnings[0]


def test_lookup_reports_timeout_and_stops(monkeypatch):
    monkeypatch.setattr(
        dns_module,
        "_resolve",
        lambda target, record_type, timeout: (_ for _ in ()).throw(
            dns.exception.Timeout()
        ),
    )

    report = lookup("example.com")

    assert report.warnings == ["A lookup timed out"]
    assert report.ok is False


def test_lookup_reports_nameserver_failure(monkeypatch):
    monkeypatch.setattr(
        dns_module,
        "_resolve",
        lambda target, record_type, timeout: (_ for _ in ()).throw(
            dns.resolver.NoNameservers()
        ),
    )

    report = lookup("example.com")

    assert "no nameservers" in report.warnings[0]


def test_lookup_continues_after_single_record_failure(monkeypatch):
    def fake_resolve(target, record_type, timeout):
        if record_type == "AAAA":
            raise dns.exception.DNSException("boom")
        return FakeAnswer([record_type])

    monkeypatch.setattr(dns_module, "_resolve", fake_resolve)

    report = lookup("example.com")

    assert report.records["A"] == ["A"]
    assert report.records["AAAA"] == []
    assert report.records["MX"] == ["MX"]
    assert any("AAAA" in warning for warning in report.warnings)


def test_lookup_does_not_crash_on_unexpected_error(monkeypatch):
    monkeypatch.setattr(
        dns_module,
        "_resolve",
        lambda target, record_type, timeout: (_ for _ in ()).throw(RuntimeError("bad")),
    )

    report = lookup("example.com")

    assert all("RuntimeError: bad" in warning for warning in report.warnings)
    assert report.ok is False


def test_lookup_rejects_invalid_target():
    with pytest.raises(ValueError, match="required"):
        lookup("   ")


def test_lookup_rejects_invalid_timeout():
    with pytest.raises(ValueError, match="timeout"):
        lookup("example.com", timeout=0)


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("_dmarc.example.com", "_dmarc.example.com"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("1.1.1.1", "1.1.1.1"),
    ],
)
def test_normalize_target_accepts(domain, expected):
    assert normalize_target(domain) == expected


@pytest.mark.parametrize(
    "domain",
    [
        "",
        "   ",
        ".",
        "example.com..",
        "exa mple.com",
        "example.com\x1b[31m",
        "https://example.com",
        "example.com/path",
        "-example.com",
        "example-.com",
        "example..com",
        "a" * 64 + ".com",
        ("a." * 128) + "com",
        "exa_mple!.com",
    ],
)
def test_normalize_target_rejects(domain):
    with pytest.raises(ValueError):
        normalize_target(domain)
