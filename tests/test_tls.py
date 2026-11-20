import ssl
from datetime import datetime, timezone

import pytest

from styxrecon import tls as tls_module
from styxrecon.tls import inspect, parse_certificate


CERT = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": ((("organizationName", "Test CA"),), (("commonName", "Test Root"),)),
    "serialNumber": "01AB",
    "notBefore": "Jan  1 00:00:00 2026 GMT",
    "notAfter": "Jan  1 00:00:00 2027 GMT",
    "subjectAltName": (
        ("DNS", "www.example.com"),
        ("DNS", "example.com"),
        ("IP Address", "192.0.2.1"),
    ),
}


def test_parse_certificate_fields():
    parsed = parse_certificate(CERT, now=datetime(2026, 6, 1, tzinfo=timezone.utc))

    assert parsed["subject"] == "commonName=example.com"
    assert parsed["issuer"] == "organizationName=Test CA, commonName=Test Root"
    assert parsed["serial_number"] == "01AB"
    assert parsed["not_before"] == "2026-01-01T00:00:00+00:00"
    assert parsed["not_after"] == "2027-01-01T00:00:00+00:00"
    assert parsed["days_remaining"] == 214
    assert parsed["expired"] is False
    assert parsed["san"] == [
        "DNS:example.com",
        "DNS:www.example.com",
        "IP Address:192.0.2.1",
    ]


def test_parse_certificate_detects_expiry():
    parsed = parse_certificate(CERT, now=datetime(2027, 6, 1, tzinfo=timezone.utc))
    assert parsed["days_remaining"] < 0
    assert parsed["expired"] is True


def test_parse_certificate_handles_empty_input():
    parsed = parse_certificate(None)
    assert parsed["subject"] == ""
    assert parsed["issuer"] == ""
    assert parsed["not_after"] is None
    assert parsed["days_remaining"] is None
    assert parsed["expired"] is None
    assert parsed["san"] == []


def test_inspect_uses_verified_handshake(monkeypatch):
    calls = []

    def fake_fetch(hostname, port, timeout, verify):
        calls.append((hostname, port, timeout, verify))
        return CERT, "TLSv1.3", "TLS_AES_256_GCM_SHA384"

    monkeypatch.setattr(tls_module, "_fetch_certificate", fake_fetch)

    result = inspect("Example.COM.", port=8443, timeout=3.5)

    assert calls == [("example.com", 8443, 3.5, True)]
    assert result["connected"] is True
    assert result["verified"] is True
    assert result["error"] is None
    assert result["protocol"] == "TLSv1.3"
    assert result["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert result["subject"] == "commonName=example.com"


def test_inspect_falls_back_to_unverified_handshake(monkeypatch):
    calls = []

    def fake_fetch(hostname, port, timeout, verify):
        calls.append(verify)
        if verify:
            raise ssl.SSLCertVerificationError("certificate has expired")
        return CERT, "TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384"

    monkeypatch.setattr(tls_module, "_fetch_certificate", fake_fetch)

    result = inspect("example.com")

    assert calls == [True, False]
    assert result["connected"] is True
    assert result["verified"] is False
    assert "certificate has expired" in result["error"]
    assert result["protocol"] == "TLSv1.2"


def test_inspect_returns_failure_when_connection_fails(monkeypatch):
    def fake_fetch(hostname, port, timeout, verify):
        raise OSError("connection refused")

    monkeypatch.setattr(tls_module, "_fetch_certificate", fake_fetch)

    result = inspect("example.com")

    assert result["connected"] is False
    assert result["verified"] is False
    assert "connection refused" in result["error"]
    assert result["san"] == []


def test_fetch_certificate_decodes_binary_certificate_when_unverified(monkeypatch):
    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def getpeercert(self, binary_form=False):
            return b"der-certificate" if binary_form else {}

        def version(self):
            return "TLSv1.3"

        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    class FakeContext:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

        def wrap_socket(self, sock, server_hostname):
            return FakeConnection()

    monkeypatch.setattr(tls_module.ssl, "create_default_context", lambda: FakeContext())
    monkeypatch.setattr(
        tls_module.socket, "create_connection", lambda address, timeout: FakeSocket()
    )
    monkeypatch.setattr(
        tls_module, "_decode_der_certificate", lambda der: CERT if der else {}
    )

    certificate, protocol, cipher = tls_module._fetch_certificate(
        "example.com", 443, 5.0, verify=True
    )

    assert certificate == CERT
    assert protocol == "TLSv1.3"
    assert cipher == "TLS_AES_256_GCM_SHA384"


def test_decode_der_certificate_uses_temporary_pem(monkeypatch):
    captured = {}

    def fake_decoder(path):
        with open(path, encoding="ascii") as handle:
            captured["contents"] = handle.read()
        return CERT

    monkeypatch.setattr(tls_module.ssl._ssl, "_test_decode_cert", fake_decoder)

    assert tls_module._decode_der_certificate(b"der-bytes") == CERT
    assert captured["contents"].startswith("-----BEGIN CERTIFICATE-----")
    assert tls_module._decode_der_certificate(None) == {}


def test_decode_der_certificate_returns_empty_on_decoder_failure(monkeypatch):
    def fake_decoder(path):
        raise ValueError("bad certificate")

    monkeypatch.setattr(tls_module.ssl._ssl, "_test_decode_cert", fake_decoder)

    assert tls_module._decode_der_certificate(b"der-bytes") == {}


def test_inspect_validates_port_and_timeout():
    with pytest.raises(ValueError, match="port"):
        inspect("example.com", port=0)
    with pytest.raises(ValueError, match="timeout"):
        inspect("example.com", timeout=0)


def test_inspect_rejects_invalid_hostname():
    with pytest.raises(ValueError):
        inspect("https://example.com")
