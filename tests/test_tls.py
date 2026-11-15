from unittest.mock import patch

from styxrecon.tls import inspect


class FakeConnection:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def getpeercert(self):
        return {
            "subject": ((('commonName', 'example.com'),),),
            "issuer": ((('commonName', 'Test CA'),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Jan  1 00:00:00 2027 GMT",
        }


class FakeContext:
    def wrap_socket(self, sock, server_hostname):
        self.server_hostname = server_hostname
        return FakeConnection()


def test_tls_inspection_uses_hostname_verification_and_bounded_timeout():
    context = FakeContext()
    with patch("styxrecon.tls.ssl.create_default_context", return_value=context), patch(
        "styxrecon.tls.socket.create_connection", return_value=FakeConnection()
    ) as connect:
        result = inspect(" example.com. ", timeout=3.5)

    assert result["verified"] is True
    assert result["hostname"] == "example.com"
    assert result["tls_version"] == "TLSv1.3"
    assert context.server_hostname == "example.com"
    connect.assert_called_once_with(("example.com", 443), timeout=3.5)


def test_tls_inspection_rejects_out_of_range_timeout_without_connecting():
    with patch("styxrecon.tls.socket.create_connection") as connect:
        result = inspect("example.com", timeout=16)
    assert result["verified"] is False
    assert "between 0 and 15 seconds" in result["error"]
    connect.assert_not_called()
