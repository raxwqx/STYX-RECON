"""Optional TLS certificate inspection for an authorized hostname."""

from __future__ import annotations

import os
import socket
import ssl
import tempfile
from datetime import datetime, timezone
from typing import Any

from .dns import normalize_target

MAX_TIMEOUT = 60.0


def _format_name(name: Any) -> str:
    """Render an ssl certificate name tuple as ``CN=..., O=...``."""
    if not name:
        return ""

    parts: list[str] = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _certificate_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(
            ssl.cert_time_to_seconds(str(value)), tz=timezone.utc
        )
    except (ValueError, OverflowError, OSError):
        return None


def parse_certificate(certificate: dict | None, now: datetime | None = None) -> dict:
    """Convert a Python certificate dictionary into stable report fields."""
    now = now or datetime.now(timezone.utc)
    certificate = certificate or {}

    not_before = _certificate_time(certificate.get("notBefore"))
    not_after = _certificate_time(certificate.get("notAfter"))
    days_remaining = None
    expired = None
    if not_after is not None:
        days_remaining = (not_after - now).days
        expired = not_after <= now

    san: list[str] = []
    for kind, value in certificate.get("subjectAltName", ()):
        san.append(f"{kind}:{value}")

    return {
        "subject": _format_name(certificate.get("subject")),
        "issuer": _format_name(certificate.get("issuer")),
        "serial_number": certificate.get("serialNumber"),
        "not_before": not_before.isoformat() if not_before else None,
        "not_after": not_after.isoformat() if not_after else None,
        "days_remaining": days_remaining,
        "expired": expired,
        "san": sorted(san),
    }


def _failure(hostname: str, port: int, error: str) -> dict:
    return {
        "hostname": hostname,
        "port": port,
        "connected": False,
        "verified": False,
        "error": error,
        "protocol": None,
        "cipher": None,
        "subject": "",
        "issuer": "",
        "serial_number": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "expired": None,
        "san": [],
    }


def _decode_der_certificate(der: bytes | None) -> dict:
    """Decode a DER certificate into the dict shape returned by getpeercert().

    ``SSLSocket.getpeercert()`` returns an empty dict when verification is
    disabled, so the unverified fallback path decodes the binary certificate
    through CPython's built-in certificate decoder.
    """
    if not der:
        return {}
    decoder = getattr(ssl._ssl, "_test_decode_cert", None)
    if decoder is None:
        return {}

    path = None
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".pem", encoding="ascii", delete=False
        ) as handle:
            handle.write(pem)
            path = handle.name
        return decoder(path)
    except (OSError, ValueError, ssl.SSLError):
        return {}
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def _fetch_certificate(hostname: str, port: int, timeout: float, verify: bool):
    if verify:
        context = ssl.create_default_context()
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as connection:
            certificate = connection.getpeercert()
            if not certificate:
                certificate = _decode_der_certificate(
                    connection.getpeercert(binary_form=True)
                )
            cipher = connection.cipher()
            return certificate, connection.version(), cipher[0] if cipher else None


def inspect(hostname: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Inspect the peer certificate on *hostname*:*port*.

    A normal certificate-verified handshake is attempted first. When the
    certificate cannot be verified (expired, self-signed, hostname mismatch),
    the check retries without verification so the report can still show the
    certificate details, marked ``verified=False``.
    """
    target = normalize_target(hostname)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not 0 < timeout <= MAX_TIMEOUT:
        raise ValueError(f"timeout must be between 0 and {MAX_TIMEOUT:g} seconds")

    verification_error: str | None = None
    try:
        certificate, protocol, cipher = _fetch_certificate(
            target, port, timeout, verify=True
        )
        verified = True
    except ssl.SSLCertVerificationError as exc:
        verification_error = str(exc)
        try:
            certificate, protocol, cipher = _fetch_certificate(
                target, port, timeout, verify=False
            )
            verified = False
        except (OSError, ssl.SSLError, ValueError) as retry_error:
            return _failure(target, port, str(retry_error))
    except (OSError, ssl.SSLError, ValueError) as exc:
        return _failure(target, port, str(exc))

    result = {
        "hostname": target,
        "port": port,
        "connected": True,
        "verified": verified,
        "error": verification_error,
        "protocol": protocol,
        "cipher": cipher,
    }
    result.update(parse_certificate(certificate))
    return result
