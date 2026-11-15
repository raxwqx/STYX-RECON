"""Bounded, certificate-verified TLS inspection for an authorized hostname."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone


def inspect(hostname: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Connect once with normal certificate validation and report peer metadata."""
    try:
        normalized = hostname.strip().rstrip(".").encode("idna").decode("ascii")
        if not normalized or not 1 <= port <= 65535:
            raise ValueError("Enter a hostname and a port from 1 to 65535.")
        if not 0 < timeout <= 15:
            raise ValueError("Timeout must be between 0 and 15 seconds.")
        context = ssl.create_default_context()
        with socket.create_connection((normalized, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=normalized) as connection:
                certificate = connection.getpeercert()
                not_after = certificate.get("notAfter")
                expires_at = None
                days_left = None
                if not_after:
                    expiry = datetime.fromtimestamp(
                        ssl.cert_time_to_seconds(not_after), tz=timezone.utc
                    )
                    expires_at = expiry.isoformat()
                    days_left = (expiry - datetime.now(timezone.utc)).days
                return {
                    "hostname": normalized,
                    "port": port,
                    "verified": True,
                    "tls_version": connection.version(),
                    "cipher": connection.cipher()[0] if connection.cipher() else None,
                    "subject": certificate.get("subject", ()),
                    "issuer": certificate.get("issuer", ()),
                    "not_before": certificate.get("notBefore"),
                    "expires_at": expires_at,
                    "days_left": days_left,
                }
    except (OSError, ssl.SSLError, UnicodeError, ValueError) as error:
        return {"hostname": hostname, "port": port, "verified": False, "error": str(error)}
