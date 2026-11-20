"""DNS reconnaissance primitives for STYX-RECON."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import unicodedata

import dns.exception
import dns.resolver


RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")

MAX_TARGET_LENGTH = 253
MAX_LABEL_LENGTH = 63
_LABEL_RE = re.compile(r"^[a-z0-9_-]+$")


@dataclass
class LookupReport:
    """Normalized DNS reconnaissance result with resolver diagnostics."""

    target: str
    records: dict[str, list[str]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    exists: bool = True
    resolved: bool = False

    @property
    def ok(self) -> bool:
        """True when the target exists and at least one DNS answer came back."""
        return self.exists and self.resolved


def normalize_target(domain: str) -> str:
    """Validate and normalize a domain before it is sent to a resolver.

    Accepts one trailing dot, lowercases ASCII names, and converts
    internationalized names to punycode. Rejects URLs, whitespace, control
    characters, empty labels, and overlong names.
    """
    if not isinstance(domain, str):
        raise ValueError("target must be a domain name")

    target = domain.strip()
    if not target:
        raise ValueError("target domain is required")
    if "://" in target:
        raise ValueError("target must be a domain name, not a URL")
    if target.endswith(".."):
        raise ValueError("target domain must not contain repeated trailing dots")

    target = target.rstrip(".").lower()
    if not target:
        raise ValueError("target domain is required")

    if not target.isascii():
        try:
            target = target.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("target contains an invalid internationalized name") from exc

    if any(unicodedata.category(ch).startswith("C") for ch in target):
        raise ValueError("target domain contains control characters")
    if any(ch.isspace() for ch in target):
        raise ValueError("target domain contains whitespace")
    if len(target) > MAX_TARGET_LENGTH:
        raise ValueError("target domain must be 253 characters or fewer")

    labels = target.split(".")
    for label in labels:
        if not label:
            raise ValueError("target domain contains an empty label")
        if len(label) > MAX_LABEL_LENGTH:
            raise ValueError("target domain contains a label longer than 63 characters")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError("target domain labels must not start or end with a hyphen")
        if not _LABEL_RE.fullmatch(label):
            raise ValueError(
                "target domain contains invalid characters; "
                "use letters, digits, hyphens, or underscores"
            )

    return target


def _resolve(target: str, record_type: str, timeout: float):
    """Small seam around dnspython so tests never need a live resolver."""
    return dns.resolver.resolve(
        target,
        record_type,
        lifetime=timeout,
        search=False,
        raise_on_no_answer=False,
    )


def lookup(domain: str, timeout: float = 5.0) -> LookupReport:
    """Collect the supported DNS record types for *domain*.

    A failed record type is reported through ``warnings`` instead of being
    silently treated as an empty record set. NXDOMAIN stops the scan because
    no other record type can exist for the name.
    """
    if timeout <= 0:
        raise ValueError("timeout must be greater than 0")

    target = normalize_target(domain)
    report = LookupReport(
        target=target,
        records={record_type: [] for record_type in RECORD_TYPES},
    )

    for record_type in RECORD_TYPES:
        try:
            answer = _resolve(target, record_type, timeout)
        except dns.resolver.NXDOMAIN:
            report.exists = False
            report.warnings.append("target does not exist (NXDOMAIN)")
            break
        except dns.resolver.NoNameservers:
            report.warnings.append("no nameservers available for the target")
            break
        except dns.exception.Timeout:
            report.warnings.append(f"{record_type} lookup timed out")
            break
        except dns.exception.DNSException as exc:
            report.warnings.append(f"{record_type} lookup failed: {exc}")
            continue
        except Exception as exc:  # defensive: never crash the CLI on resolver bugs
            report.warnings.append(
                f"{record_type} lookup failed: {type(exc).__name__}: {exc}"
            )
            continue

        if getattr(answer, "rrset", None) is None:
            continue

        values = set()
        for record in answer:
            text = record.to_text().strip()
            if text:
                values.add(text)
        report.records[record_type] = sorted(values)
        report.resolved = True

    return report
