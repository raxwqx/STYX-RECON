# Changelog

## 0.2.0 - 2026-11-20

### Added

- Optional TLS certificate inspection via `--tls`, with `--port` for alternate ports. Reports connection status, verification result, protocol, cipher, subject, issuer, serial number, validity window, days remaining, expiry, and SAN entries.
- Certificate-verified handshake first, with a details-only unverified retry when verification fails (expired, self-signed, or hostname mismatch). Binary certificates are decoded for the fallback report.
- JSON output now includes `tool`, `version`, `exists`, and `resolved` metadata alongside DNS results and warnings.
- Turkish `README.md` and English `README_EN.md` covering the new TLS feature, validation rules, limits, exit codes, and JSON schema.
- CI for Linux, macOS, and Windows on Python 3.10–3.13.
- Network-free unit tests for DNS lookup behavior, target normalization, TLS certificate parsing, verification fallback, and CLI output/exit codes.

### Fixed

- The README no longer tells users to run a nonexistent `main.py`; the documented entry point is `styx-recon` or `python -m styxrecon`.
- Resolver failures are no longer silently swallowed. NXDOMAIN, no-nameserver, timeout, and other DNS exceptions are reported as warnings; NXDOMAIN and fatal resolver failures stop further queries.
- Targets are validated before lookup: URLs, whitespace, control characters, empty/overlong labels, repeated trailing dots, invalid characters, and leading/trailing hyphens are rejected.
- Internationalized domain names are converted to punycode instead of failing inside the resolver.
- DNS results are deduplicated and sorted for deterministic output.
- Terminal output strips control characters from DNS/TLS values and warnings, and wraps values in Rich `Text` so record contents cannot inject markup.
- The CLI validates `--timeout` (0–60 seconds) and `--port` (1–65535), and rejects `--port` without `--tls`.
- DNS and TLS connection failures now produce exit code `1`; invalid input produces exit code `2`.
- Requirement metadata now declares supported version ranges, package metadata, and a development extra for pytest.

### Changed

- Package version is now `0.2.0` in `pyproject.toml` and `styxrecon/__version__`.
- `python -m styxrecon` and the console script both return meaningful exit codes.
- The test suite no longer depends on live DNS resolution.
