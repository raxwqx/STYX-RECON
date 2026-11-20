# 🕷️ STYX-RECON

**Lightweight DNS reconnaissance toolkit with optional TLS certificate inspection.**

[Türkçe dokümantasyon](README.md)

STYX-RECON is a lightweight Python toolkit designed for security research, OSINT, and network inventory. It collects publicly accessible DNS records and can optionally inspect the target's TLS certificate. Results are presented as a readable terminal table or JSON.

<p>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" />
  <img alt="MIT License" src="https://img.shields.io/badge/License-MIT-14B8A6.svg" />
  <a href="https://github.com/raxwqx/STYX-RECON/actions/workflows/tests.yml"><img alt="Tests" src="https://github.com/raxwqx/STYX-RECON/actions/workflows/tests.yml/badge.svg?branch=main" /></a>
</p>

## ✨ Features

- 🔎 A, AAAA, MX, NS, TXT, and CNAME records
- 🔐 **Optional TLS certificate inspection (`--tls`)** — new
- 🧾 JSON output (tool/version metadata, DNS records, warnings, optional TLS result)
- ⏱️ Configurable DNS and TLS timeout
- ⚠️ Resolver failures are reported instead of silently swallowed: NXDOMAIN, timeouts, and nameserver errors become warnings
- ✅ Target validation and normalization (URLs, whitespace, control characters, and invalid labels are rejected)
- 🌍 Punycode conversion for internationalized domain names
- 🧼 Control-character sanitization and Rich markup neutralization in terminal output
- 📊 Readable Rich-based tables
- 🚦 Meaningful exit codes for scripts
- 🧪 Unit tests that do not require network access
- 🐍 Python 3.10+ with lightweight dependencies

## 📦 Requirements

- Python 3.10 or newer
- `dnspython` and `rich`
- Access to the system resolver for DNS queries
- TCP access to the target port (default 443) for TLS inspection

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/raxwqx/STYX-RECON.git
cd STYX-RECON
```

Create a virtual environment and install the package:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

On Windows:

```powershell
.venv\Scripts\activate
```

Alternatively, install only the dependencies and run it as a module:

```bash
pip install -r requirements.txt
python -m styxrecon example.com
```

## ⚡ Usage

```bash
styx-recon example.com
```

As a module:

```bash
python -m styxrecon example.com
```

JSON output:

```bash
styx-recon example.com --json
```

TLS certificate inspection:

```bash
styx-recon example.com --tls
```

Custom TLS port and timeout:

```bash
styx-recon example.com --tls --port 8443 --timeout 10
```

Help and version:

```bash
styx-recon --help
styx-recon --version
```

> `--port` can only be used together with `--tls`. The default port is 443.

## 🖥️ Example output

```text
🕷️ STYX-RECON
Target: example.com

              DNS Reconnaissance
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Record ┃ Value                            ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ A      │ 192.0.2.10                       │
│ A      │ 192.0.2.11                       │
│ AAAA   │ 2001:db8::10                     │
│ MX     │ 10 mail.example.com.             │
│ NS     │ ns1.example.com.                 │
│ NS     │ ns2.example.com.                 │
│ TXT    │ "v=spf1 -all"                    │
│ CNAME  │ -                                │
└────────┴──────────────────────────────────┘
```

With `--tls`, a certificate table is added:

```text
                                TLS Certificate
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Field          ┃ Value                                           ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Host           │ example.com:443                                 │
│ Verified       │ yes                                             │
│ Protocol       │ TLSv1.3                                         │
│ Cipher         │ TLS_AES_256_GCM_SHA384                          │
│ Subject        │ commonName=example.com                          │
│ Issuer         │ commonName=Example CA                           │
│ Serial         │ 01AB...                                         │
│ Not before     │ 2026-01-01T00:00:00+00:00                       │
│ Not after      │ 2027-01-01T00:00:00+00:00                       │
│ Days remaining │ 214                                             │
│ Expired        │ no                                              │
│ SAN            │ DNS:example.com, DNS:www.example.com            │
└────────────────┴─────────────────────────────────────────────────┘
```

## 🔐 TLS inspection

The TLS check runs only when `--tls` is supplied and the target exists. The tool first attempts a **verified** handshake using the system trust store. If the certificate is expired, self-signed, or does not match the hostname, the check retries without verification so the certificate details are still reported, but with `Verified: no` and a verification warning.

Reported fields:

- Connection status and verification result
- TLS protocol and cipher
- Subject and issuer
- Serial number
- Validity start/end times (UTC, ISO 8601)
- Days remaining and expiry flag
- Subject Alternative Name (SAN) entries

TLS inspection performs a single handshake on one port; it does not scan ports or analyze the full certificate chain.

## 🔍 DNS records

| Record | Description |
| ------ | ----------- |
| A | IPv4 address |
| AAAA | IPv6 address |
| MX | Mail exchange servers (including priority) |
| NS | Authoritative nameservers |
| TXT | Text records |
| CNAME | Canonical name |

Record values are deduplicated and sorted for deterministic output. A missing record type is rendered as `-`.

## 📦 JSON output

```bash
styx-recon example.com --json
```

Example:

```json
{
  "tool": "styx-recon",
  "version": "0.2.0",
  "target": "example.com",
  "exists": true,
  "resolved": true,
  "dns": {
    "A": ["192.0.2.10"],
    "AAAA": ["2001:db8::10"],
    "MX": ["10 mail.example.com."],
    "NS": ["ns1.example.com."],
    "TXT": ["\"v=spf1 -all\""],
    "CNAME": []
  },
  "warnings": [],
  "tls": {
    "hostname": "example.com",
    "port": 443,
    "connected": true,
    "verified": true,
    "error": null,
    "protocol": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=example.com",
    "issuer": "commonName=Example CA",
    "serial_number": "01AB...",
    "not_before": "2026-01-01T00:00:00+00:00",
    "not_after": "2027-01-01T00:00:00+00:00",
    "days_remaining": 214,
    "expired": false,
    "san": ["DNS:example.com", "DNS:www.example.com"]
  }
}
```

Notes:

- `tls` is present only when `--tls` is used.
- `warnings` is always an array and may be empty.
- `exists` reports NXDOMAIN; `resolved` reports whether at least one record answer was received.
- DNS values are preserved verbatim in JSON; terminal rendering strips control characters.

## 🚦 Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | Query completed and at least one DNS answer was received; if requested, the TLS connection succeeded |
| `1` | Target does not exist (NXDOMAIN), no DNS answer was received, or the requested TLS connection failed |
| `2` | Invalid target, port, timeout, or command-line usage |

## 🛡️ Target validation and limits

- The target may be at most 253 characters, and each label at most 63 characters.
- One trailing dot is accepted and removed; repeated trailing dots are rejected.
- URLs, whitespace, control characters, empty labels, and leading/trailing hyphens are rejected.
- Non-ASCII names are converted to punycode (for example, `bücher.example` → `xn--bcher-kva.example`).
- `--timeout` must be greater than 0 and at most 60 seconds.
- The TLS port must be between 1 and 65535.
- NXDOMAIN stops the remaining record queries.
- Nameserver failures and timeouts stop the remaining queries and produce a single warning.
- A failure in one record type does not stop the other record types.

## 🧪 Tests

The tests do not require network access; DNS and TLS layers are mocked.

```bash
pip install -e ".[dev]"
python -m pytest -q
```

CI runs compilation, tests, and a CLI version check on Linux, macOS, and Windows with Python 3.10–3.13.

## 📁 Project structure

```text
STYX-RECON/
├── styxrecon/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── dns.py
│   ├── reporter.py
│   ├── tls.py
│   └── whois.py
├── tests/
│   ├── test_cli.py
│   ├── test_dns.py
│   └── test_tls.py
├── .github/workflows/tests.yml
├── CHANGELOG.md
├── README.md
├── README_EN.md
├── pyproject.toml
└── requirements.txt
```

## 🗺️ Roadmap

- WHOIS queries
- DNS over HTTPS support
- SPF/DMARC/CAA security summary
- CSV and HTML reporting
- Deeper certificate chain analysis

## ⚠️ Disclaimer

STYX-RECON is intended for **educational purposes, security research, and authorized testing only**. Do not use it against systems or domains you are not authorized to inspect. The developer is not responsible for misuse or damage caused by this software.

## 📜 License

MIT
