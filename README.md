# 🕷️ STYX-RECON

**Lightweight DNS & Reconnaissance Toolkit**

STYX-RECON is a lightweight Python-based reconnaissance toolkit designed for security research and information gathering.

It focuses on collecting publicly accessible DNS information and presenting the results in a clear and readable format.

---

## ✨ Features

* 🔎 DNS reconnaissance
* 🌐 A record lookup
* 🌐 AAAA record lookup
* 📧 MX record lookup
* 🏷️ NS record lookup
* 📝 TXT record lookup
* 🔗 CNAME record lookup
* 📊 Rich terminal output
* 📦 JSON output support
* 🧪 Automated tests
* 🐍 Python-based and lightweight

---

## 🚀 Installation

### Clone the repository

```bash
git clone https://github.com/raxwqx/STYX-RECON.git
cd STYX-RECON
```

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## ⚡ Usage

Run STYX-RECON against a target domain:

```bash
python main.py example.com
```

### JSON output

To receive the results in JSON format:

```bash
python main.py example.com --json
```

---

## 🔍 DNS Records

STYX-RECON currently supports the following DNS record types:

| Record | Description                |
| ------ | -------------------------- |
| A      | IPv4 address               |
| AAAA   | IPv6 address               |
| MX     | Mail exchange servers      |
| NS     | Authoritative name servers |
| TXT    | Text records               |
| CNAME  | Canonical name             |

---

## 📦 JSON Output

STYX-RECON can export reconnaissance results as JSON, making the output easier to process with other tools or scripts.

Example:

```bash
python main.py example.com --json
```

---

## 🧪 Testing

Run the test suite with:

```bash
python -m pytest -q
```

---

## 📁 Project Structure

```text
STYX-RECON/
├── main.py
├── requirements.txt
├── README.md
├── LICENSE
└── tests/
```

---

## 🎯 Project Goal

The goal of STYX-RECON is to provide a simple and lightweight reconnaissance tool for security researchers, penetration testers, and anyone interested in learning about DNS reconnaissance.

The project is designed to remain easy to understand, extend, and use.

---

## 🛣️ Roadmap

Planned improvements may include:

* TLS inspection
* WHOIS information
* Additional DNS reconnaissance
* More detailed reporting
* Further reconnaissance modules

---

## ⚠️ Disclaimer

STYX-RECON is intended for **educational purposes, security research, and authorized testing only**.

Do not use this tool against systems or domains without proper authorization.

The developer is not responsible for misuse or damage caused by this software.

---

## 📜 License

This project is licensed under the **MIT License**.
