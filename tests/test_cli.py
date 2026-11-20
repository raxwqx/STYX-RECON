import json

import pytest

from styxrecon import __version__
from styxrecon import cli as cli_module
from styxrecon.cli import main
from styxrecon.dns import LookupReport


def make_report(**overrides):
    report = LookupReport(
        target="example.com",
        records={
            "A": ["192.0.2.10"],
            "AAAA": [],
            "MX": ["10 mail.example.com."],
            "NS": ["ns1.example.com."],
            "TXT": ["v=spf1 -all"],
            "CNAME": [],
        },
        warnings=[],
        exists=True,
        resolved=True,
    )
    for key, value in overrides.items():
        setattr(report, key, value)
    return report


def test_json_output_has_tool_metadata(monkeypatch, capsys):
    monkeypatch.setattr(cli_module, "lookup", lambda target, timeout: make_report())

    code = main(["example.com", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["tool"] == "styx-recon"
    assert payload["version"] == __version__
    assert payload["target"] == "example.com"
    assert payload["exists"] is True
    assert payload["resolved"] is True
    assert payload["dns"]["A"] == ["192.0.2.10"]
    assert payload["warnings"] == []
    assert "tls" not in payload


def test_json_output_includes_tls_when_requested(monkeypatch, capsys):
    monkeypatch.setattr(cli_module, "lookup", lambda target, timeout: make_report())
    monkeypatch.setattr(
        cli_module,
        "inspect_tls",
        lambda target, port, timeout: {
            "hostname": target,
            "port": port,
            "connected": True,
            "verified": True,
            "error": None,
        },
    )

    code = main(["example.com", "--json", "--tls", "--port", "8443"])

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["tls"]["port"] == 8443
    assert payload["tls"]["verified"] is True


def test_invalid_target_returns_exit_code_two(monkeypatch, capsys):
    def fail(target, timeout):
        raise ValueError("target domain contains whitespace")

    monkeypatch.setattr(cli_module, "lookup", fail)

    code = main(["bad target"])

    captured = capsys.readouterr()
    assert code == 2
    assert "target domain contains whitespace" in captured.err


def test_nxdomain_returns_exit_code_one(monkeypatch, capsys):
    report = make_report(
        records={name: [] for name in ("A", "AAAA", "MX", "NS", "TXT", "CNAME")},
        warnings=["target does not exist (NXDOMAIN)"],
        exists=False,
        resolved=False,
    )
    monkeypatch.setattr(cli_module, "lookup", lambda target, timeout: report)
    monkeypatch.setattr(
        cli_module,
        "inspect_tls",
        lambda *args, **kwargs: pytest.fail("TLS must not run for NXDOMAIN"),
    )

    code = main(["missing.example", "--tls"])

    assert code == 1
    assert "NXDOMAIN" in capsys.readouterr().out


def test_tls_connection_failure_returns_exit_code_one(monkeypatch, capsys):
    monkeypatch.setattr(cli_module, "lookup", lambda target, timeout: make_report())
    monkeypatch.setattr(
        cli_module,
        "inspect_tls",
        lambda target, port, timeout: {
            "hostname": target,
            "port": port,
            "connected": False,
            "verified": False,
            "error": "connection refused",
        },
    )

    code = main(["example.com", "--json", "--tls"])

    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["tls"]["connected"] is False


def test_terminal_output_keeps_untrusted_text_literal(monkeypatch, capsys):
    report = make_report(
        records={
            "A": ["192.0.2.10"],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": ["[red]not markup\x1b[2J"],
            "CNAME": [],
        }
    )
    monkeypatch.setattr(cli_module, "lookup", lambda target, timeout: report)

    code = main(["example.com"])

    output = capsys.readouterr().out
    assert code == 0
    assert "[red]not markup[2J" in output
    assert "\x1b" not in output
    assert "STYX-RECON" in output


def test_port_without_tls_is_rejected():
    with pytest.raises(SystemExit) as excinfo:
        main(["example.com", "--port", "8443"])
    assert excinfo.value.code == 2


@pytest.mark.parametrize("value", ["0", "-1", "61", "nope"])
def test_invalid_timeout_is_rejected(value):
    with pytest.raises(SystemExit) as excinfo:
        main(["example.com", "--timeout", value])
    assert excinfo.value.code == 2


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out
