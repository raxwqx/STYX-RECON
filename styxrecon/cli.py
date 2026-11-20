"""Command-line interface for STYX-RECON."""

from __future__ import annotations

import argparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .dns import LookupReport, lookup
from .reporter import print_json, sanitize
from .tls import inspect as inspect_tls


def _timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not 0 < timeout <= 60:
        raise argparse.ArgumentTypeError("timeout must be between 0 and 60 seconds")
    return timeout


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="styx-recon",
        description="STYX-RECON - Lightweight DNS & reconnaissance toolkit",
    )
    parser.add_argument("target", help="Target domain")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--tls",
        action="store_true",
        help="Inspect the TLS certificate on the target port",
    )
    parser.add_argument(
        "--port",
        type=_port,
        default=443,
        help="TLS port used with --tls (default: 443)",
    )
    parser.add_argument(
        "--timeout",
        type=_timeout,
        default=5.0,
        help="DNS and TLS timeout in seconds (default: 5, max: 60)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"STYX-RECON {__version__}",
    )
    return parser


def _dns_table(report: LookupReport) -> Table:
    table = Table(title="DNS Reconnaissance")
    table.add_column("Record", style="cyan")
    table.add_column("Value")

    for record_type, values in report.records.items():
        if values:
            for value in values:
                table.add_row(record_type, Text(sanitize(value)))
        else:
            table.add_row(record_type, "-")
    return table


def _tls_table(result: dict) -> Table:
    table = Table(title="TLS Certificate")
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    if not result["connected"]:
        table.add_row("Status", Text("connection failed", style="red"))
        table.add_row("Host", Text(f"{result['hostname']}:{result['port']}"))
        table.add_row("Error", Text(sanitize(result.get("error") or "unknown error")))
        return table

    table.add_row("Host", Text(f"{result['hostname']}:{result['port']}"))
    table.add_row(
        "Verified",
        Text("yes", style="green") if result["verified"] else Text("no", style="yellow"),
    )
    table.add_row("Protocol", Text(sanitize(result.get("protocol") or "-")))
    table.add_row("Cipher", Text(sanitize(result.get("cipher") or "-")))
    table.add_row("Subject", Text(sanitize(result.get("subject") or "-")))
    table.add_row("Issuer", Text(sanitize(result.get("issuer") or "-")))
    table.add_row("Serial", Text(sanitize(result.get("serial_number") or "-")))
    table.add_row("Not before", Text(sanitize(result.get("not_before") or "-")))
    table.add_row("Not after", Text(sanitize(result.get("not_after") or "-")))

    days = result.get("days_remaining")
    table.add_row("Days remaining", Text("-" if days is None else str(days)))
    expired = result.get("expired")
    table.add_row(
        "Expired",
        Text("-" if expired is None else ("yes" if expired else "no")),
    )

    san = result.get("san") or []
    table.add_row("SAN", Text(sanitize(", ".join(san)) if san else "-"))
    return table


def _render(console: Console, report: LookupReport, tls_result: dict | None) -> None:
    console.print()
    console.print("[bold cyan]🕷️ STYX-RECON[/bold cyan]")
    console.print(Text("Target: ") + Text(report.target, style="bold"))
    console.print()
    console.print(_dns_table(report))

    if report.warnings:
        console.print()
        warnings = Text("\n".join(f"! {sanitize(item)}" for item in report.warnings))
        console.print(Panel(warnings, title="Warnings", border_style="yellow"))

    if tls_result is not None:
        console.print()
        console.print(_tls_table(tls_result))
        if tls_result.get("error"):
            console.print()
            console.print(
                Panel(
                    Text(sanitize(tls_result["error"])),
                    title="TLS Warning",
                    border_style="yellow",
                )
            )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.port != 443 and not args.tls:
        parser.error("--port requires --tls")

    try:
        report = lookup(args.target, timeout=args.timeout)
    except ValueError as exc:
        Console(stderr=True).print(f"[bold red]error:[/bold red] {sanitize(exc)}")
        return 2

    tls_result = None
    if args.tls and report.exists:
        try:
            tls_result = inspect_tls(report.target, port=args.port, timeout=args.timeout)
        except ValueError as exc:
            Console(stderr=True).print(f"[bold red]error:[/bold red] {sanitize(exc)}")
            return 2

    if args.json:
        payload = {
            "tool": "styx-recon",
            "version": __version__,
            "target": report.target,
            "exists": report.exists,
            "resolved": report.resolved,
            "dns": report.records,
            "warnings": report.warnings,
        }
        if tls_result is not None:
            payload["tls"] = tls_result
        print_json(payload)
    else:
        _render(Console(), report, tls_result)

    if not report.ok:
        return 1
    if tls_result is not None and not tls_result["connected"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
