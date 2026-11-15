
import argparse

from rich.console import Console
from rich.table import Table

from .dns import lookup
from .tls import inspect as inspect_tls


console = Console()


def main():
    parser = argparse.ArgumentParser(
        prog="styx-recon",
        description="STYX-RECON - Lightweight reconnaissance toolkit",
    )

    parser.add_argument(
        "target",
        help="Target domain",
    )

    parser.add_argument(
        "--tls",
        action="store_true",
        help="perform one verified TLS handshake on port 443",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    args = parser.parse_args()

    domain = args.target

    results = lookup(domain)
    tls_result = inspect_tls(domain) if args.tls else None

    if args.json:
        from .reporter import print_json

        print_json({
            "target": domain,
            "dns": results,
            "tls": tls_result,
        })
        return

    console.print()
    console.print("[bold cyan]🕷️ STYX-RECON[/bold cyan]")
    console.print(f"Target: [bold]{domain}[/bold]")
    console.print()

    table = Table(title="DNS Reconnaissance")

    table.add_column("Record", style="cyan")
    table.add_column("Value")

    for record_type, values in results.items():
        if values:
            for value in values:
                table.add_row(record_type, value)
        else:
            table.add_row(record_type, "-")

    console.print(table)
    if tls_result is not None:
        console.print()
        tls_table = Table(title="TLS Certificate")
        tls_table.add_column("Field", style="cyan")
        tls_table.add_column("Value")
        for key, value in tls_result.items():
            tls_table.add_row(key.replace("_", " ").title(), str(value))
        console.print(tls_table)


if __name__ == "__main__":
    main()
