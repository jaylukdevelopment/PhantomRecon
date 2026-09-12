from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from phantomrecon import __version__
from phantomrecon.config import ScanConfig
from phantomrecon.logger import setup_logger

app = typer.Typer(
    name="phantomrecon",
    help="PhantomRecon — Professional Bug Bounty Vulnerability Scanner",
    add_completion=False,
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"PhantomRecon v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True
    ),
) -> None:
    pass


@app.command()
def scan(
    url: str = typer.Option("", "--url", "-u", help="Target URL to scan"),
    target_file: str = typer.Option("", "--target-file", "-t", help="File with URLs to scan"),
    depth: int = typer.Option(3, "--depth", "-d", help="Crawl depth"),
    max_urls: int = typer.Option(500, "--max-urls", help="Max URLs to crawl"),
    concurrency: int = typer.Option(15, "--concurrency", "-c", help="Concurrent requests"),
    timeout: int = typer.Option(12, "--timeout", help="Request timeout in seconds"),
    rate_limit: float = typer.Option(0.2, "--rate-limit", "-r", help="Delay between requests (seconds)"),
    modules: str = typer.Option("all", "--modules", "-m", help="Comma-separated modules to run"),
    oob_port: int = typer.Option(8888, "--oob-port", help="OOB listener port"),
    min_confidence: float = typer.Option(0.5, "--min-confidence", help="Min confidence (0.0-1.0)"),
    output_dir: str = typer.Option("scan_results", "--output", "-o", help="Output directory"),
    proxy: str = typer.Option("", "--proxy", "-p", help="HTTP proxy (http://127.0.0.1:8080)"),
    cookies: str = typer.Option("", "--cookies", help="Cookies: name=val,name2=val2"),
    headers: str = typer.Option("", "--headers", help="Extra headers: Name:Value,Name2:Value2"),
    token: str = typer.Option("", "--token", help="Bearer token"),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose output"),
    stealth: bool = typer.Option(False, "--stealth", help="Stealth mode (slower, fewer requests)"),
    no_json: bool = typer.Option(False, "--no-json", help="Disable JSON report"),
    no_html: bool = typer.Option(False, "--no-html", help="Disable HTML report"),
    no_markdown: bool = typer.Option(False, "--no-markdown", help="Disable Markdown report"),
    log_file: str = typer.Option("", "--log-file", help="Write logs to file"),
) -> None:
    """Run a vulnerability scan against a target."""

    if not url and not target_file:
        console.print("[bold red]Error:[/] Provide --url or --target-file")
        raise typer.Exit(1)

    setup_logger(level=10 if verbose else 20, log_file=log_file)

    _print_banner()

    parsed_cookies = {}
    if cookies:
        for pair in cookies.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                parsed_cookies[k.strip()] = v.strip()

    parsed_headers = {}
    if headers:
        for pair in headers.split(","):
            if ":" in pair:
                k, v = pair.split(":", 1)
                parsed_headers[k.strip()] = v.strip()

    module_list = [m.strip() for m in modules.split(",") if m.strip()]
    if "all" in module_list:
        module_list = ["ALL"]

    config = ScanConfig(
        target_url=url,
        target_file=target_file,
        crawl_depth=depth,
        max_urls=max_urls,
        concurrency=concurrency,
        timeout=timeout,
        rate_limit=rate_limit,
        modules=module_list,
        oob_port=oob_port,
        min_confidence=min_confidence,
        output_dir=Path(output_dir),
        proxy=proxy,
        cookies=parsed_cookies,
        headers=parsed_headers,
        bearer_token=token,
        verbose=verbose,
        stealth=stealth,
        no_json=no_json,
        no_html=no_html,
        no_markdown=no_markdown,
        log_file=log_file,
    )

    from phantomrecon.scanner import PhantomScanner
    scanner = PhantomScanner(config)

    result = asyncio.run(scanner.run())

    _print_summary(result)

    exit_code = 1 if result.critical_count > 0 else 0
    raise typer.Exit(exit_code)


@app.command()
def dashboard(
    port: int = typer.Option(8501, "--port", "-p", help="Dashboard port"),
    results_dir: str = typer.Option("scan_results", "--results", "-r", help="Results directory"),
) -> None:
    """Launch the Streamlit web dashboard."""
    import subprocess

    web_app = Path(__file__).parent / "web" / "app.py"
    cmd = [
        sys.executable, "-m", "streamlit", "run", str(web_app),
        "--server.port", str(port),
        "--server.headless", "true",
        "--theme.base", "dark",
    ]
    console.print(f"[bold cyan]Starting dashboard on port {port}...[/]")
    subprocess.run(cmd)


def _print_banner() -> None:
    banner = f"""
[bold cyan]
    ╔══════════════════════════════════════════════╗
    ║   ██████╗ ██╗  ██╗ █████╗ ███████╗███╗   ██╗████████╗    ██████╗ ███████╗ ██████╗ ██╗   ██╗██████╗  █████╗ ██████╗ ███████╗███╗   ██╗
    ║   ██╔══██╗██║  ██║██╔══██╗██╔════╝████╗  ██║╚══██╔══╝    ██╔══██╗██╔════╝██╔═══██╗██║   ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║
    ║   ██████╔╝███████║███████║███████╗██╔██╗ ██║   ██║       ██████╔╝█████╗  ██║   ██║██║   ██║██████╔╝███████║██████╔╝█████╗  ██╔██╗ ██║
    ║   ██╔═══╝ ██╔══██║██╔══██║╚════██║██║╚██╗██║   ██║       ██╔══██╗██╔══╝  ██║   ██║██║   ██║██╔═══╝ ██╔══██║██╔══██╗██╔══╝  ██║╚██╗██║
    ║   ██║     ██║  ██║██║  ██║███████║██║ ╚████║   ██║       ██║  ██║███████╗╚██████╔╝╚██████╔╝██║     ██║  ██║██║  ██║███████╗██║ ╚████║
    ║   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
[/]
[dim]    Professional Bug Bounty Scanner v{__version__}[/]
"""
    console.print(banner)


def _print_summary(result) -> None:
    table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Target", result.target)
    table.add_row("URLs Scanned", str(result.urls_scanned))
    table.add_row("Modules Run", str(len(result.modules_run)))
    table.add_row("Total Findings", str(len(result.findings)))
    table.add_row("Critical", f"[bold red]{result.critical_count}[/]")
    table.add_row("High", f"[bold yellow]{result.high_count}[/]")
    table.add_row("Medium", f"[yellow]{result.medium_count}[/]")
    table.add_row("Low", f"[blue]{result.low_count}[/]")
    table.add_row("Info", f"[dim]{result.info_count}[/]")
    console.print()
    console.print(table)

    if result.findings:
        console.print()
        findings_table = Table(title="Top Findings", show_header=True, header_style="bold red")
        findings_table.add_column("Severity", width=10)
        findings_table.add_column("Name", width=35)
        findings_table.add_column("CVSS", width=6)
        findings_table.add_column("URL", width=50)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_f = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 5))
        for f in sorted_f[:15]:
            color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}.get(f.severity, "white")
            findings_table.add_row(
                f"[{color}]{f.severity}[/]",
                f.name[:35],
                str(f.cvss_score),
                f.url[:50],
            )
        console.print(findings_table)


if __name__ == "__main__":
    app()
