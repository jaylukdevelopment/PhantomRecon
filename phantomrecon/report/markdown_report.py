from __future__ import annotations

from pathlib import Path

from phantomrecon.logger import log
from phantomrecon.models.finding import ScanResult


def generate_markdown_report(result: ScanResult, output_dir: Path) -> Path:
    """Export scan results to Markdown (HackerOne-style)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    filepath = output_dir / "report.md"

    lines = [
        "# PhantomRecon Scan Report",
        "",
        f"**Target:** {result.target}",
        f"**URLs Scanned:** {result.urls_scanned}",
        f"**Modules Run:** {', '.join(result.modules_run)}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| Critical | {result.critical_count} |",
        f"| High | {result.high_count} |",
        f"| Medium | {result.medium_count} |",
        f"| Low | {result.low_count} |",
        f"| Info | {result.info_count} |",
        "",
    ]

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 5))

    if sorted_findings:
        lines.append("## Findings\n")
        for i, f in enumerate(sorted_findings, 1):
            lines.extend([
                f"### {i}. [{f.severity}] {f.name}",
                "",
                f"- **URL:** {f.url}",
                f"- **Parameter:** `{f.parameter}`",
                f"- **CVSS Score:** {f.cvss_score}",
                f"- **CWE:** {f.cwe}",
                f"- **OWASP:** {f.owasp}",
                "",
                f"**Description:** {f.description}",
                "",
                "**Payload:**",
                "```",
                f"{f.payload}",
                "```",
                "",
                "**Evidence:**",
                "```",
                f"{f.evidence}",
                "```",
                "",
                f"**Remediation:** {f.remediation}",
                "",
                "**PoC (curl):**",
                "```bash",
                f"{f.poc_curl}",
                "```",
                "",
                "---",
                "",
            ])

    filepath.write_text("\n".join(lines))
    log.info(f"  [bold green]Markdown report:[/] {filepath}")
    return filepath
