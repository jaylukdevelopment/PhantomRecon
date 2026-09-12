from __future__ import annotations

from pathlib import Path

from phantomrecon.logger import log
from phantomrecon.models.finding import ScanResult

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhantomRecon — {target}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0a0a0f;color:#e0e0e0;line-height:1.6}}
.container{{max-width:1200px;margin:0 auto;padding:20px}}
.header{{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:30px;border-radius:12px;margin-bottom:20px;border:1px solid #2a2a4a}}
.header h1{{font-size:28px;background:linear-gradient(90deg,#00d4ff,#7b2ff7);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px}}
.header .meta{{color:#888;font-size:14px}}
.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px}}
.stat{{padding:16px;border-radius:8px;text-align:center;border:1px solid #2a2a4a}}
.stat.critical{{background:#3d0000;border-color:#ff4444}}
.stat.high{{background:#3d2200;border-color:#ff8800}}
.stat.medium{{background:#3d3300;border-color:#ffcc00}}
.stat.low{{background:#002233;border-color:#44aaff}}
.stat.info{{background:#0d1f0d;border-color:#44ff44}}
.stat .num{{font-size:32px;font-weight:bold}}
.stat .label{{font-size:12px;text-transform:uppercase;color:#aaa}}
.finding{{background:#12121f;border:1px solid #2a2a4a;border-radius:8px;margin-bottom:16px;overflow:hidden}}
.finding-header{{padding:16px;cursor:pointer;display:flex;align-items:center;gap:12px}}
.finding-header:hover{{background:#1a1a30}}
.severity{{padding:4px 10px;border-radius:4px;font-size:12px;font-weight:bold;text-transform:uppercase}}
.severity.CRITICAL{{background:#ff4444;color:#fff}}
.severity.HIGH{{background:#ff8800;color:#fff}}
.severity.MEDIUM{{background:#ffcc00;color:#000}}
.severity.LOW{{background:#44aaff;color:#000}}
.severity.INFO{{background:#44ff44;color:#000}}
.finding-title{{font-size:16px;font-weight:600;flex:1}}
.finding-meta{{color:#888;font-size:13px}}
.finding-body{{padding:0 16px 16px;display:none}}
.finding.open .finding-body{{display:block}}
.detail-row{{margin-bottom:12px}}
.detail-label{{font-size:12px;color:#888;text-transform:uppercase;margin-bottom:4px}}
.detail-value{{font-size:14px;padding:8px;background:#0a0a14;border-radius:4px;word-break:break-all;font-family:monospace}}
pre{{background:#0a0a14;padding:12px;border-radius:4px;overflow-x:auto;font-size:13px}}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>PhantomRecon Scan Report</h1>
<div class="meta">Target: {target} | Scan Date: {date}</div>
</div>
<div class="stats">
<div class="stat critical"><div class="num">{critical}</div><div class="label">Critical</div></div>
<div class="stat high"><div class="num">{high}</div><div class="label">High</div></div>
<div class="stat medium"><div class="num">{medium}</div><div class="label">Medium</div></div>
<div class="stat low"><div class="num">{low}</div><div class="label">Low</div></div>
<div class="stat info"><div class="num">{info}</div><div class="label">Info</div></div>
</div>
{findings_html}
</div>
<script>
document.querySelectorAll('.finding-header').forEach(h=>{{
h.onclick=()=>h.parentElement.classList.toggle('open')
}})
</script>
</body></html>"""

FINDING_TEMPLATE = """
<div class="finding">
<div class="finding-header">
<span class="severity {severity}">{severity}</span>
<span class="finding-title">{name}</span>
<span class="finding-meta">CVSS: {cvss} | Confidence: {confidence}%</span>
</div>
<div class="finding-body">
<div class="detail-row"><div class="detail-label">URL</div><div class="detail-value">{url}</div></div>
<div class="detail-row"><div class="detail-label">Parameter</div><div class="detail-value">{parameter}</div></div>
<div class="detail-row"><div class="detail-label">Payload</div><pre>{payload}</pre></div>
<div class="detail-row"><div class="detail-label">Evidence</div><pre>{evidence}</pre></div>
<div class="detail-row"><div class="detail-label">Description</div><div class="detail-value">{description}</div></div>
<div class="detail-row"><div class="detail-label">Remediation</div><div class="detail-value">{remediation}</div></div>
<div class="detail-row"><div class="detail-label">CWE / OWASP</div><div class="detail-value">{cwe} | {owasp}</div></div>
<div class="detail-row"><div class="detail-label">PoC (curl)</div><pre>{poc_curl}</pre></div>
</div></div>"""


def generate_html_report(result: ScanResult, output_dir: Path) -> Path:
    from datetime import datetime

    output_dir.mkdir(parents=True, exist_ok=True)
    filepath = output_dir / "report.html"

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 5))

    findings_html = "\n".join(
        FINDING_TEMPLATE.format(
            severity=f.severity,
            name=f.name,
            cvss=f.cvss_score,
            confidence=f"{f.confidence * 100:.0f}",
            url=f.url,
            parameter=f.parameter,
            payload=_escape(f.payload),
            evidence=_escape(f.evidence),
            description=f.description,
            remediation=f.remediation,
            cwe=f.cwe,
            owasp=f.owasp,
            poc_curl=_escape(f.poc_curl),
        )
        for f in sorted_findings
    )

    html = HTML_TEMPLATE.format(
        target=result.target,
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        critical=result.critical_count,
        high=result.high_count,
        medium=result.medium_count,
        low=result.low_count,
        info=result.info_count,
        findings_html=findings_html,
    )

    filepath.write_text(html)
    log.info(f"  [bold green]HTML report:[/] {filepath}")
    return filepath


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
