from __future__ import annotations

import json
from pathlib import Path

from phantomrecon.logger import log
from phantomrecon.models.finding import ScanResult


def generate_json_report(result: ScanResult, output_dir: Path) -> Path:
    """Export scan results to JSON."""
    output_dir.mkdir(parents=True, exist_ok=True)
    filepath = output_dir / "findings.json"

    data = {
        "target": result.target,
        "total_findings": len(result.findings),
        "summary": {
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "info": result.info_count,
        },
        "urls_scanned": result.urls_scanned,
        "modules_run": result.modules_run,
        "findings": [f.model_dump() for f in result.findings],
    }

    filepath.write_text(json.dumps(data, indent=2, default=str))
    log.info(f"  [bold green]JSON report:[/] {filepath}")
    return filepath
