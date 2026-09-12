from __future__ import annotations

from pathlib import Path

from phantomrecon.logger import log
from phantomrecon.models.finding import ScanResult


def generate_poc_report(result: ScanResult, output_dir: Path) -> Path:
    """Generate PoC code for all findings."""
    output_dir.mkdir(parents=True, exist_ok=True)
    filepath = output_dir / "poc_collection.py"

    lines = [
        "#!/usr/bin/env python3",
        '"""PhantomRecon PoC Collection — Auto-generated proof-of-concept scripts."""',
        "",
        "import httpx",
        "import sys",
        "",
        "",
        "def main():",
        '    target = sys.argv[1] if len(sys.argv) > 1 else ""',
        "    if not target:",
        '        print("Usage: python poc_collection.py <target_url>")',
        "        return",
        "",
    ]

    for i, f in enumerate(result.findings, 1):
        lines.extend([
            f"    # PoC {i}: {f.name} ({f.severity})",
            f"    print(f'\\n[*] Testing PoC {i}: {f.name}')",
            "    try:",
            f"        {f.poc_python.replace(chr(10), chr(10) + '        ')}",
            "    except Exception as e:",
            "        print(f'    Error: {e}')",
            "",
        ])

    lines.extend([
        "",
        'if __name__ == "__main__":',
        "    main()",
    ])

    filepath.write_text("\n".join(lines))
    log.info(f"  [bold green]PoC report:[/] {filepath}")
    return filepath
