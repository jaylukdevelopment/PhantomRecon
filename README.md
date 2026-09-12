# PhantomRecon

**Professional Bug Bounty Vulnerability Scanner**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

PhantomRecon is a comprehensive, async-first web vulnerability scanner designed for professional bug bounty hunters and penetration testers. Built with Python's `asyncio` and `httpx`, it provides high-throughput scanning with intelligent noise reduction, WAF evasion, and multi-format reporting.

> **DISCLAIMER**: This tool is intended solely for authorized security testing. Unauthorized scanning is illegal. Use only on systems you own or have explicit written permission to test.

---

## Features

| Category | Capability |
|---|---|
| **Interface** | CLI (typer + rich) + Streamlit web dashboard |
| **Scan Engine** | Async-first with configurable rate limiting |
| **WAF Evasion** | UA rotation pool, payload mutation engine |
| **OOB Detection** | Built-in async callback listener for blind vulnerabilities |
| **Reporting** | JSON, HTML (dark theme), Markdown (HackerOne-style), PoC generator |
| **CVSS Scoring** | Real CVSS v3.1 calculation per finding |
| **False Positive Reduction** | Multi-factor confidence scoring |

## Vulnerability Modules

| Module | Techniques | Severity |
|---|---|---|
| **SQL Injection** | Error-based, Boolean-blind, Time-based, UNION | Critical |
| **XSS** | Reflected, DOM-based, Blind/OOB, Context-aware | High-Critical |
| **SSRF** | Cloud metadata (AWS/GCP/Azure), Internal IP, OOB | High-Critical |
| **LFI/RFI** | Path traversal, PHP wrappers, Null-byte | High |
| **RCE** | Command injection, SSTI (multiple engines) | Critical |
| **XXE** | File read, SSRF via XXE | High |
| **IDOR** | ID enumeration, Parameter manipulation | Medium-High |
| **Open Redirect** | Direct redirect, Meta refresh | Medium |
| **CORS** | Origin reflection, Null origin, Wildcard+creds | Medium-High |
| **Security Headers** | CSP, HSTS, X-Frame-Options, 15+ headers | Low-High |
| **JWT** | None algorithm, Weak secrets, Kid injection | High-Critical |
| **GraphQL** | Introspection, Mutations exposed | Medium-High |
| **Cloud Config** | S3 buckets, Firebase, Azure Blob, GCP metadata | High |
| **Sensitive Files** | .env, .git, phpinfo, backups, debug endpoints | Medium-Critical |
| **CVE Check** | 30+ known CVE templates | Critical |
| **Recon** | Subdomains, Technology fingerprinting, Path discovery | Info |

## Quick Start

### Installation

```bash
git clone https://github.com/jaylukdevelopment/PhantomRecon.git
cd PhantomRecon
pip install -e .
```

### Basic Scan

```bash
# Full scan
phantomrecon scan --url https://target.com

# Targeted modules (faster)
phantomrecon scan --url https://target.com --modules sqli,xss,ssrf

# Authenticated scan
phantomrecon scan --url https://target.com \
  --cookies "session=abc123;csrftoken=xyz" \
  --token "Bearer eyJhbGci..."

# With OOB listener for blind vulns
phantomrecon scan --url https://target.com --oob-port 8888

# Stealth mode
phantomrecon scan --url https://target.com --stealth

# With proxy (Burp Suite)
phantomrecon scan --url https://target.com --proxy http://127.0.0.1:8080
```

### Launch Dashboard

```bash
phantomrecon dashboard --port 8501
```

### Run as Module

```bash
python -m phantomrecon scan --url https://target.com
```

## CLI Reference

```
Usage: phantomrecon scan [OPTIONS]

Options:
  --url TEXT                    Target URL to scan
  --target-file TEXT            File with URLs to scan
  --depth INT                  Crawl depth (default: 3)
  --max-urls INT               Max URLs to crawl (default: 500)
  --concurrency INT            Concurrent requests (default: 15)
  --timeout INT                Request timeout in seconds (default: 12)
  --rate-limit FLOAT           Delay between requests (default: 0.2)
  --modules TEXT               Comma-separated modules (default: all)
  --oob-port INT               OOB listener port (default: 8888)
  --min-confidence FLOAT       Min confidence 0.0-1.0 (default: 0.5)
  --output TEXT                Output directory (default: scan_results)
  --proxy TEXT                 HTTP proxy
  --cookies TEXT               Cookies: name=val,name2=val2
  --headers TEXT               Extra headers: Name:Value,Name2:Value2
  --token TEXT                 Bearer token
  --verbose                    Verbose output
  --stealth                    Stealth mode
  --no-json                    Disable JSON report
  --no-html                    Disable HTML report
  --no-markdown                Disable Markdown report
  --log-file TEXT              Write logs to file
```

## Output Files

| File | Description |
|---|---|
| `scan_results/findings.json` | Machine-readable JSON with full evidence |
| `scan_results/report.html` | Styled HTML report with dark theme |
| `scan_results/report.md` | Markdown report for bug bounty submissions |
| `scan_results/poc_collection.py` | Auto-generated PoC scripts |

## Architecture

```
PhantomRecon/
├── phantomrecon/
│   ├── cli.py              # CLI entry point (typer + rich)
│   ├── config.py           # Global configuration
│   ├── scanner.py          # Core orchestrator
│   ├── crawler.py          # Async BFS crawler
│   ├── http_client.py      # Async HTTP client (httpx)
│   ├── analyzers/          # 16 vulnerability modules
│   ├── evasion/            # WAF detection + payload mutation
│   ├── oob/                # Built-in OOB callback server
│   ├── models/             # Pydantic data models
│   ├── report/             # JSON/HTML/Markdown/PoC generators
│   ├── web/                # Streamlit dashboard
│   └── utils/              # CVSS calculator, timing analysis
└── tests/                  # Test suite
```

## Safe Practice Targets

| Target | URL | Notes |
|---|---|---|
| DVWA | `http://localhost/dvwa` | Docker: `docker run --rm -it -p 80:80 vulnerables/web-dvwa` |
| Juice Shop | `http://localhost:3000` | Docker: `docker run -p 3000:3000 bkimminich/juice-shop` |
| WebGoat | `http://localhost:8080/WebGoat` | Docker: `docker run -p 8080:8080 webgoat/webgoat` |
| Vulnweb | `http://testphp.vulnweb.com` | Public demo by Acunetix |

## Dependencies

- `httpx[http2]` — Async HTTP client
- `aiohttp` — OOB callback server
- `rich` — Terminal UI
- `typer` — CLI framework
- `beautifulsoup4` — HTML parsing
- `streamlit` — Web dashboard
- `plotly` — Charts
- `pydantic` — Data models
- `tldextract` — Domain extraction

## License

MIT License — see [LICENSE](LICENSE) for details.
