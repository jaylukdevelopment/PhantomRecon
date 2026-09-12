from __future__ import annotations

import asyncio
import re
from urllib.parse import parse_qs, urlencode, urlparse

from phantomrecon.analyzers.base import BaseAnalyzer
from phantomrecon.logger import log
from phantomrecon.models.finding import CrawlResult, Finding


class RCEAnalyzer(BaseAnalyzer):
    """Remote Code Execution detection: command injection, SSTI."""

    name = "rce"
    category = "injection"

    CMD_PAYLOADS = [
        ("id", r"uid=\d+"),
        ("$(id)", r"uid=\d+"),
        ("`id`", r"uid=\d+"),
        (";id;", r"uid=\d+"),
        ("|id|", r"uid=\d+"),
        ("||id||", r"uid=\d+"),
    ]

    SSTI_PAYLOADS = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("#{7*7}", "49"),
        ("{{config}}", "class"),
    ]

    async def analyze(self, crawl_result: CrawlResult, oob_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        targets = self._build_targets(crawl_result)

        tasks = []
        for url, param, method, fields in targets:
            for payload, pattern in self.CMD_PAYLOADS:
                tasks.append(self._test_cmd_injection(url, param, method, fields, payload, pattern))
            for payload, expected in self.SSTI_PAYLOADS:
                tasks.append(self._test_ssti(url, param, method, fields, payload, expected))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Finding):
                findings.append(result)

        log.info(f"  [bold]{self.name}:[/] {len(findings)} findings")
        return findings

    def _build_targets(self, cr: CrawlResult) -> list[tuple[str, str, str, dict]]:
        targets = []
        cmd_params = ["cmd", "command", "exec", "execute", "query", "run", "ping",
                       "host", "ip", "domain", "url", "file", "path"]
        for form in cr.forms:
            for param in form["fields"]:
                if any(kw in param.lower() for kw in cmd_params):
                    targets.append((form["url"], param, form["method"], form["fields"]))
        for param, urls in cr.params.items():
            if any(kw in param.lower() for kw in cmd_params):
                for url in urls[:3]:
                    targets.append((url, param, "GET", {}))
        return targets

    async def _test_cmd_injection(
        self, url: str, param: str, method: str, fields: dict, payload: str, pattern: str
    ) -> Finding | None:
        try:
            if method == "GET":
                test_url = self._inject(url, param, payload)
                resp = await self.client.get(test_url)
            else:
                data = {**fields, param: payload}
                resp = await self.client.post(url, data=data)

            if re.search(pattern, resp.text):
                return self._make_finding(
                    rule_id="RCE-001",
                    name="OS Command Injection",
                    severity="CRITICAL",
                    confidence=0.85,
                    url=url,
                    method=method,
                    parameter=param,
                    payload=payload,
                    evidence=f"Command output detected: {re.search(pattern, resp.text).group()[:100]}",
                    description="User input is passed to OS commands without sanitization.",
                    remediation="Use language-native APIs instead of shell commands. Validate and sanitize all input.",
                    cwe="CWE-78",
                    owasp="A03:2021",
                )
        except Exception:
            pass
        return None

    async def _test_ssti(
        self, url: str, param: str, method: str, fields: dict, payload: str, expected: str
    ) -> Finding | None:
        try:
            if method == "GET":
                test_url = self._inject(url, param, payload)
                resp = await self.client.get(test_url)
            else:
                data = {**fields, param: payload}
                resp = await self.client.post(url, data=data)

            if expected in resp.text and payload not in resp.text:
                return self._make_finding(
                    rule_id="RCE-002",
                    name="Server-Side Template Injection (SSTI)",
                    severity="CRITICAL",
                    confidence=0.88,
                    url=url,
                    method=method,
                    parameter=param,
                    payload=payload,
                    evidence=f"Template expression evaluated: {payload} -> {expected}",
                    description="Server evaluates template expressions in user input, enabling RCE.",
                    remediation="Use sandboxed template engines. Never render user input as templates.",
                    cwe="CWE-1336",
                    owasp="A03:2021",
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
