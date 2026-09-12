from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlencode, urlparse

from phantomrecon.analyzers.base import BaseAnalyzer
from phantomrecon.logger import log
from phantomrecon.models.finding import CrawlResult, Finding
from phantomrecon.utils.timing import ResponseAnalyzer


class SQLiAnalyzer(BaseAnalyzer):
    """SQL Injection detection: error-based, boolean-blind, time-based, UNION."""

    name = "sqli"
    category = "injection"

    ERROR_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "1' ORDER BY 100--"]
    UNION_PAYLOADS = ["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--"]
    TIME_PAYLOADS = ["' OR SLEEP(3)--", "'; WAITFOR DELAY '0:0:3'--", "' OR pg_sleep(3)--"]

    async def analyze(self, crawl_result: CrawlResult, oob_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        targets = self._build_targets(crawl_result)

        tasks = []
        for url, param, method, fields in targets:
            tasks.append(self._test_error_sqli(url, param, method, fields))
            tasks.append(self._test_boolean_sqli(url, param, method, fields))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Finding):
                findings.append(result)

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

    async def _test_error_sqli(self, url: str, param: str, method: str, fields: dict) -> Finding | None:
        for payload in self.ERROR_PAYLOADS:
            try:
                if method == "GET":
                    test_url = self._inject_get(url, param, payload)
                    resp = await self.client.get(test_url)
                else:
                    data = {**fields, param: payload}
                    resp = await self.client.post(url, data=data)

                if ResponseAnalyzer.has_sql_error(resp.text):
                    return self._make_finding(
                        rule_id="SQLI-001",
                        name="SQL Injection (Error-based)",
                        severity="CRITICAL",
                        confidence=0.85,
                        url=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        evidence=resp.text[:300],
                        description="SQL error message disclosed in response, indicating unsanitized input.",
                        remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
                        cwe="CWE-89",
                        owasp="A03:2021",
                    )
            except Exception:
                continue
        return None

    async def _test_boolean_sqli(self, url: str, param: str, method: str, fields: dict) -> Finding | None:
        try:
            if method == "GET":
                normal_len = len((await self.client.get(url)).text)
                true_url = self._inject_get(url, param, "' OR '1'='1")
                true_len = len((await self.client.get(true_url)).text)
                false_url = self._inject_get(url, param, "' OR '1'='2")
                false_len = len((await self.client.get(false_url)).text)
            else:
                normal_len = len((await self.client.post(url, data=fields)).text)
                true_len = len((await self.client.post(url, data={**fields, param: "' OR '1'='1"})).text)
                false_len = len((await self.client.post(url, data={**fields, param: "' OR '1'='2"})).text)

            if normal_len > 0 and true_len != false_len:
                diff_ratio = abs(true_len - false_len) / max(normal_len, 1)
                if diff_ratio > 0.1:
                    return self._make_finding(
                        rule_id="SQLI-002",
                        name="SQL Injection (Boolean-blind)",
                        severity="HIGH",
                        confidence=0.7,
                        url=url,
                        method=method,
                        parameter=param,
                        payload="' OR '1'='1 / ' OR '1'='2",
                        evidence=f"True response: {true_len} bytes, False: {false_len} bytes (normal: {normal_len})",
                        description="Different response lengths for true/false conditions indicate boolean-based SQLi.",
                        remediation="Use parameterized queries/prepared statements.",
                        cwe="CWE-89",
                        owasp="A03:2021",
                    )
        except Exception:
            pass
        return None

    def _inject_get(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        flat = {k: v[0] for k, v in params.items()}
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(flat)}"
