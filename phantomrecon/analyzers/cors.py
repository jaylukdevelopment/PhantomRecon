from __future__ import annotations

import asyncio

from phantomrecon.analyzers.base import BaseAnalyzer
from phantomrecon.logger import log
from phantomrecon.models.finding import CrawlResult, Finding


class CORSAnalyzer(BaseAnalyzer):
    """CORS misconfiguration detection."""

    name = "cors"
    category = "misconfiguration"

    TEST_ORIGINS = [
        "https://evil.com",
        "https://attacker.com",
        "null",
    ]

    async def analyze(self, crawl_result: CrawlResult, oob_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        tasks = [self._test_cors(url) for url in crawl_result.urls[:30]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Finding):
                findings.append(result)
        log.info(f"  [bold]{self.name}:[/] {len(findings)} findings")
        return findings

    async def _test_cors(self, url: str) -> Finding | None:
        for origin in self.TEST_ORIGINS:
            try:
                resp = await self.client.get(
                    url, headers={"Origin": origin}
                )
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                if acao == "*" and acac.lower() == "true":
                    return self._make_finding(
                        rule_id="CORS-001",
                        name="CORS Misconfiguration (Wildcard + Credentials)",
                        severity="HIGH",
                        confidence=0.95,
                        url=url,
                        evidence="ACAO: * with ACAC: true",
                        description="Server allows any origin with credentials, enabling cross-origin data theft.",
                        remediation="Whitelist specific trusted origins. Never use wildcard with credentials.",
                        cwe="CWE-942",
                        owasp="A05:2021",
                    )

                if acao == origin and origin not in ("",):
                    return self._make_finding(
                        rule_id="CORS-002",
                        name="CORS Misconfiguration (Origin Reflection)",
                        severity="HIGH",
                        confidence=0.9,
                        url=url,
                        evidence=f"ACAO reflects: {origin}",
                        description="Server reflects arbitrary Origin header, allowing cross-origin requests.",
                        remediation="Validate Origin against a strict allow-list.",
                        cwe="CWE-942",
                        owasp="A05:2021",
                    )

                if origin == "null" and acao == "null":
                    return self._make_finding(
                        rule_id="CORS-003",
                        name="CORS Misconfiguration (Null Origin Allowed)",
                        severity="MEDIUM",
                        confidence=0.8,
                        url=url,
                        evidence="ACAO: null accepted",
                        description="Server accepts null Origin, exploitable via sandboxed iframes.",
                        remediation="Reject null Origin. Only allow trusted origins.",
                        cwe="CWE-942",
                        owasp="A05:2021",
                    )
            except Exception:
                continue
        return None
