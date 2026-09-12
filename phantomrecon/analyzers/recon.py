from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from phantomrecon.analyzers.base import BaseAnalyzer
from phantomrecon.logger import log
from phantomrecon.models.finding import CrawlResult, Finding


class ReconAnalyzer(BaseAnalyzer):
    """Reconnaissance: subdomain enumeration, port scanning, technology fingerprinting."""

    name = "recon"
    category = "reconnaissance"

    COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017]

    async def analyze(self, crawl_result: CrawlResult, oob_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        if not crawl_result.urls:
            return findings

        urlparse(crawl_result.urls[0]).netloc.split(":")[0]

        findings.extend(await self._check_common_paths(crawl_result.urls[0]))
        findings.extend(self._report_tech(crawl_result))

        log.info(f"  [bold]{self.name}:[/] {len(findings)} findings")
        return findings

    async def _check_common_paths(self, base_url: str) -> list[Finding]:
        findings = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        interesting_paths = [
            ("/admin", "Admin panel accessible"),
            ("/.git/HEAD", "Git repository exposed"),
            ("/.env", "Environment file exposed"),
            ("/phpinfo.php", "PHP info page exposed"),
            ("/server-status", "Server status exposed"),
            ("/wp-admin", "WordPress admin accessible"),
            ("/xmlrpc.php", "XML-RPC endpoint accessible"),
        ]

        async def check(path: str, desc: str) -> Finding | None:
            try:
                resp = await self.client.get(base + path)
                if resp.status_code == 200:
                    return self._make_finding(
                        rule_id="RECON-001",
                        name="Interesting Path Discovered",
                        severity="INFO",
                        confidence=0.7,
                        url=base + path,
                        evidence=f"HTTP {resp.status_code} - {desc}",
                        description=desc,
                        remediation="Restrict access to sensitive paths.",
                        cwe="CWE-538",
                        owasp="A05:2021",
                    )
            except Exception:
                pass
            return None

        tasks = [check(p, d) for p, d in interesting_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Finding):
                findings.append(result)

        return findings

    def _report_tech(self, cr: CrawlResult) -> list[Finding]:
        findings = []
        if cr.technologies:
            techs = list(set(cr.technologies))
            findings.append(self._make_finding(
                rule_id="RECON-010",
                name="Technologies Detected",
                severity="INFO",
                confidence=0.85,
                url=cr.urls[0] if cr.urls else "",
                evidence=f"Technologies: {', '.join(techs)}",
                description=f"Detected technologies: {', '.join(techs)}",
                remediation="Ensure all detected technologies are up to date.",
                cwe="CWE-200",
                owasp="A05:2021",
            ))

        if cr.js_urls:
            findings.append(self._make_finding(
                rule_id="RECON-011",
                name="JavaScript Endpoints Discovered",
                severity="INFO",
                confidence=0.7,
                url=cr.urls[0] if cr.urls else "",
                evidence=f"Found {len(cr.js_urls)} JS endpoints",
                description=f"Discovered {len(cr.js_urls)} JavaScript API endpoints.",
                remediation="Review exposed API endpoints for authorization.",
                cwe="CWE-200",
                owasp="A01:2021",
            ))

        return findings
