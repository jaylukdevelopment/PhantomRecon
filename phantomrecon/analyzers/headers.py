from __future__ import annotations

from phantomrecon.analyzers.base import BaseAnalyzer
from phantomrecon.logger import log
from phantomrecon.models.finding import CrawlResult, Finding


class HeadersAnalyzer(BaseAnalyzer):
    """Security headers analysis."""

    name = "headers"
    category = "misconfiguration"

    REQUIRED_HEADERS = {
        "content-security-policy": {
            "id": "HDR-001",
            "name": "Missing Content-Security-Policy",
            "severity": "MEDIUM",
            "description": "CSP header missing, increasing XSS attack surface.",
            "remediation": "Implement a strict Content-Security-Policy header.",
            "cwe": "CWE-693",
        },
        "strict-transport-security": {
            "id": "HDR-002",
            "name": "Missing Strict-Transport-Security",
            "severity": "HIGH",
            "description": "HSTS header missing, allowing protocol downgrade attacks.",
            "remediation": "Add Strict-Transport-Security header with max-age >= 31536000.",
            "cwe": "CWE-319",
        },
        "x-frame-options": {
            "id": "HDR-003",
            "name": "Missing X-Frame-Options",
            "severity": "MEDIUM",
            "description": "Clickjacking protection header missing.",
            "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN.",
            "cwe": "CWE-1021",
        },
        "x-content-type-options": {
            "id": "HDR-004",
            "name": "Missing X-Content-Type-Options",
            "severity": "LOW",
            "description": "MIME sniffing protection header missing.",
            "remediation": "Add X-Content-Type-Options: nosniff.",
            "cwe": "CWE-693",
        },
        "x-xss-protection": {
            "id": "HDR-005",
            "name": "Missing X-XSS-Protection",
            "severity": "LOW",
            "description": "Legacy XSS protection header missing.",
            "remediation": "Add X-XSS-Protection: 1; mode=block.",
            "cwe": "CWE-79",
        },
        "referrer-policy": {
            "id": "HDR-006",
            "name": "Missing Referrer-Policy",
            "severity": "LOW",
            "description": "Referrer information may leak to third parties.",
            "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin.",
            "cwe": "CWE-200",
        },
        "permissions-policy": {
            "id": "HDR-007",
            "name": "Missing Permissions-Policy",
            "severity": "LOW",
            "description": "Browser feature restrictions not configured.",
            "remediation": "Add Permissions-Policy to restrict camera, microphone, etc.",
            "cwe": "CWE-693",
        },
    }

    async def analyze(self, crawl_result: CrawlResult, oob_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        tested: set[str] = set()

        for url in crawl_result.urls[:20]:
            base = url.split("?")[0]
            if base in tested:
                continue
            tested.add(base)

            try:
                resp = await self.client.get(url)
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                findings.extend(self._check_missing_headers(url, headers_lower))
                findings.extend(self._check_server_disclosure(url, headers_lower))
            except Exception:
                continue

        log.info(f"  [bold]{self.name}:[/] {len(findings)} findings")
        return findings

    def _check_missing_headers(self, url: str, headers: dict) -> list[Finding]:
        findings = []
        for header, info in self.REQUIRED_HEADERS.items():
            if header not in headers:
                findings.append(self._make_finding(
                    rule_id=info["id"],
                    name=info["name"],
                    severity=info["severity"],
                    confidence=0.95,
                    url=url,
                    parameter=header,
                    evidence=f"Header '{header}' not present in response",
                    description=info["description"],
                    remediation=info["remediation"],
                    cwe=info["cwe"],
                    owasp="A05:2021",
                ))
        return findings

    def _check_server_disclosure(self, url: str, headers: dict) -> list[Finding]:
        findings = []
        server = headers.get("server", "")
        if server and any(v in server.lower() for v in ["apache", "nginx", "iis", "tomcat"]):
            findings.append(self._make_finding(
                rule_id="HDR-010",
                name="Server Version Disclosure",
                severity="INFO",
                confidence=0.99,
                url=url,
                parameter="Server",
                evidence=f"Server header: {server}",
                description="Server version disclosed, aiding attacker reconnaissance.",
                remediation="Remove or obfuscate Server header.",
                cwe="CWE-200",
                owasp="A05:2021",
            ))

        powered = headers.get("x-powered-by", "")
        if powered:
            findings.append(self._make_finding(
                rule_id="HDR-011",
                name="Technology Disclosure",
                severity="INFO",
                confidence=0.99,
                url=url,
                parameter="X-Powered-By",
                evidence=f"X-Powered-By: {powered}",
                description="Technology stack disclosed via response header.",
                remediation="Remove X-Powered-By header.",
                cwe="CWE-200",
                owasp="A05:2021",
            ))
        return findings
