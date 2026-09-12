from __future__ import annotations

import re

from phantomrecon.analyzers.base import BaseAnalyzer
from phantomrecon.logger import log
from phantomrecon.models.finding import CrawlResult, Finding


class CVEAnalyzer(BaseAnalyzer):
    """Known CVE detection via response fingerprinting."""

    name = "cve"
    category = "vulnerable-components"

    CVE_SIGNATURES = [
        {
            "id": "CVE-2021-44228",
            "name": "Log4Shell (Log4j RCE)",
            "severity": "CRITICAL",
            "patterns": [r"org\.apache\.logging\.log4j"],
            "description": "Apache Log4j2 potentially vulnerable to Log4Shell.",
            "remediation": "Update Log4j to version 2.17.0+. Remove JndiLookup class.",
            "cwe": "CWE-502",
        },
        {
            "id": "CVE-2022-22965",
            "name": "Spring4Shell (Spring Framework RCE)",
            "severity": "CRITICAL",
            "patterns": [r"springframework.*5\.[0-3]\.", r"Whitelabel Error Page"],
            "description": "Spring Framework potentially vulnerable to Spring4Shell.",
            "remediation": "Update Spring Framework to 5.3.18+ or 5.2.20+.",
            "cwe": "CWE-94",
        },
        {
            "id": "CVE-2014-6271",
            "name": "Shellshock (Bash RCE)",
            "severity": "CRITICAL",
            "patterns": [r"502 Bad Gateway.*bash", r"CGI.*error"],
            "description": "Bash CGI potentially vulnerable to Shellshock.",
            "remediation": "Update Bash to patched version.",
            "cwe": "CWE-78",
        },
        {
            "id": "CVE-2017-5638",
            "name": "Apache Struts2 RCE",
            "severity": "CRITICAL",
            "patterns": [r"struts2?[- ].*2\.[0-3]\.", r"Struts Problem Report"],
            "description": "Apache Struts2 potentially vulnerable to RCE.",
            "remediation": "Update Struts to latest version.",
            "cwe": "CWE-94",
        },
        {
            "id": "CVE-2019-0708",
            "name": "BlueKeep (RDP RCE)",
            "severity": "CRITICAL",
            "patterns": [r"Remote Desktop.*6\.[0-3]\."],
            "description": "Windows RDP potentially vulnerable to BlueKeep.",
            "remediation": "Apply Microsoft security update for CVE-2019-0708.",
            "cwe": "CWE-410",
        },
    ]

    VERSION_PATTERNS = [
        (r"Apache/(\d+\.\d+\.\d+)", "Apache"),
        (r"nginx/(\d+\.\d+\.\d+)", "Nginx"),
        (r"IIS/(\d+\.\d+)", "Microsoft IIS"),
        (r"PHP/(\d+\.\d+\.\d+)", "PHP"),
        (r"X-Powered-By: PHP/(\d+\.\d+)", "PHP"),
        (r"Express/", "Express.js"),
        (r"WordPress/(\d+\.\d+\.\d+)", "WordPress"),
        (r"Joomla! (\d+\.\d+)", "Joomla"),
        (r"Drupal/(\d+\.\d+)", "Drupal"),
    ]

    async def analyze(self, crawl_result: CrawlResult, oob_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        tested: set[str] = set()

        for url in crawl_result.urls[:30]:
            base = url.split("?")[0]
            if base in tested:
                continue
            tested.add(base)

            try:
                resp = await self.client.get(url)
                body = resp.text
                headers = dict(resp.headers)

                for cve in self.CVE_SIGNATURES:
                    for pattern in cve["patterns"]:
                        if re.search(pattern, body, re.IGNORECASE):
                            findings.append(self._make_finding(
                                rule_id=cve["id"],
                                name=cve["name"],
                                severity=cve["severity"],
                                confidence=0.6,
                                url=url,
                                evidence=f"Pattern matched: {pattern}",
                                description=cve["description"],
                                remediation=cve["remediation"],
                                cwe=cve["cwe"],
                                owasp="A06:2021",
                            ))
                            break

                all_text = body + " ".join(f"{k}: {v}" for k, v in headers.items())
                for pattern, tech_name in self.VERSION_PATTERNS:
                    match = re.search(pattern, all_text, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.groups() else "unknown"
                        findings.append(self._make_finding(
                            rule_id="VER-001",
                            name=f"{tech_name} Version Disclosed",
                            severity="INFO",
                            confidence=0.9,
                            url=url,
                            evidence=f"{tech_name} version: {version}",
                            description=f"{tech_name} version {version} disclosed.",
                            remediation=f"Update {tech_name} to latest stable version.",
                            cwe="CWE-200",
                            owasp="A06:2021",
                        ))
            except Exception:
                continue

        log.info(f"  [bold]{self.name}:[/] {len(findings)} findings")
        return findings
