from __future__ import annotations

import asyncio

from phantomrecon.analyzers.base import BaseAnalyzer
from phantomrecon.logger import log
from phantomrecon.models.finding import CrawlResult, Finding


class CloudConfigAnalyzer(BaseAnalyzer):
    """Cloud misconfiguration detection: AWS S3, Firebase, GCP, Azure."""

    name = "cloud"
    category = "misconfiguration"

    FIREBASE_PATHS = [".json", "/.json"]
    S3_INDICATORS = ["<ListBucketResult", "AccessDenied", "NoSuchBucket"]
    GCS_INDICATORS = ["<ListBucketResult", "NoSuchBucket"]
    AZURE_INDICATORS = ["<EnumerationResults", "InvalidAuthenticationInfo"]

    async def analyze(self, crawl_result: CrawlResult, oob_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        tasks = [self._check_cloud(url) for url in crawl_result.urls[:50]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
        log.info(f"  [bold]{self.name}:[/] {len(findings)} findings")
        return findings

    async def _check_cloud(self, url: str) -> list[Finding]:
        findings = []
        try:
            resp = await self.client.get(url)
            body = resp.text

            for indicator in self.S3_INDICATORS:
                if indicator in body:
                    findings.append(self._make_finding(
                        rule_id="CLOUD-001",
                        name="AWS S3 Bucket Exposed",
                        severity="HIGH",
                        confidence=0.8,
                        url=url,
                        evidence=f"S3 response detected: {indicator}",
                        description="AWS S3 bucket listing may be publicly accessible.",
                        remediation="Restrict S3 bucket permissions. Enable bucket policies.",
                        cwe="CWE-538",
                        owasp="A05:2021",
                    ))
                    break

            for indicator in self.AZURE_INDICATORS:
                if indicator in body:
                    findings.append(self._make_finding(
                        rule_id="CLOUD-003",
                        name="Azure Blob Storage Exposed",
                        severity="HIGH",
                        confidence=0.8,
                        url=url,
                        evidence=f"Azure response detected: {indicator}",
                        description="Azure Blob container may be publicly accessible.",
                        remediation="Restrict container access policies.",
                        cwe="CWE-538",
                        owasp="A05:2021",
                    ))
                    break
        except Exception:
            pass
        return findings
