from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlencode, urlparse

from phantomrecon.analyzers.base import BaseAnalyzer
from phantomrecon.logger import log
from phantomrecon.models.finding import CrawlResult, Finding


class SSRFAnalyzer(BaseAnalyzer):
    """Server-Side Request Forgery detection: cloud metadata, internal probing."""

    name = "ssrf"
    category = "server-side"

    INTERNAL_TARGETS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://169.254.169.254",
    ]

    CLOUD_METADATA = {
        "AWS": "http://169.254.169.254/latest/meta-data/",
        "GCP": "http://metadata.google.internal/computeMetadata/v1/",
        "Azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    }

    URL_PARAM_NAMES = ["url", "uri", "path", "dest", "redirect", "src", "href", "link", "feed", "img", "image", "fetch", "load", "page", "file", "reference"]

    async def analyze(self, crawl_result: CrawlResult, oob_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        url_targets = self._build_url_targets(crawl_result)

        tasks = []
        for url, param, method in url_targets:
            tasks.append(self._test_internal_ssrf(url, param, method))
            for cloud, meta_url in self.CLOUD_METADATA.items():
                tasks.append(self._test_cloud_ssrf(url, param, method, cloud, meta_url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Finding):
                findings.append(result)

        if oob_url:
            oob_findings = await self._test_oob_ssrf(crawl_result, oob_url)
            findings.extend(oob_findings)

        log.info(f"  [bold]{self.name}:[/] {len(findings)} findings")
        return findings

    def _build_url_targets(self, cr: CrawlResult) -> list[tuple[str, str, str]]:
        targets = []
        for form in cr.forms:
            for param in form["fields"]:
                if any(kw in param.lower() for kw in self.URL_PARAM_NAMES):
                    targets.append((form["url"], param, form["method"]))
        for param, urls in cr.params.items():
            if any(kw in param.lower() for kw in self.URL_PARAM_NAMES):
                for url in urls[:3]:
                    targets.append((url, param, "GET"))
        return targets

    async def _test_internal_ssrf(self, url: str, param: str, method: str) -> Finding | None:
        for target in self.INTERNAL_TARGETS:
            try:
                test_url = self._inject_url(url, param, target)
                resp = await self.client.get(test_url)
                if resp.status_code == 200 and len(resp.text) > 100:
                    return self._make_finding(
                        rule_id="SSRF-001",
                        name="SSRF - Internal Host Access",
                        severity="HIGH",
                        confidence=0.7,
                        url=url,
                        method=method,
                        parameter=param,
                        payload=target,
                        evidence=f"Successfully accessed internal host: {target} (status: {resp.status_code})",
                        description="Server fetches internal resources, potentially exposing internal network.",
                        remediation="Implement allow-list for outbound requests. Block internal IP ranges.",
                        cwe="CWE-918",
                        owasp="A10:2021",
                    )
            except Exception:
                continue
        return None

    async def _test_cloud_ssrf(
        self, url: str, param: str, method: str, cloud: str, meta_url: str
    ) -> Finding | None:
        try:
            test_url = self._inject_url(url, param, meta_url)
            resp = await self.client.get(test_url)
            body = resp.text.lower()
            if resp.status_code == 200 and any(
                kw in body for kw in ["ami-id", "instance-id", "metadata", "compute"]
            ):
                return self._make_finding(
                    rule_id=f"SSRF-{cloud.upper()}",
                    name=f"SSRF - {cloud} Metadata Exposure",
                    severity="CRITICAL",
                    confidence=0.9,
                    url=url,
                    method=method,
                    parameter=param,
                    payload=meta_url,
                    evidence=f"Cloud metadata accessible at {meta_url}",
                    description=f"Server exposes {cloud} instance metadata, enabling credential theft.",
                    remediation="Disable IMDSv1. Use IMDSv2 with hop limit. Block metadata endpoints.",
                    cwe="CWE-918",
                    owasp="A10:2021",
                )
        except Exception:
            pass
        return None

    async def _test_oob_ssrf(self, cr: CrawlResult, oob_url: str) -> list[Finding]:
        findings = []
        targets = self._build_url_targets(cr)[:5]
        for url, param, _method in targets:
            try:
                test_url = self._inject_url(url, param, oob_url)
                await self.client.get(test_url)
            except Exception:
                continue
        return findings

    def _inject_url(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        flat = {k: v[0] for k, v in params.items()}
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(flat)}"
