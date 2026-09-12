from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlencode, urlparse

from phantomrecon.analyzers.base import BaseAnalyzer
from phantomrecon.logger import log
from phantomrecon.models.finding import CrawlResult, Finding


class OpenRedirectAnalyzer(BaseAnalyzer):
    """Open redirect vulnerability detection."""

    name = "redirect"
    category = "access-control"

    REDIRECT_PARAMS = ["url", "redirect", "next", "return", "goto", "dest", "redir", "continue", "rurl", "return_url"]
    REDIRECT_PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "///evil.com",
        "https://evil.com%00.example.com",
    ]

    async def analyze(self, crawl_result: CrawlResult, oob_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        targets = self._build_targets(crawl_result)

        tasks = [self._test_redirect(url, param, method) for url, param, method in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Finding):
                findings.append(result)

        log.info(f"  [bold]{self.name}:[/] {len(findings)} findings")
        return findings

    def _build_targets(self, cr: CrawlResult) -> list[tuple[str, str, str]]:
        targets = []
        for form in cr.forms:
            for param in form["fields"]:
                if any(kw in param.lower() for kw in self.REDIRECT_PARAMS):
                    targets.append((form["url"], param, form["method"]))
        for param, urls in cr.params.items():
            if any(kw in param.lower() for kw in self.REDIRECT_PARAMS):
                for url in urls[:3]:
                    targets.append((url, param, "GET"))
        return targets

    async def _test_redirect(self, url: str, param: str, method: str) -> Finding | None:
        for payload in self.REDIRECT_PAYLOADS:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                flat = {k: v[0] for k, v in params.items()}
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(flat)}"

                resp = await self.client.get(test_url, follow_redirects=False)
                location = resp.headers.get("location", "")

                if "evil.com" in location:
                    return self._make_finding(
                        rule_id="REDIR-001",
                        name="Open Redirect",
                        severity="MEDIUM",
                        confidence=0.9,
                        url=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        evidence=f"Redirect to: {location}",
                        description="Application redirects to user-controlled URL without validation.",
                        remediation="Validate redirect targets against an allow-list. Use indirect references.",
                        cwe="CWE-601",
                        owasp="A01:2021",
                    )

                resp2 = await self.client.get(test_url)
                if "evil.com" in resp2.url:
                    return self._make_finding(
                        rule_id="REDIR-002",
                        name="Open Redirect (meta/JS)",
                        severity="MEDIUM",
                        confidence=0.85,
                        url=url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        evidence=f"Client-side redirect to: {resp2.url}",
                        description="Client-side redirect to user-controlled URL.",
                        remediation="Validate redirect targets.",
                        cwe="CWE-601",
                        owasp="A01:2021",
                    )
            except Exception:
                continue
        return None
