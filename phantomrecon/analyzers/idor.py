from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlencode, urlparse

from phantomrecon.analyzers.base import BaseAnalyzer
from phantomrecon.logger import log
from phantomrecon.models.finding import CrawlResult, Finding


class IDORAnalyzer(BaseAnalyzer):
    """Insecure Direct Object Reference detection via ID enumeration."""

    name = "idor"
    category = "access-control"

    ID_PARAMS = ["id", "user_id", "userid", "uid", "account", "profile", "order", "file", "doc"]

    async def analyze(self, crawl_result: CrawlResult, oob_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        targets = self._build_targets(crawl_result)

        tasks = [self._test_idor(url, param, method) for url, param, method in targets]
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
                if any(kw in param.lower() for kw in self.ID_PARAMS):
                    targets.append((form["url"], param, form["method"]))
        for param, urls in cr.params.items():
            if any(kw in param.lower() for kw in self.ID_PARAMS):
                for url in urls[:3]:
                    targets.append((url, param, "GET"))
        return targets

    async def _test_idor(self, url: str, param: str, method: str) -> Finding | None:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            original_val = params.get(param, ["1"])[0]

            try:
                original_id = int(original_val)
            except ValueError:
                return None

            test_ids = [original_id - 1, original_id + 1, 1, 0]
            original_len = len((await self.client.get(url)).text)

            for test_id in test_ids:
                if test_id == original_id:
                    continue
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = str(test_id)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                resp = await self.client.get(test_url)
                if resp.status_code == 200 and len(resp.text) > 100:
                    diff = abs(len(resp.text) - original_len) / max(original_len, 1)
                    if diff < 0.3:
                        return self._make_finding(
                            rule_id="IDOR-001",
                            name="Insecure Direct Object Reference",
                            severity="MEDIUM",
                            confidence=0.6,
                            url=url,
                            method=method,
                            parameter=param,
                            payload=f"{original_id} -> {test_id}",
                            evidence=f"Sequential ID enumeration returns valid data (original: {original_id}, tested: {test_id})",
                            description="Application allows accessing other users' objects by modifying IDs.",
                            remediation="Implement authorization checks. Use indirect references (UUIDs, slugs).",
                            cwe="CWE-639",
                            owasp="A01:2021",
                        )
        except Exception:
            pass
        return None
