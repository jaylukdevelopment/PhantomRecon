from __future__ import annotations

from abc import ABC, abstractmethod

from phantomrecon.config import ScanConfig
from phantomrecon.http_client import AsyncHTTPClient
from phantomrecon.models.finding import CrawlResult, Finding
from phantomrecon.utils.cvss import CVSSv31Calculator


class BaseAnalyzer(ABC):
    """Abstract base class for all vulnerability analyzers."""

    name: str = "base"
    category: str = "general"

    def __init__(self, client: AsyncHTTPClient, config: ScanConfig) -> None:
        self.client = client
        self.config = config

    @abstractmethod
    async def analyze(
        self,
        crawl_result: CrawlResult,
        oob_url: str = "",
    ) -> list[Finding]:
        ...

    def _make_finding(
        self,
        *,
        rule_id: str,
        name: str,
        severity: str,
        confidence: float,
        url: str,
        method: str = "GET",
        parameter: str = "",
        payload: str = "",
        evidence: str = "",
        description: str = "",
        remediation: str = "",
        cwe: str = "",
        owasp: str = "",
    ) -> Finding:
        score, vector = CVSSv31Calculator.from_severity(severity)
        poc_curl = self._generate_curl(method, url, parameter, payload)
        poc_python = self._generate_python(method, url, parameter, payload)

        return Finding(
            rule_id=rule_id,
            name=name,
            category=self.category,
            severity=severity,
            confidence=min(max(confidence, 0.0), 1.0),
            url=url,
            method=method,
            parameter=parameter,
            payload=payload,
            evidence=evidence[:500],
            description=description,
            remediation=remediation,
            cwe=cwe,
            owasp=owasp,
            cvss_score=score,
            cvss_vector=vector,
            poc_curl=poc_curl,
            poc_python=poc_python,
        )

    def _generate_curl(self, method: str, url: str, param: str, payload: str) -> str:
        if method == "GET":
            from urllib.parse import parse_qs, urlencode, urlparse

            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param] = [payload]
            flat = {k: v[0] for k, v in params.items()}
            new_q = urlencode(flat)
            new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_q}"
            return f"curl -k '{new_url}'"
        else:
            return f"curl -k -X {method} -d '{param}={payload}' '{url}'"

    def _generate_python(self, method: str, url: str, param: str, payload: str) -> str:
        if method == "GET":
            return (
                f"import httpx\n"
                f"r = httpx.{method.lower()}('{url}', params={{'{param}': '{payload}'}}, verify=False)\n"
                f"print(r.text)"
            )
        else:
            return (
                f"import httpx\n"
                f"r = httpx.{method.lower()}('{url}', data={{'{param}': '{payload}'}}, verify=False)\n"
                f"print(r.text)"
            )
