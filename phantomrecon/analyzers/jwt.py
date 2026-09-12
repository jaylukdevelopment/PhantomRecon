from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json

from phantomrecon.analyzers.base import BaseAnalyzer
from phantomrecon.logger import log
from phantomrecon.models.finding import CrawlResult, Finding


class JWTAnalyzer(BaseAnalyzer):
    """JWT vulnerability detection: none algorithm, weak secrets, kid injection."""

    name = "jwt"
    category = "authentication"

    WEAK_SECRETS = [
        "secret", "password", "123456", "jwt_secret", "changeme",
        "key", "test", "admin", "supersecret", "mysecret",
        "shhhhh", "keyboard cat", "your-256-bit-secret",
    ]

    async def analyze(self, crawl_result: CrawlResult, oob_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        tasks = [self._test_jwt(url) for url in crawl_result.urls[:30]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Finding):
                findings.append(result)
        log.info(f"  [bold]{self.name}:[/] {len(findings)} findings")
        return findings

    async def _test_jwt(self, url: str) -> list[Finding]:
        findings = []
        try:
            resp = await self.client.get(url)
            auth_header = resp.headers.get("www-authenticate", "")
            if "bearer" not in auth_header.lower():
                token = self._extract_token_from_cookies(resp)
                if not token:
                    return findings
            else:
                token = auth_header.split("Bearer ")[-1].strip()

            parts = token.split(".")
            if len(parts) != 3:
                return findings

            findings.extend(self._test_none_algorithm(token, url))
            findings.extend(self._test_weak_secret(token, url))
            findings.extend(self._test_kid_injection(token, url))
        except Exception:
            pass
        return findings

    def _extract_token_from_cookies(self, resp) -> str | None:
        for name in resp.cookies:
            val = resp.cookies[name]
            parts = val.split(".")
            if len(parts) == 3:
                return val
        return None

    def _test_none_algorithm(self, token: str, url: str) -> list[Finding]:
        findings = []
        parts = token.split(".")
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            if header.get("alg", "").lower() == "none":
                findings.append(self._make_finding(
                    rule_id="JWT-001",
                    name="JWT None Algorithm",
                    severity="CRITICAL",
                    confidence=0.95,
                    url=url,
                    parameter="JWT",
                    payload=token[:200],
                    evidence=f"JWT uses 'none' algorithm: {header}",
                    description="JWT accepts unsigned tokens, enabling authentication bypass.",
                    remediation="Reject 'none' algorithm. Enforce strong algorithms (RS256, ES256).",
                    cwe="CWE-327",
                    owasp="A02:2021",
                ))
        except Exception:
            pass
        return findings

    def _test_weak_secret(self, token: str, url: str) -> list[Finding]:
        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        sig = base64.urlsafe_b64decode(parts[2] + "==")

        for secret in self.WEAK_SECRETS:
            try:
                expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
                if hmac.compare_digest(sig, expected):
                    return [self._make_finding(
                        rule_id="JWT-002",
                        name="JWT Weak Secret",
                        severity="CRITICAL",
                        confidence=0.98,
                        url=url,
                        parameter="JWT",
                        payload=f"Secret: {secret}",
                        evidence=f"JWT signed with weak secret: {secret}",
                        description="JWT signed with easily guessable secret.",
                        remediation="Use a strong, randomly generated secret (256+ bits).",
                        cwe="CWE-327",
                        owasp="A02:2021",
                    )]
            except Exception:
                continue
        return []

    def _test_kid_injection(self, token: str, url: str) -> list[Finding]:
        parts = token.split(".")
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            kid = header.get("kid", "")
            if kid:
                traversal_payloads = ["../../etc/passwd", "/dev/null", "null"]
                for payload in traversal_payloads:
                    header["kid"] = payload
                    new_header = base64.urlsafe_b64encode(
                        json.dumps(header).encode()
                    ).rstrip(b"=").decode()
                    f"{new_header}.{parts[1]}.{parts[2]}"
                    return [self._make_finding(
                        rule_id="JWT-003",
                        name="JWT Kid Injection",
                        severity="HIGH",
                        confidence=0.7,
                        url=url,
                        parameter="JWT kid",
                        payload=f"kid={payload}",
                        evidence=f"JWT kid parameter is controllable: {kid}",
                        description="JWT kid parameter may be vulnerable to path traversal or injection.",
                        remediation="Validate kid parameter. Don't use user-controlled values for kid.",
                        cwe="CWE-327",
                        owasp="A02:2021",
                    )]
        except Exception:
            pass
        return []
