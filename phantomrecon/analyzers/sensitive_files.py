from __future__ import annotations

import asyncio

from phantomrecon.analyzers.base import BaseAnalyzer
from phantomrecon.logger import log
from phantomrecon.models.finding import CrawlResult, Finding


class SensitiveFilesAnalyzer(BaseAnalyzer):
    """Sensitive file exposure detection."""

    name = "sensitive"
    category = "exposure"

    SENSITIVE_PATHS = {
        "/.env": ("ENV-001", ".env file exposed", "CRITICAL", "Environment variables with secrets exposed."),
        "/.git/config": ("GIT-001", ".git directory exposed", "CRITICAL", "Git repository exposed, source code may be accessible."),
        "/.git/HEAD": ("GIT-002", ".git HEAD exposed", "HIGH", "Git repository structure exposed."),
        "/phpinfo.php": ("INFO-001", "phpinfo() exposed", "MEDIUM", "PHP configuration and environment details exposed."),
        "/.htaccess": ("CFG-001", ".htaccess exposed", "MEDIUM", "Apache configuration file exposed."),
        "/.htpasswd": ("CFG-002", ".htpasswd exposed", "CRITICAL", "Password file exposed."),
        "/server-status": ("INFO-002", "Apache server-status exposed", "MEDIUM", "Server status page publicly accessible."),
        "/server-info": ("INFO-003", "Apache server-info exposed", "MEDIUM", "Server information page publicly accessible."),
        "/elmah.axd": ("CFG-003", "ELMAH error log exposed", "MEDIUM", "ASP.NET error log exposed."),
        "/trace.axd": ("CFG-004", "ASP.NET trace exposed", "MEDIUM", "ASP.NET trace handler exposed."),
        "/web.config": ("CFG-005", "web.config exposed", "HIGH", "ASP.NET configuration file exposed."),
        "/crossdomain.xml": ("CFG-006", "crossdomain.xml exposed", "LOW", "Flash cross-domain policy exposed."),
        "/.well-known/security.txt": ("INFO-004", "security.txt found", "INFO", "Security contact information found."),
        "/readme.html": ("INFO-005", "Readme exposed", "INFO", "Readme file may disclose version info."),
        "/LICENSE.txt": ("INFO-006", "License file exposed", "INFO", "License file may disclose version info."),
        "/api/swagger.json": ("API-001", "Swagger API docs exposed", "MEDIUM", "API documentation publicly accessible."),
        "/api/docs": ("API-002", "API documentation exposed", "MEDIUM", "API documentation publicly accessible."),
        "/debug": ("DBG-001", "Debug endpoint exposed", "HIGH", "Debug endpoint publicly accessible."),
        "/backup": ("BAK-001", "Backup directory exposed", "HIGH", "Backup directory may contain sensitive files."),
    }

    SENSITIVE_BODY_MARKERS = {
        "DB_PASSWORD": "Database password in response body",
        "AWS_SECRET_ACCESS_KEY": "AWS secret key in response body",
        "PRIVATE KEY": "Private key in response body",
    }

    async def analyze(self, crawl_result: CrawlResult, oob_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        base_url = crawl_result.urls[0] if crawl_result.urls else ""
        if not base_url:
            return findings

        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        tasks = [self._check_path(base + path, info) for path, info in self.SENSITIVE_PATHS.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Finding):
                findings.append(result)

        log.info(f"  [bold]{self.name}:[/] {len(findings)} findings")
        return findings

    async def _check_path(self, url: str, path_info: tuple) -> Finding | None:
        rule_id, name, severity, description = path_info
        try:
            resp = await self.client.get(url)
            if resp.status_code == 200 and len(resp.text) > 10:
                evidence = resp.text[:200]
                return self._make_finding(
                    rule_id=rule_id,
                    name=name,
                    severity=severity,
                    confidence=0.9,
                    url=url,
                    evidence=evidence,
                    description=description,
                    remediation="Remove or restrict access to sensitive files.",
                    cwe="CWE-538",
                    owasp="A05:2021",
                )
        except Exception:
            pass
        return None
