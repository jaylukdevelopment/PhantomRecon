from __future__ import annotations

import asyncio
import time

from phantomrecon.analyzers import ANALYZER_MAP
from phantomrecon.config import ScanConfig
from phantomrecon.crawler import AsyncCrawler
from phantomrecon.evasion import WAFDetector
from phantomrecon.http_client import AsyncHTTPClient
from phantomrecon.logger import log
from phantomrecon.models.finding import ScanResult
from phantomrecon.oob.server import OOBServer
from phantomrecon.report.html_report import generate_html_report
from phantomrecon.report.json_report import generate_json_report
from phantomrecon.report.markdown_report import generate_markdown_report
from phantomrecon.report.poc_generator import generate_poc_report


class PhantomScanner:
    """Core scan orchestrator."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._oob: OOBServer | None = None

    async def run(self) -> ScanResult:
        result = ScanResult(target=self.config.target_url)
        start_time = time.time()

        log.info("[bold cyan]PhantomRecon v1.0.0 — Professional Bug Bounty Scanner[/]")
        log.info(f"[bold]Target:[/] {self.config.target_url}")
        log.info(f"[bold]Modules:[/] {', '.join(self.config.modules)}")
        log.info(f"[bold]Rate Limit:[/] {self.config.rate_limit}s | Concurrency: {self.config.concurrency}")

        if self.config.oob_port:
            self._oob = OOBServer(port=self.config.oob_port)
            try:
                await self._oob.start()
            except Exception as exc:
                log.warning(f"OOB listener failed to start: {exc}")
                self._oob = None

        try:
            async with AsyncHTTPClient(self.config) as client:
                await self._detect_waf(client)

                crawl_result = await self._crawl(client)
                result.urls_scanned = len(crawl_result.urls)

                target_url = self.config.target_url or (crawl_result.urls[0] if crawl_result.urls else "")
                result.target = target_url

                oob_url = ""
                if self._oob:
                    oob_url = f"http://localhost:{self.config.oob_port}"

                await self._run_analyzers(client, crawl_result, result, oob_url)

        except Exception as exc:
            log.error(f"Scan error: {exc}")
            result.errors.append(str(exc))
        finally:
            if self._oob:
                await self._oob.stop()

        elapsed = time.time() - start_time
        log.info(f"\n[bold green]Scan complete in {elapsed:.1f}s[/]")

        self._generate_reports(result)

        return result

    async def _detect_waf(self, client: AsyncHTTPClient) -> None:
        try:
            resp = await client.get(self.config.target_url)
            waf = WAFDetector.detect(dict(resp.headers), resp.text)
            if waf:
                log.warning(f"[bold yellow]WAF detected:[/] {waf}")
            if WAFDetector.is_blocked(resp.status_code, resp.text):
                log.warning("[bold yellow]Target may be blocking requests[/]")
        except Exception:
            pass

    async def _crawl(self, client: AsyncHTTPClient):
        crawler = AsyncCrawler(client, self.config)
        return await crawler.crawl(self.config.target_url)

    async def _run_analyzers(
        self,
        client,
        crawl_result,
        result: ScanResult,
        oob_url: str,
    ) -> None:
        active_modules = self.config.modules
        if "ALL" in active_modules:
            active_modules = list(ANALYZER_MAP.keys())

        analyzers = []
        for mod_name in active_modules:
            if mod_name in ANALYZER_MAP:
                analyzers.append(ANALYZER_MAP[mod_name](client, self.config))

        if not analyzers:
            log.warning("No valid modules to run")
            return

        log.info(f"\n[bold]Running {len(analyzers)} analyzer(s)...[/]\n")

        tasks = [analyzer.analyze(crawl_result, oob_url) for analyzer in analyzers]
        all_results = await asyncio.gather(*tasks, return_exceptions=True)

        for mod_name, res in zip(
            [a.name for a in analyzers], all_results, strict=False
        ):
            if isinstance(res, Exception):
                log.error(f"  [red]{mod_name} failed:[/] {res}")
                result.errors.append(f"{mod_name}: {res}")
            elif isinstance(res, list):
                for finding in res:
                    if finding.confidence >= self.config.min_confidence:
                        result.findings.append(finding)
                result.modules_run.append(mod_name)

        result.findings.sort(
            key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
                f.severity, 5
            )
        )

        if self._oob:
            oob_callbacks = self._oob.callback_count
            if oob_callbacks > 0:
                log.info(f"  [bold magenta]OOB callbacks received:[/] {oob_callbacks}")

    def _generate_reports(self, result: ScanResult) -> None:
        output_dir = self.config.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)

        log.info(f"\n[bold]Generating reports in {output_dir}/[/]")

        if not self.config.no_json:
            generate_json_report(result, output_dir)
        if not self.config.no_html:
            generate_html_report(result, output_dir)
        if not self.config.no_markdown:
            generate_markdown_report(result, output_dir)
        generate_poc_report(result, output_dir)
