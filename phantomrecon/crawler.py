from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import tldextract
from bs4 import BeautifulSoup

from phantomrecon.config import ScanConfig
from phantomrecon.http_client import AsyncHTTPClient
from phantomrecon.logger import log
from phantomrecon.models.finding import CrawlResult


class AsyncCrawler:
    """Async BFS web crawler with form extraction and JS endpoint discovery."""

    COMMON_PATHS = [
        "/admin", "/login", "/api", "/robots.txt", "/sitemap.xml",
        "/.env", "/.git/config", "/wp-admin", "/phpinfo.php",
        "/.well-known/security.txt", "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/debug", "/test", "/backup", "/config", "/wp-login.php",
        "/xmlrpc.php", "/readme.html", "/license.txt",
    ]

    def __init__(self, client: AsyncHTTPClient, config: ScanConfig) -> None:
        self.client = client
        self.config = config
        self._visited: set[str] = set()
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._forms: list[dict[str, Any]] = []
        self._params: dict[str, list[str]] = {}
        self._js_urls: list[str] = []
        self._technologies: list[str] = []
        self._robots_disallowed: list[str] = []

    async def crawl(self, start_url: str) -> CrawlResult:
        log.info(f"[bold cyan]Crawling:[/] {start_url} (depth={self.config.crawl_depth})")
        await self._queue.put((start_url, 0))
        self._visited.add(start_url)

        await self._probe_common_paths(start_url)

        tasks: list[asyncio.Task] = []
        while not self._queue.empty() or tasks:
            while not self._queue.empty():
                url, depth = await self._queue.get()
                tasks.append(asyncio.create_task(self._process_url(url, depth)))

            if tasks:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                tasks = list(pending)
                for task in done:
                    try:
                        task.result()
                    except Exception as exc:
                        log.debug(f"Crawl error: {exc}")

        urls = list(self._visited)
        log.info(f"[bold green]Crawl complete:[/] {len(urls)} URLs, {len(self._forms)} forms")
        return CrawlResult(
            urls=urls,
            forms=self._forms,
            params=self._params,
            js_urls=self._js_urls,
            technologies=self._technologies,
        )

    async def _process_url(self, url: str, depth: int) -> None:
        if depth >= self.config.crawl_depth:
            return

        try:
            resp = await self.client.get(url)
            body = resp.text
            self._detect_technologies(resp.headers, body)
            self._extract_forms(url, body)
            self._extract_links(url, body, depth)
            self._extract_js_endpoints(url, body)
        except Exception as exc:
            log.debug(f"Failed to crawl {url}: {exc}")

    def _extract_links(self, base_url: str, html: str, depth: int) -> None:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            resolved = self._resolve(base_url, href)
            if resolved and self._in_scope(resolved) and resolved not in self._visited:
                self._visited.add(resolved)
                self._queue.put_nowait((resolved, depth + 1))

        for tag in soup.find_all(["script", "img", "link"], src=True):
            src = tag.get("src", "")
            resolved = self._resolve(base_url, src)
            if resolved and self._in_scope(resolved) and resolved not in self._visited:
                self._visited.add(resolved)

    def _extract_forms(self, page_url: str, html: str) -> None:
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            form_url = self._resolve(page_url, action) or page_url

            inputs: dict[str, str] = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs[name] = inp.get("value", "")
                    if name not in self._params:
                        self._params[name] = []
                    if form_url not in self._params[name]:
                        self._params[name].append(form_url)

            if inputs:
                self._forms.append({
                    "url": form_url,
                    "method": method,
                    "fields": inputs,
                })

    def _extract_js_endpoints(self, base_url: str, html: str) -> None:
        patterns = [
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']',
            r'\.get\s*\(\s*["\']([^"\']+)["\']',
            r'\.post\s*\(\s*["\']([^"\']+)["\']',
            r'url\s*[:=]\s*["\']([^"\']+/api/[^"\']+)["\']',
            r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, html):
                endpoint = match.group(1)
                resolved = self._resolve(base_url, endpoint)
                if resolved and resolved not in self._js_urls:
                    self._js_urls.append(resolved)

    def _detect_technologies(self, headers: dict, body: str) -> None:
        server = headers.get("server", "").lower()
        if server:
            self._technologies.append(f"Server:{server}")

        powered = headers.get("x-powered-by", "").lower()
        if powered:
            self._technologies.append(f"PoweredBy:{powered}")

        tech_signs = {
            "WordPress": ["wp-content", "wp-includes", "wordpress"],
            "Joomla": ["joomla", "/media/system/"],
            "Drupal": ["drupal", "sites/default/files"],
            "React": ["react", "_next/static"],
            "Vue.js": ["vue", "__vue__"],
            "Angular": ["ng-app", "ng-controller"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "Laravel": ["laravel", "csrf-token"],
            "Express": ["express", "X-Powered-By: Express"],
            "Spring": ["spring", "Whitelabel Error"],
        }
        body_lower = body.lower()
        for tech, indicators in tech_signs.items():
            for indicator in indicators:
                if indicator.lower() in body_lower:
                    self._technologies.append(tech)
                    break

        if "cf-ray" in {k.lower() for k in headers}:
            self._technologies.append("Cloudflare")
        if "x-amz-cf-id" in {k.lower() for k in headers}:
            self._technologies.append("CloudFront")

    async def _probe_common_paths(self, base_url: str) -> None:
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        async def probe(path: str) -> None:
            url = base + path
            try:
                resp = await self.client.head(url)
                if resp.status_code < 400:
                    self._visited.add(url)
                    log.debug(f"  Found: {url} ({resp.status_code})")
            except Exception:
                pass

        await asyncio.gather(*[probe(p) for p in self.COMMON_PATHS])

    def _resolve(self, base_url: str, href: str) -> str | None:
        try:
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                return None
            resolved = urljoin(base_url, href)
            parsed = urlparse(resolved)
            if parsed.scheme in ("http", "https"):
                return resolved
        except Exception:
            pass
        return None

    def _in_scope(self, url: str) -> bool:
        if not self.config.target_url:
            return True
        target_domain = tldextract.extract(urlparse(self.config.target_url).netloc)
        url_domain = tldextract.extract(urlparse(url).netloc)
        return (
            url_domain.domain == target_domain.domain
            and url_domain.suffix == target_domain.suffix
        )
