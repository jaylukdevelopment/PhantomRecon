from __future__ import annotations

import asyncio
import random
import time
from typing import Any

import httpx

from phantomrecon.config import ScanConfig
from phantomrecon.logger import log


class AsyncHTTPClient:
    """Async HTTP client with rate limiting, retries, and UA rotation."""

    DEFAULT_UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    )

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._semaphore = asyncio.Semaphore(config.concurrency)
        self._last_request: float = 0.0
        self._lock = asyncio.Lock()
        self._request_count = 0
        self._error_count = 0
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> AsyncHTTPClient:
        headers = {"User-Agent": self.DEFAULT_UA}
        headers.update(self.config.headers)
        if self.config.bearer_token:
            headers["Authorization"] = f"Bearer {self.config.bearer_token}"

        cookies = dict(self.config.cookies)

        if self.config.proxy:
            self._client = httpx.AsyncClient(
                proxy=self.config.proxy,
                headers=headers,
                cookies=cookies,
                timeout=httpx.Timeout(self.config.timeout),
                follow_redirects=True,
                verify=False,
                limits=httpx.Limits(
                    max_connections=self.config.concurrency * 2,
                    max_keepalive_connections=self.config.concurrency,
                ),
            )
        else:
            self._client = httpx.AsyncClient(
                headers=headers,
                cookies=cookies,
                timeout=httpx.Timeout(self.config.timeout),
                follow_redirects=True,
                verify=False,
                limits=httpx.Limits(
                    max_connections=self.config.concurrency * 2,
                    max_keepalive_connections=self.config.concurrency,
                ),
            )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    async def _rate_limit(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            if elapsed < self.config.rate_limit:
                wait = self.config.rate_limit - elapsed + random.uniform(0, 0.05)
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()

    async def request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        async with self._semaphore:
            await self._rate_limit()
            retries = 3
            for attempt in range(retries):
                try:
                    assert self._client is not None
                    resp = await self._client.request(method, url, **kwargs)
                    self._request_count += 1
                    return resp
                except httpx.TimeoutException:
                    log.debug(f"Timeout on {url} (attempt {attempt + 1}/{retries})")
                    if attempt == retries - 1:
                        self._error_count += 1
                        raise
                    await asyncio.sleep(1 * (attempt + 1))
                except httpx.RequestError as exc:
                    log.debug(f"Request error on {url}: {exc}")
                    if attempt == retries - 1:
                        self._error_count += 1
                        raise
                    await asyncio.sleep(1 * (attempt + 1))
            raise httpx.RequestError("Max retries exceeded")

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)

    @property
    def stats(self) -> dict[str, int]:
        return {"requests": self._request_count, "errors": self._error_count}
