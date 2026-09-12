from __future__ import annotations

import asyncio
import time
from typing import Any

from aiohttp import web

from phantomrecon.logger import log


class OOBServer:
    """Built-in Out-of-Band callback listener for blind vulnerability detection."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8888) -> None:
        self.host = host
        self.port = port
        self._callbacks: list[dict[str, Any]] = []
        self._tokens: dict[str, str] = {}
        self._runner: web.AppRunner | None = None
        self._callbacks_event = asyncio.Event()
        self._running = False

    def register_token(self, token: str, module: str) -> None:
        self._tokens[token] = module
        log.debug(f"OOB token registered: {token} -> {module}")

    async def start(self) -> None:
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", self._handler)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.host, self.port)
        await site.start()
        self._running = True
        log.info(f"[bold yellow]OOB listener started:[/] {self.host}:{self.port}")

    async def stop(self) -> None:
        if self._runner:
            self._running = False
            await self._runner.cleanup()
            log.info("OOB listener stopped")

    async def _handler(self, request: web.Request) -> web.Response:
        path = request.path
        query = dict(request.query)
        headers = dict(request.headers)
        body = ""
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.text()

        callback = {
            "time": time.time(),
            "method": request.method,
            "path": path,
            "query": query,
            "headers": headers,
            "body": body,
            "remote": request.remote,
        }

        token_found = None
        for token in self._tokens:
            if token in path or token in str(query) or token in body:
                token_found = token
                callback["module"] = self._tokens[token]
                break

        self._callbacks.append(callback)
        self._callbacks_event.set()

        log.warning(
            f"[bold magenta]OOB callback received:[/] {request.method} {path}"
            + (f" (module: {token_found})" if token_found else "")
        )

        return web.Response(text="OK", status=200)

    async def wait_for_callback(self, timeout: float = 30.0) -> dict[str, Any] | None:
        try:
            await asyncio.wait_for(self._callbacks_event.wait(), timeout=timeout)
            self._callbacks_event.clear()
            if self._callbacks:
                return self._callbacks[-1]
        except TimeoutError:
            pass
        return None

    def get_callbacks(self, module: str = "") -> list[dict[str, Any]]:
        if module:
            return [c for c in self._callbacks if c.get("module") == module]
        return list(self._callbacks)

    def clear_callbacks(self) -> None:
        self._callbacks.clear()

    @property
    def callback_count(self) -> int:
        return len(self._callbacks)
