from __future__ import annotations

import asyncio
import contextlib
import re
from typing import Any


class TimingAnalyzer:
    """Detect time-based vulnerabilities using MAD + EWMA noise filtering."""

    def __init__(self, baseline_probes: int = 3, threshold: float = 1.5) -> None:
        self._baselines: dict[str, list[float]] = {}
        self._ewma: dict[str, float] = {}
        self._alpha = 0.3
        self._baseline_probes = baseline_probes
        self._threshold = threshold

    async def measure_baseline(self, func: Any, url: str, **kwargs: Any) -> float:
        times: list[float] = []
        for _ in range(self._baseline_probes):
            start = asyncio.get_event_loop().time()
            with contextlib.suppress(Exception):
                await func(url, **kwargs)
            elapsed = asyncio.get_event_loop().time() - start
            times.append(elapsed)

        median = sorted(times)[len(times) // 2]
        self._baselines[url] = times
        self._ewma[url] = median
        return median

    async def measure_with_payload(
        self, func: Any, url: str, payload_time: float = 5.0, **kwargs: Any
    ) -> tuple[bool, float]:
        start = asyncio.get_event_loop().time()
        with contextlib.suppress(Exception):
            await func(url, **kwargs)
        elapsed = asyncio.get_event_loop().time() - start

        baseline = self._ewma.get(url, 0.5)
        if elapsed >= baseline + (payload_time * 0.7):
            self._ewma[url] = self._alpha * elapsed + (1 - self._alpha) * baseline
            return True, elapsed
        return False, elapsed

    def get_baseline(self, url: str) -> float:
        return self._ewma.get(url, 0.5)


class ResponseAnalyzer:
    """Analyze responses for vulnerability indicators."""

    SQL_ERRORS = [
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"ora-\d{5}",
        r"postgresql.*error",
        r"sqlite.*error",
        r"sql command not properly ended",
        r"microsoft.*sql.*error",
        r"syntax error.*sql",
        r"mysql_fetch",
        r"pg_query",
        r"sqlite3\.",
    ]

    @staticmethod
    def has_sql_error(body: str) -> bool:
        for pattern in ResponseAnalyzer.SQL_ERRORS:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def content_differs(resp_a: str, resp_b: str, threshold: float = 0.3) -> bool:
        len_a, len_b = len(resp_a), len(resp_b)
        if len_a == 0 and len_b == 0:
            return False
        diff_ratio = abs(len_a - len_b) / max(len_a, len_b)
        return diff_ratio > threshold

    @staticmethod
    def contains_payload(response_text: str, payload: str) -> bool:
        return payload in response_text

    @staticmethod
    def detect_reflection(response_text: str, payload: str) -> bool:
        encoded_variants = [
            payload,
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace("<", "\u003c").replace(">", "\u003e"),
        ]
        return any(variant in response_text for variant in encoded_variants)
