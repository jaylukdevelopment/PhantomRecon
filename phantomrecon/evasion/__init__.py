from __future__ import annotations

import random

from phantomrecon.logger import log as log

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
]


def get_random_ua() -> str:
    return random.choice(USER_AGENTS)


class PayloadMutator:
    """Mutate payloads for WAF evasion."""

    @staticmethod
    def case_alternate(payload: str) -> str:
        return "".join(
            c.upper() if i % 2 else c for i, c in enumerate(payload)
        )

    @staticmethod
    def url_encode(payload: str) -> str:
        return "".join(f"%{ord(c):02x}" for c in payload)

    @staticmethod
    def double_url_encode(payload: str) -> str:
        return "".join(f"%25{ord(c):02x}" for c in payload)

    @staticmethod
    def sql_comments(payload: str) -> str:
        return payload.replace(" ", "/**/").replace("'", "'/**'")

    @staticmethod
    def null_byte(payload: str) -> str:
        return payload + "%00"

    @staticmethod
    def unicode_escape(payload: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def html_entities(payload: str) -> str:
        return "".join(f"&#{ord(c)};" for c in payload)

    @staticmethod
    def tab_newline(payload: str) -> str:
        return payload.replace(" ", "\t").replace(" ", "\n")

    @classmethod
    def mutate_all(cls, payload: str) -> list[str]:
        mutations = [payload]
        if payload.startswith(("'", '"', "<")):
            mutations.append(cls.case_alternate(payload))
            mutations.append(cls.url_encode(payload))
            mutations.append(cls.double_url_encode(payload))
            mutations.append(cls.html_entities(payload))
        if any(kw in payload.lower() for kw in ("select", "union", "insert", "drop", "update")):
            mutations.append(cls.sql_comments(payload))
            mutations.append(cls.null_byte(payload))
        return list(set(mutations))


class WAFDetector:
    """Detect Web Application Firewalls from response headers and body."""

    WAF_SIGNATURES: dict[str, list[str]] = {
        "Cloudflare": ["cf-ray", "cf-cache-status", "cloudflare"],
        "AWS WAF": ["x-amzn-waf", "x-amzn-requestid"],
        "Akamai": ["x-akamai-transformed", "akamai"],
        "Imperva": ["x-iinfo", "imperva", "incap_ses"],
        "Sucuri": ["x-sucuri-id", "sucuri"],
        "Barracuda": ["barra_counter_session", "barracuda"],
        "F5 BIG-IP": ["bigip", "tsstopped", "f5"],
        "ModSecurity": ["mod_security", "noyouth"],
        "StackPath": ["stackpath"],
        "Wordfence": ["wordfence"],
    }

    @classmethod
    def detect(cls, headers: dict[str, str], body: str = "") -> str | None:
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.lower()

        for waf_name, signatures in cls.WAF_SIGNATURES.items():
            for sig in signatures:
                if any(sig in k for k in headers_lower) or sig in body_lower:
                    return waf_name
        return None

    @classmethod
    def is_blocked(cls, status: int, body: str) -> bool:
        if status in (403, 406, 429, 503):
            return True
        block_indicators = [
            "access denied", "blocked", "forbidden",
            "security violation", "request blocked",
            "waf", "not acceptable",
        ]
        body_lower = body.lower()
        return any(ind in body_lower for ind in block_indicators)
