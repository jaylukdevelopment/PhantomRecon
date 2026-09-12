from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, ""))


def is_same_domain(url_a: str, url_b: str) -> bool:
    return urlparse(url_a).netloc == urlparse(url_b).netloc


def extract_domain(url: str) -> str:
    return urlparse(url).netloc


def build_url_with_params(base_url: str, params: dict[str, str]) -> str:
    parsed = urlparse(base_url)
    existing = parse_qs(parsed.query)
    existing.update(params)
    new_query = urlencode(existing, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ""))


def resolve_url(base: str, href: str) -> str | None:
    try:
        resolved = urljoin(base, href)
        parsed = urlparse(resolved)
        if parsed.scheme in ("http", "https"):
            return resolved
    except Exception:
        pass
    return None


def get_page_title(html: str) -> str:
    import re

    match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else ""


def truncate(text: str, max_len: int = 500) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def safe_get(d: dict, *keys: str, default: str = "") -> str:
    current = d
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return str(current) if current is not None else default
