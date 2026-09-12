from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanConfig:
    """Global configuration for a PhantomRecon scan."""

    target_url: str = ""
    target_file: str = ""
    crawl_depth: int = 3
    max_urls: int = 500
    concurrency: int = 15
    timeout: int = 12
    rate_limit: float = 0.2
    modules: list[str] = field(default_factory=lambda: list("ALL"))
    oob_port: int = 8888
    oob_host: str = "0.0.0.0"
    min_confidence: float = 0.5
    output_dir: Path = field(default_factory=lambda: Path("scan_results"))
    proxy: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    bearer_token: str = ""
    login_url: str = ""
    login_user: str = ""
    login_pass: str = ""
    verbose: bool = False
    stealth: bool = False
    no_json: bool = False
    no_html: bool = False
    no_markdown: bool = False
    log_file: str = ""
    user_agent: str = ""
    respect_robots: bool = True

    def __post_init__(self) -> None:
        self.output_dir = Path(self.output_dir)
        if self.stealth:
            self.rate_limit = max(self.rate_limit, 0.5)
            self.concurrency = min(self.concurrency, 3)
        if self.modules == ["ALL"]:
            from phantomrecon.analyzers import ANALYZER_MAP

            self.modules = list(ANALYZER_MAP.keys())
