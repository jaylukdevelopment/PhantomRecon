from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Finding(BaseModel):
    """Represents a single vulnerability finding."""

    rule_id: str
    name: str
    category: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    url: str
    method: str = "GET"
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    cwe: str = ""
    owasp: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    poc_curl: str = ""
    poc_python: str = ""

    class Config:
        use_enum_values = True


class CrawlResult(BaseModel):
    """Result from the crawler."""

    urls: list[str] = []
    forms: list[dict[str, Any]] = []
    params: dict[str, list[str]] = {}
    js_urls: list[str] = []
    technologies: list[str] = []


class ScanResult(BaseModel):
    """Complete scan result container."""

    target: str = ""
    findings: list[Finding] = []
    urls_scanned: int = 0
    modules_run: list[str] = []
    errors: list[str] = []
    metadata: dict[str, Any] = {}

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)
