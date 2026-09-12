from phantomrecon.analyzers.base import BaseAnalyzer
from phantomrecon.analyzers.cloud_config import CloudConfigAnalyzer
from phantomrecon.analyzers.cors import CORSAnalyzer
from phantomrecon.analyzers.cve_checker import CVEAnalyzer
from phantomrecon.analyzers.graphql import GraphQLAnalyzer
from phantomrecon.analyzers.headers import HeadersAnalyzer
from phantomrecon.analyzers.idor import IDORAnalyzer
from phantomrecon.analyzers.jwt import JWTAnalyzer
from phantomrecon.analyzers.lfi import LFIAnalyzer
from phantomrecon.analyzers.open_redirect import OpenRedirectAnalyzer
from phantomrecon.analyzers.rce import RCEAnalyzer
from phantomrecon.analyzers.recon import ReconAnalyzer
from phantomrecon.analyzers.sensitive_files import SensitiveFilesAnalyzer
from phantomrecon.analyzers.sqli import SQLiAnalyzer
from phantomrecon.analyzers.ssrf import SSRFAnalyzer
from phantomrecon.analyzers.xss import XSSAnalyzer
from phantomrecon.analyzers.xxe import XXEAnalyzer

ALL_ANALYZERS: list[type[BaseAnalyzer]] = [
    SQLiAnalyzer,
    XSSAnalyzer,
    SSRFAnalyzer,
    LFIAnalyzer,
    RCEAnalyzer,
    XXEAnalyzer,
    IDORAnalyzer,
    OpenRedirectAnalyzer,
    CORSAnalyzer,
    HeadersAnalyzer,
    JWTAnalyzer,
    GraphQLAnalyzer,
    CloudConfigAnalyzer,
    SensitiveFilesAnalyzer,
    CVEAnalyzer,
    ReconAnalyzer,
]

ANALYZER_MAP: dict[str, type[BaseAnalyzer]] = {
    "sqli": SQLiAnalyzer,
    "xss": XSSAnalyzer,
    "ssrf": SSRFAnalyzer,
    "lfi": LFIAnalyzer,
    "rce": RCEAnalyzer,
    "xxe": XXEAnalyzer,
    "idor": IDORAnalyzer,
    "redirect": OpenRedirectAnalyzer,
    "cors": CORSAnalyzer,
    "headers": HeadersAnalyzer,
    "jwt": JWTAnalyzer,
    "graphql": GraphQLAnalyzer,
    "cloud": CloudConfigAnalyzer,
    "sensitive": SensitiveFilesAnalyzer,
    "cve": CVEAnalyzer,
    "recon": ReconAnalyzer,
}

__all__ = [
    "BaseAnalyzer",
    "ALL_ANALYZERS",
    "ANALYZER_MAP",
    "SQLiAnalyzer",
    "XSSAnalyzer",
    "SSRFAnalyzer",
    "LFIAnalyzer",
    "RCEAnalyzer",
    "XXEAnalyzer",
    "IDORAnalyzer",
    "OpenRedirectAnalyzer",
    "CORSAnalyzer",
    "HeadersAnalyzer",
    "JWTAnalyzer",
    "GraphQLAnalyzer",
    "CloudConfigAnalyzer",
    "SensitiveFilesAnalyzer",
    "CVEAnalyzer",
    "ReconAnalyzer",
]
