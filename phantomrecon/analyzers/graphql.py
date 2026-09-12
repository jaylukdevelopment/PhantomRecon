from __future__ import annotations

import asyncio

from phantomrecon.analyzers.base import BaseAnalyzer
from phantomrecon.logger import log
from phantomrecon.models.finding import CrawlResult, Finding


class GraphQLAnalyzer(BaseAnalyzer):
    """GraphQL introspection and misconfiguration detection."""

    name = "graphql"
    category = "misconfiguration"

    ENDPOINTS = ["/graphql", "/api/graphql", "/graphiql", "/v1/graphql", "/query", "/gql"]

    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            types {
                name
                kind
                fields {
                    name
                    type { name kind }
                }
            }
        }
    }
    """

    async def analyze(self, crawl_result: CrawlResult, oob_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        endpoints = list(set(self.ENDPOINTS + [
            url for url in crawl_result.urls
            if any(kw in url.lower() for kw in ["graphql", "gql", "query"])
        ]))

        tasks = [self._test_endpoint(ep) for ep in endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
        log.info(f"  [bold]{self.name}:[/] {len(findings)} findings")
        return findings

    async def _test_endpoint(self, endpoint: str) -> list[Finding]:
        findings = []
        try:
            resp = await self.client.post(
                endpoint,
                json={"query": self.INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json"},
            )
            data = resp.json()
            if "__schema" in data.get("data", {}):
                schema = data["data"]["__schema"]
                type_count = len(schema.get("types", []))
                findings.append(self._make_finding(
                    rule_id="GQL-001",
                    name="GraphQL Introspection Enabled",
                    severity="MEDIUM",
                    confidence=0.95,
                    url=endpoint,
                    method="POST",
                    parameter="query",
                    evidence=f"Schema exposes {type_count} types",
                    description=f"GraphQL introspection is enabled, exposing {type_count} types and their fields.",
                    remediation="Disable introspection in production. Implement query depth limiting.",
                    cwe="CWE-200",
                    owasp="A03:2021",
                ))

                mutations = [t for t in schema.get("types", []) if t.get("kind") == "OBJECT" and t.get("name", "").endswith("Mutation")]
                if mutations:
                    findings.append(self._make_finding(
                        rule_id="GQL-002",
                        name="GraphQL Mutations Exposed",
                        severity="HIGH",
                        confidence=0.9,
                        url=endpoint,
                        method="POST",
                        evidence=f"Mutations available: {[m['name'] for m in mutations]}",
                        description="GraphQL mutations are publicly accessible.",
                        remediation="Implement authorization for mutations.",
                        cwe="CWE-284",
                        owasp="A01:2021",
                    ))
        except Exception:
            pass
        return findings
