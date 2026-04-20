"""
sentinel/agents/api_agent.py

API Security Agent.
Analyzes API security for:
  - GraphQL introspection (leaks full schema)
  - Swagger/OpenAPI documentation exposure
  - REST API versioning and endpoint enumeration
  - API authentication mechanisms
  - Excessive data exposure in API responses
  - Mass assignment vectors in API schemas
  - API key exposure in responses

SCOPE: PROBE and ACTIVE modes.
ACTIONS: http_probe
NEVER: mutates data, sends malicious payloads, exploits
"""

import json
import re
import requests  # for RequestException type only
from sentinel.core.evidence import safe_request, classify_failure

from sentinel.core import (
    validate_action, AgentName, ScanSession, Finding, Severity,
)

HEADERS = {"User-Agent": "Sentinel-SecurityScanner/1.0"}
TIMEOUT = 10

# GraphQL endpoints to check
GRAPHQL_PATHS = ["/graphql", "/gql", "/api/graphql", "/graphiql", "/playground"]

# API documentation paths
API_DOC_PATHS = [
    "/swagger", "/swagger-ui.html", "/swagger-ui", "/swagger.json",
    "/api-docs", "/api-docs.json", "/openapi.json", "/openapi.yaml",
    "/api/swagger", "/api/swagger.json", "/api/openapi",
    "/v1/swagger.json", "/v2/swagger.json",
    "/docs", "/redoc", "/api/redoc",
]

# GraphQL introspection query
INTROSPECTION_QUERY = {
    "query": "{ __schema { types { name fields { name type { name kind } } } } }"
}

# Simplified introspection to check if enabled
INTROSPECTION_CHECK = {
    "query": "{ __typename }"
}

_AGENT = "api_agent"


def _record_failure(session: ScanSession, url: str,
                    failure_class: str = "other",
                    failure_reason: str = "") -> None:
    """
    Route request failure to SessionIntelligence.record_request_failure().

    After 7b: call sites pass resp.failure_class and resp.failure_reason
    directly from FailedResponse. classify_failure still available for
    requests.RequestException catch paths.
    """
    intel = getattr(session, '_session_intel', None)
    if intel is not None:
        intel.record_request_failure(_AGENT, url, failure_class, failure_reason)


def run_api_agent(session: ScanSession, target_url: str) -> list[Finding]:
    """Run API security analysis."""
    validate_action(AgentName.API, "http_probe", target_url, session)

    base = target_url.rstrip("/")
    findings = []

    print(f"[API] Starting API security analysis on {base}")

    findings.extend(_check_graphql(base, session))
    findings.extend(_check_api_docs(base, session))
    findings.extend(_check_api_versioning(base, session))
    findings.extend(_check_api_auth_headers(base, session))

    print(f"[API] {len(findings)} API findings")
    return findings


# ── GraphQL Analysis ──────────────────────────────────────────────────────────

def _check_graphql(base: str, session: ScanSession) -> list[Finding]:
    """Check for GraphQL introspection and schema exposure."""
    findings = []

    for path in GRAPHQL_PATHS:
        url = base + path

        try:
            resp = safe_request(
                "POST", url,
                headers={**HEADERS, "Content-Type": "application/json"},
                timeout=TIMEOUT,
                json=INTROSPECTION_CHECK,
            )

            # 7b: FailedResponse is falsy — safe_request never returns None after 7b
            if not resp:
                _record_failure(session, url,
                                getattr(resp, "failure_class", "other"),
                                getattr(resp, "failure_reason", ""))
                continue

            if resp.status_code not in (200, 400):
                continue

            try:
                data = resp.json()
            except (json.JSONDecodeError, ValueError):
                continue

            if "data" in data or "errors" in data:
                findings.append(Finding(
                    agent=AgentName.API,
                    title=f"GraphQL Endpoint Exposed: {path}",
                    description=(
                        f"GraphQL API endpoint found at {url}. "
                        "GraphQL endpoints can expose significant attack surface "
                        "including introspection, batching attacks, and deep query abuse."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=url,
                    mitre_tactic="Discovery",
                    mitre_technique="T1046 — Network Service Discovery",
                    remediation=(
                        "Disable GraphQL introspection in production. "
                        "Implement query depth limiting and complexity analysis. "
                        "Add authentication to the GraphQL endpoint. "
                        "Consider query allowlisting for production."
                    ),
                ))

                # Test full introspection
                intro_resp = safe_request(
                    "POST", url,
                    headers={**HEADERS, "Content-Type": "application/json"},
                    timeout=TIMEOUT,
                    json=INTROSPECTION_QUERY,
                )

                # 7b: FailedResponse is falsy
                if not intro_resp:
                    _record_failure(session, url,
                                    getattr(intro_resp, "failure_class", "other"),
                                    getattr(intro_resp, "failure_reason", ""))
                    continue

                if intro_resp.status_code == 200:
                    try:
                        intro_data = intro_resp.json()
                        types = (intro_data.get("data", {})
                                           .get("__schema", {})
                                           .get("types", []))
                        if types:
                            type_names = [t["name"] for t in types
                                          if not t["name"].startswith("__")]
                            findings.append(Finding(
                                agent=AgentName.API,
                                title="GraphQL Introspection Enabled — Full Schema Exposed",
                                description=(
                                    f"GraphQL introspection is ENABLED at {url}. "
                                    f"Full schema with {len(type_names)} types is publicly "
                                    f"accessible. "
                                    f"Types include: {', '.join(type_names[:10])}... "
                                    "Attackers can map the entire API schema including all "
                                    "queries, mutations, and data types."
                                ),
                                severity=Severity.HIGH,
                                file_path=url,
                                mitre_tactic="Discovery",
                                mitre_technique="T1046 — Network Service Discovery",
                                remediation=(
                                    "Disable introspection in production: "
                                    "set introspection=False in your GraphQL server config. "
                                    "Use schema directives to hide sensitive fields. "
                                    "Implement field-level authorization."
                                ),
                            ))
                    except (json.JSONDecodeError, ValueError):
                        pass

        except requests.RequestException as e:
            _record_failure(session, url, classify_failure(str(e)), str(e))
            continue

    return findings


# ── API Documentation Exposure ────────────────────────────────────────────────

def _check_api_docs(base: str, session: ScanSession) -> list[Finding]:
    """Check for exposed API documentation (Swagger/OpenAPI)."""
    findings = []

    for path in API_DOC_PATHS:
        url = base + path
        try:
            resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT,
                                allow_redirects=False)

            # 7b: FailedResponse is falsy — safe_request never returns None after 7b
            if not resp:
                _record_failure(session, url,
                                getattr(resp, "failure_class", "other"),
                                getattr(resp, "failure_reason", ""))
                continue

            if resp.status_code != 200:
                continue

            content_type = resp.headers.get("Content-Type", "")
            is_api_doc = False
            endpoints_found = []

            if "json" in content_type or path.endswith(".json"):
                try:
                    data = resp.json()
                    if "swagger" in data or "openapi" in data or "paths" in data:
                        is_api_doc = True
                        paths = data.get("paths", {})
                        endpoints_found = list(paths.keys())[:20]
                except (json.JSONDecodeError, ValueError):
                    pass

            elif "text/html" in content_type and (
                "swagger" in resp.text.lower() or "openapi" in resp.text.lower()
            ):
                is_api_doc = True

            if is_api_doc:
                findings.append(Finding(
                    agent=AgentName.API,
                    title=f"API Documentation Exposed: {path}",
                    description=(
                        f"API documentation accessible at {url}. "
                        f"Exposes complete API structure to unauthenticated users. "
                        + (f"Found {len(endpoints_found)} endpoints: "
                           f"{', '.join(endpoints_found[:5])}..."
                           if endpoints_found else "")
                    ),
                    severity=Severity.MEDIUM,
                    file_path=url,
                    mitre_tactic="Reconnaissance",
                    mitre_technique="T1590 — Gather Victim Network Information",
                    remediation=(
                        "Restrict API documentation to authenticated users or internal network. "
                        "In production, either disable docs or require authentication to view them. "
                        "Ensure docs don't include sensitive examples with real credentials."
                    ),
                ))

        except requests.RequestException as e:
            _record_failure(session, url, classify_failure(str(e)), str(e))
            continue

    return findings


# ── API Versioning Analysis ───────────────────────────────────────────────────

def _check_api_versioning(base: str, session: ScanSession) -> list[Finding]:
    """Check for old/deprecated API versions still accessible."""
    findings = []

    version_paths = {
        "v1": ["/api/v1", "/v1", "/rest/v1"],
        "v2": ["/api/v2", "/v2", "/rest/v2"],
        "v3": ["/api/v3", "/v3"],
    }

    accessible_versions = []
    for version, paths in version_paths.items():
        for path in paths:
            url = base + path
            try:
                resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT,
                                    allow_redirects=False)

                # 7b: FailedResponse is falsy
                if not resp:
                    _record_failure(session, url,
                                    getattr(resp, "failure_class", "other"),
                                    getattr(resp, "failure_reason", ""))
                    continue

                if resp.status_code in (200, 401, 403):
                    accessible_versions.append(version)
                    break

            except requests.RequestException as e:
                _record_failure(session, url, classify_failure(str(e)), str(e))
                continue

    if len(accessible_versions) > 1:
        findings.append(Finding(
            agent=AgentName.API,
            title=f"Multiple API Versions Active: {', '.join(accessible_versions)}",
            description=(
                f"Multiple API versions are accessible: {', '.join(accessible_versions)}. "
                "Old API versions often lack security fixes applied to newer versions "
                "and may have weaker authentication or authorization."
            ),
            severity=Severity.MEDIUM,
            file_path=base,
            mitre_tactic="Initial Access",
            mitre_technique="T1190 — Exploit Public-Facing Application",
            remediation=(
                "Decommission old API versions. "
                "If backward compatibility is needed, ensure all versions have identical "
                "security controls. "
                "Implement a deprecation timeline and force clients to upgrade."
            ),
        ))

    return findings


# ── API Authentication Headers ────────────────────────────────────────────────

def _check_api_auth_headers(base: str, session: ScanSession) -> list[Finding]:
    """Check what authentication mechanisms the API uses and if they're secure."""
    findings = []

    test_paths = ["/api/users", "/api/orders", "/api/products", "/rest/user/whoami"]

    for path in test_paths:
        url = base + path
        try:
            resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT,
                                allow_redirects=False)

            # 7b: FailedResponse is falsy — safe_request never returns None after 7b
            if not resp:
                _record_failure(session, url,
                                getattr(resp, "failure_class", "other"),
                                getattr(resp, "failure_reason", ""))
                continue

            if resp.status_code not in (200, 401, 403):
                continue

            www_auth = resp.headers.get("WWW-Authenticate", "")

            if "basic" in www_auth.lower():
                findings.append(Finding(
                    agent=AgentName.API,
                    title=f"HTTP Basic Auth Used: {path}",
                    description=(
                        f"API endpoint {url} uses HTTP Basic Authentication. "
                        "Basic auth sends credentials as base64-encoded plaintext. "
                        "If not over HTTPS, credentials are trivially intercepted."
                    ),
                    severity=Severity.HIGH,
                    file_path=url,
                    mitre_tactic="Credential Access",
                    mitre_technique="T1557 — Adversary-in-the-Middle",
                    remediation=(
                        "Replace HTTP Basic Auth with token-based authentication (JWT/OAuth2). "
                        "If Basic Auth is required, enforce HTTPS-only. "
                        "Implement short-lived tokens that expire."
                    ),
                ))

            if resp.status_code == 200 and path not in ["/api/products"]:
                content = resp.text[:200]
                if len(content) > 50:
                    findings.append(Finding(
                        agent=AgentName.API,
                        title=f"API Endpoint Accessible Without Authentication: {path}",
                        description=(
                            f"Endpoint {url} returned HTTP 200 with data "
                            "without any authentication headers. "
                            f"Response preview: {content[:100]}"
                        ),
                        severity=Severity.HIGH,
                        file_path=url,
                        mitre_tactic="Initial Access",
                        mitre_technique="T1190 — Exploit Public-Facing Application",
                        remediation=(
                            "Implement JWT or session-based authentication on all non-public "
                            "endpoints. "
                            "Return 401 Unauthorized for unauthenticated requests. "
                            "Audit all API endpoints to ensure consistent auth enforcement."
                        ),
                    ))

        except requests.RequestException as e:
            _record_failure(session, url, classify_failure(str(e)), str(e))
            continue

    return findings
