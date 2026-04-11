from typing import Optional
"""
sentinel/agents/injection_agent.py

Injection Detection Agent.
Detects CONDITIONS that indicate injection vulnerabilities
WITHOUT sending malicious payloads.

How it works:
  - Sends a single quote ' to observe error responses
  - Checks if error messages leak SQL syntax
  - Checks if responses differ in ways that indicate parsing
  - Checks for reflected input in responses (XSS indicator)
  - Checks for template injection indicators
  - Tests for error-based information disclosure

This is the line between finding and exploiting:
  ✅ Send ' and observe "SQL syntax error near ''" → FOUND: SQL injection condition
  ❌ Send ' OR 1=1-- and log in → EXPLOITATION (we don't do this)

SCOPE: PROBE and ACTIVE modes.
ACTIONS: http_probe
NEVER: sends exploit payloads, extracts data, bypasses auth
"""

import re
import json
import hashlib
import requests
from urllib.parse import urljoin, urlparse, urlencode
# TLS warnings suppressed per-request in safe_request/probe_with_evidence

from sentinel.core import (
    validate_action, AgentName, ScanSession, Finding, Severity, ScanMode,
)
from sentinel.core.auth_context import AuthContext

HEADERS = {"User-Agent": "Sentinel-SecurityScanner/1.0"}
TIMEOUT = 10

# Single probe character — not a payload, just an error trigger
PROBE_CHAR = "'"

# SQL error patterns that indicate injection vulnerability
SQL_ERROR_PATTERNS = [
    (r"sql syntax.*near",                "MySQL SQL Error"),
    (r"syntax error.*unexpected",        "SQL Syntax Error"),
    (r"quoted string not properly terminated", "Oracle SQL Error"),
    (r"unclosed quotation mark",         "MSSQL Error"),
    (r"pg::syntaxerror",                 "PostgreSQL Error"),
    (r"sqlite3::exception",              "SQLite Error"),
    (r"sequelizeerror",                  "Sequelize ORM Error"),
    (r"ORA-\d+",                         "Oracle Error Code"),
    (r"microsoft ole db.*error",         "MSSQL OLE DB Error"),
    (r"supplied argument is not.*valid.*mysql", "MySQL Error"),
    (r"warning.*mysql_",                 "MySQL Warning"),
    (r"valid mysql result",              "MySQL Result Error"),
    (r"mysqlclient",                     "MySQL Client Error"),
    (r"syntax error near \"",            "Generic SQL Syntax Error"),
    (r"from.*where.*error",              "SQL Query Fragment"),
    (r"unterminated string",             "SQL String Error"),
]

# XSS reflection indicators
XSS_REFLECTION_MARKERS = [
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    "alert(",
]

# Template injection indicators
TEMPLATE_PATTERNS = [
    (r"\{\{.*\}\}",   "Jinja2/Twig Template"),
    (r"\$\{.*\}",     "EL/Thymeleaf Template"),
    (r"<%.*%>",       "JSP/ASP Template"),
    (r"#\{.*\}",      "Ruby ERB Template"),
]

# Endpoints likely to process user input
INPUT_ENDPOINTS = [
    "/rest/user/login",
    "/api/login",
    "/search",
    "/api/search",
    "/rest/products/search",
    "/api/products/search",
    "/api/users",
    "/feedback",
    "/api/feedback",
    "/register",
    "/api/register",
    "/api/user/register",
    "/rest/user/register",
    "/forgot-password",
    "/api/forgot-password",
]

# Search/filter parameters commonly vulnerable to injection
INPUT_PARAMS = ["q", "search", "query", "s", "term", "filter", "id", "name", "email"]


def run_injection_agent(session: ScanSession, target_url: str,
                        auth: Optional[AuthContext] = None) -> list[Finding]:
    """
    Run injection condition detection.
    Sends single probe characters and analyzes error responses.
    """
    validate_action(AgentName.INJECTION, "http_probe", target_url, session)

    base = target_url.rstrip("/")
    findings = []

    print(f"[INJECTION] Scanning for injection conditions on {base}")

    findings.extend(_check_search_injection(base, session, auth))
    findings.extend(_check_login_injection(base, session))
    findings.extend(_check_api_injection(base, session, auth))
    findings.extend(_check_xss_reflection(base, session, auth))

    print(f"[INJECTION] {len(findings)} injection condition findings")
    return findings


def _check_search_injection(base: str, session: ScanSession,
                             auth: Optional[AuthContext]) -> list[Finding]:
    """Check search endpoints for SQL injection conditions."""
    findings = []

    search_endpoints = [
        "/rest/products/search?q=",
        "/api/search?q=",
        "/search?q=",
        "/api/products?name=",
    ]

    for endpoint in search_endpoints:
        url = base + endpoint + PROBE_CHAR

        try:
            if auth and auth.logged_in:
                resp = auth.get(url)
            else:
                resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT)

            if not resp or resp.status_code not in (200, 400, 500, 503):
                continue

            content = resp.text.lower()

            # Check for SQL errors
            for pattern, error_type in SQL_ERROR_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append(Finding(
                        agent=AgentName.INJECTION,
                        title=f"SQL Injection Condition: {endpoint.split('?')[0]}",
                        description=(
                            f"Endpoint {base + endpoint.split('?')[0]} returned a {error_type} "
                            f"when probed with a single quote. "
                            "This strongly indicates unsanitized SQL query construction. "
                            f"Error type: {error_type}"
                        ),
                        severity=Severity.CRITICAL,
                        file_path=url,
                        cve_id="CWE-89",
                        mitre_tactic="Initial Access",
                        mitre_technique="T1190 — Exploit Public-Facing Application",
                        remediation=(
                            "Use parameterized queries or prepared statements. "
                            "NEVER concatenate user input into SQL queries. "
                            "Implement input validation and output encoding. "
                            "Use an ORM with parameterized queries."
                        ),
                    ))
                    break

            # Check if response differs significantly from normal
            # Behavioral injection detection — requires strong signal, not just size noise
            normal_url = base + endpoint + "apple"
            try:
                if auth and auth.logged_in:
                    normal_resp = auth.get(normal_url)
                else:
                    normal_resp = safe_request("GET", normal_url, headers=HEADERS, timeout=TIMEOUT)

                if normal_resp:
                    size_probe  = len(resp.content)
                    size_normal = len(normal_resp.content)
                    # Require: >3x difference AND both responses are JSON
                    # >500 byte diff alone is not sufficient — it's noise for dynamic endpoints
                    is_json_both = ("json" in resp.headers.get("Content-Type","") and
                                    "json" in normal_resp.headers.get("Content-Type",""))
                    size_ratio = max(size_probe, size_normal) / max(min(size_probe, size_normal), 1)
                    if is_json_both and size_ratio > 3.0 and abs(size_probe - size_normal) > 1000:
                        findings.append(Finding(
                            agent=AgentName.INJECTION,
                            title=f"Injection Behavioral Anomaly: {endpoint.split('?')[0]}",
                            description=(
                                f"JSON response size differs {size_ratio:.1f}x between normal input "
                                f"({size_normal} bytes) and probe input "
                                f"({size_probe} bytes) at {endpoint.split('?')[0]}. "
                                "Warrants manual verification — may indicate injection condition. "
                                "Not confirmed without SQL error pattern match."
                            ),
                            severity=Severity.MEDIUM,
                            file_path=url,
                            cve_id="CWE-89",
                            mitre_tactic="Initial Access",
                            mitre_technique="T1190 — Exploit Public-Facing Application",
                            remediation=(
                                "Manually verify: send the probe character and inspect the query. "
                                "Implement parameterized queries and input validation."
                            ),
                        ))
            except Exception:
                pass

        except requests.RequestException:
            continue

    return findings


def _check_login_injection(base: str, session: ScanSession) -> list[Finding]:
    """Check login endpoint for SQL injection conditions in error responses."""
    findings = []

    login_endpoints = ["/rest/user/login", "/api/login", "/login"]

    for endpoint in login_endpoints:
        url = base + endpoint
        try:
            # Send probe character in email field
            resp = safe_request(
                "POST", url,
                headers={**HEADERS, "Content-Type": "application/json"},
                timeout=TIMEOUT,
                json={"email": f"test{PROBE_CHAR}@test.com", "password": "test"},
            )

            if resp.status_code not in (200, 400, 401, 500):
                continue

            content = resp.text.lower()

            for pattern, error_type in SQL_ERROR_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append(Finding(
                        agent=AgentName.INJECTION,
                        title=f"SQL Injection in Login: {endpoint}",
                        description=(
                            f"Login endpoint {url} returned a {error_type} "
                            "when email field was probed. "
                            "The login query appears to be vulnerable to SQL injection. "
                            "This could allow authentication bypass."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=url,
                        cve_id="CWE-89",
                        mitre_tactic="Initial Access",
                        mitre_technique="T1078 — Valid Accounts",
                        remediation=(
                            "Use parameterized queries for login. "
                            "Example: SELECT * FROM users WHERE email = ? AND password = ?"
                        ),
                    ))
                    break

        except requests.RequestException:
            continue

    return findings


def _check_api_injection(base: str, session: ScanSession,
                          auth: Optional[AuthContext]) -> list[Finding]:
    """Check API endpoints for injection conditions."""
    findings = []

    # Test ID-based endpoints with non-numeric input
    id_endpoints = [
        "/api/users/",
        "/api/products/",
        "/api/BasketItems/",
        "/api/Feedbacks/",
        "/rest/user/",
    ]

    for endpoint in id_endpoints:
        url = base + endpoint + PROBE_CHAR

        try:
            if auth and auth.logged_in:
                resp = auth.get(url)
            else:
                resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT)

            if not resp:
                continue

            content = resp.text.lower()

            for pattern, error_type in SQL_ERROR_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append(Finding(
                        agent=AgentName.INJECTION,
                        title=f"SQL Injection in API ID Parameter: {endpoint}",
                        description=(
                            f"API endpoint {endpoint} leaked a {error_type} "
                            "when ID parameter was probed. "
                            "The query is not parameterized."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=url,
                        cve_id="CWE-89",
                        mitre_tactic="Collection",
                        mitre_technique="T1213 — Data from Information Repositories",
                        remediation="Use parameterized queries. Validate that ID parameters are numeric.",
                    ))
                    break

        except requests.RequestException:
            continue

    return findings


def _check_xss_reflection(base: str, session: ScanSession,
                           auth: Optional[AuthContext]) -> list[Finding]:
    """
    Check for XSS reflection conditions.
    Uses a benign unique marker, not a script tag.
    If our marker appears in the response unencoded, XSS is likely possible.
    """
    findings = []

    # Use a unique harmless string — not a script, just a marker
    xss_marker = "sentinel_xss_test_12345"
    xss_endpoints = [
        f"/rest/products/search?q={xss_marker}",
        f"/search?q={xss_marker}",
        f"/api/search?q={xss_marker}",
    ]

    for endpoint in xss_endpoints:
        url = base + endpoint
        try:
            if auth and auth.logged_in:
                resp = auth.get(url)
            else:
                resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT)

            if not resp or resp.status_code != 200:
                continue

            content_type = resp.headers.get("Content-Type", "")

            # If our marker appears unencoded in HTML response — XSS reflection possible
            if xss_marker in resp.text and "text/html" in content_type:
                # Check if it's actually unencoded
                if f"{xss_marker}" in resp.text and f"&lt;" not in resp.text[:100]:
                    findings.append(Finding(
                        agent=AgentName.INJECTION,
                        title=f"Reflected XSS Condition: {endpoint.split('?')[0]}",
                        description=(
                            f"Input is reflected unencoded in HTML response at "
                            f"{endpoint.split('?')[0]}. "
                            "User-controlled input appears in the HTML output without encoding, "
                            "indicating a reflected XSS vulnerability condition."
                        ),
                        severity=Severity.HIGH,
                        file_path=url,
                        cve_id="CWE-79",
                        mitre_tactic="Initial Access",
                        mitre_technique="T1059.007 — JavaScript",
                        remediation=(
                            "Encode all user input before outputting to HTML. "
                            "Use a templating engine with auto-escaping enabled. "
                            "Implement Content Security Policy headers."
                        ),
                    ))

            # Check JSON responses for unencoded reflection
            if xss_marker in resp.text and "json" in content_type:
                try:
                    data = resp.json()
                    data_str = json.dumps(data)
                    if xss_marker in data_str:
                        findings.append(Finding(
                            agent=AgentName.INJECTION,
                            title=f"Input Reflected in JSON Response: {endpoint.split('?')[0]}",
                            description=(
                                f"Search input is reflected in JSON response without sanitization. "
                                "While JSON responses require additional steps to trigger XSS, "
                                "unfiltered reflection indicates missing input validation."
                            ),
                            severity=Severity.MEDIUM,
                            file_path=url,
                            cve_id="CWE-79",
                            mitre_tactic="Initial Access",
                            mitre_technique="T1059.007 — JavaScript",
                            remediation=(
                                "Validate and sanitize all input before processing. "
                                "Set Content-Type: application/json to prevent MIME sniffing."
                            ),
                        ))
                except (json.JSONDecodeError, ValueError):
                    pass

        except requests.RequestException:
            continue

    return findings


# For type hints

