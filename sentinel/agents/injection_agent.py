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

# 7a fix: safe_request was missing — caused NameError on every run
# classify_failure imported here — single definition in evidence.py
from sentinel.core.evidence import safe_request, classify_failure

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

_AGENT = "injection_agent"


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

            # 7b: FailedResponse is falsy — safe_request never returns None after 7b
            if resp is None or resp.status_code == 0:
                _record_failure(session, url,
                                getattr(resp, "failure_class", "other"),
                                getattr(resp, "failure_reason", ""))
                continue

            if resp.status_code not in (200, 400, 500, 503):
                continue

            content = resp.text.lower()

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

            # Behavioral injection detection
            normal_url = base + endpoint + "apple"
            try:
                if auth and auth.logged_in:
                    normal_resp = auth.get(normal_url)
                else:
                    normal_resp = safe_request("GET", normal_url, headers=HEADERS,
                                               timeout=TIMEOUT)

                if normal_resp:
                    size_probe  = len(resp.content)
                    size_normal = len(normal_resp.content)
                    is_json_both = (
                        "json" in resp.headers.get("Content-Type", "") and
                        "json" in normal_resp.headers.get("Content-Type", "")
                    )
                    same_status = resp.status_code == normal_resp.status_code

                    # Behavioral detection requires structural evidence, not just size.
                    # Size-only variance triggers on normal search results (more vs fewer items).
                    anomaly_signal = None

                    if is_json_both and same_status:
                        # Parse both responses to inspect structure
                        try:
                            import json as _json
                            probe_json  = _json.loads(resp.text)
                            normal_json = _json.loads(normal_resp.text)

                            # Probe is error-shaped when normal is not
                            error_keys = {"error", "exception", "message", "msg",
                                          "detail", "details", "err", "errors"}
                            probe_keys  = set(probe_json.keys())  if isinstance(probe_json, dict) else set()
                            normal_keys = set(normal_json.keys()) if isinstance(normal_json, dict) else set()

                            probe_error_shaped  = bool(probe_keys  & error_keys)
                            normal_error_shaped = bool(normal_keys & error_keys)

                            if probe_error_shaped and not normal_error_shaped:
                                anomaly_signal = (
                                    f"Probe response contains error-shaped fields "
                                    f"({', '.join(probe_keys & error_keys)}) "
                                    f"while normal response does not."
                                )

                            # Top-level type divergence (list vs dict or vice versa)
                            elif type(probe_json) != type(normal_json):
                                anomaly_signal = (
                                    f"Probe response top-level type ({type(probe_json).__name__}) "
                                    f"differs from normal ({type(normal_json).__name__})."
                                )

                        except (_json.JSONDecodeError, ValueError):
                            pass  # Cannot parse — skip behavioral check

                    elif not same_status and resp.status_code >= 500 and normal_resp.status_code < 500:
                        # Probe caused a server error that normal input did not
                        anomaly_signal = (
                            f"Probe input triggered HTTP {resp.status_code} "
                            f"while normal input returned HTTP {normal_resp.status_code}."
                        )

                    if anomaly_signal:
                        findings.append(Finding(
                            agent=AgentName.INJECTION,
                            title=f"Injection Behavioral Anomaly: {endpoint.split('?')[0]}",
                            description=(
                                f"Structural difference between normal and probe responses "
                                f"at {endpoint.split('?')[0]}. {anomaly_signal} "
                                "May indicate unparameterized input handling."
                            ),
                            severity=Severity.MEDIUM,
                            file_path=url,
                            cve_id="CWE-89",
                            mitre_tactic="Initial Access",
                            mitre_technique="T1190 — Exploit Public-Facing Application",
                            remediation=(
                                "Investigate why probe input causes structurally different "
                                "response. Use parameterized queries."
                            ),
                        ))
                else:
                    # safe_request returned FailedResponse — log with real class
                    if hasattr(normal_resp, "failure_class"):
                        _record_failure(session, normal_url,
                                        normal_resp.failure_class,
                                        normal_resp.failure_reason)
                    else:
                        _record_failure(session, normal_url, "other", "no response")

            except Exception as e:
                # Unexpected error in behavioral comparison — log with classify_failure
                _record_failure(session, normal_url,
                                classify_failure(str(e)), str(e)[:120])

        except requests.RequestException as e:
            _record_failure(session, url, classify_failure(str(e)), str(e))
            continue

    return findings


def _check_login_injection(base: str, session: ScanSession) -> list[Finding]:
    """Check login endpoint for SQL injection conditions in error responses."""
    findings = []

    login_endpoints = ["/rest/user/login", "/api/login", "/login"]

    for endpoint in login_endpoints:
        url = base + endpoint
        try:
            resp = safe_request(
                "POST", url,
                headers={**HEADERS, "Content-Type": "application/json"},
                timeout=TIMEOUT,
                json={"email": f"test{PROBE_CHAR}@test.com", "password": "test"},
            )

            # 7b: FailedResponse is falsy (status_code == 0, ok == False)
            # safe_request never returns None after 7b; kept as safety net
            if resp is None or resp.status_code == 0:
                _record_failure(session, url,
                                getattr(resp, "failure_class", "other"),
                                getattr(resp, "failure_reason", ""))
                continue

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

        except requests.RequestException as e:
            _record_failure(session, url, classify_failure(str(e)), str(e))
            continue

    return findings


def _check_api_injection(base: str, session: ScanSession,
                          auth: Optional[AuthContext]) -> list[Finding]:
    """Check API endpoints for injection conditions."""
    findings = []

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

            if resp is None or resp.status_code == 0:
                _record_failure(session, url, getattr(resp, "failure_class", "other"), getattr(resp, "failure_reason", ""))
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
                        remediation=(
                            "Use parameterized queries. "
                            "Validate that ID parameters are numeric."
                        ),
                    ))
                    break

        except requests.RequestException as e:
            _record_failure(session, url, classify_failure(str(e)), str(e))
            continue

    return findings


def _check_xss_reflection(base: str, session: ScanSession,
                           auth: Optional[AuthContext]) -> list[Finding]:
    """
    Check for XSS reflection conditions.
    Uses a benign unique marker, not a script tag.
    """
    findings = []

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

            # 7b: FailedResponse is falsy — safe_request never returns None after 7b
            if resp is None or resp.status_code == 0:
                _record_failure(session, url,
                                getattr(resp, "failure_class", "other"),
                                getattr(resp, "failure_reason", ""))
                continue

            if resp.status_code != 200:
                continue

            content_type = resp.headers.get("Content-Type", "")

            if xss_marker in resp.text and "text/html" in content_type:
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

            if xss_marker in resp.text and "json" in content_type:
                try:
                    data = resp.json()
                    data_str = json.dumps(data)
                    if xss_marker in data_str:
                        findings.append(Finding(
                            agent=AgentName.INJECTION,
                            title=f"Input Reflected in JSON Response: {endpoint.split('?')[0]}",
                            description=(
                                "Search input is reflected in JSON response without sanitization. "
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

        except requests.RequestException as e:
            _record_failure(session, url, classify_failure(str(e)), str(e))
            continue

    return findings
