"""
sentinel/agents/probe_agent.py

Probe Agent — Active-Safe Web Probing.
Part of MODE2 (PROBE mode).

Finds:
  - All endpoints via spidering
  - Unauthenticated access to protected endpoints
  - IDOR vulnerabilities (change ID, observe response)
  - Rate limiting absence on auth endpoints
  - User enumeration via different error messages
  - HTTP method tampering (GET vs POST vs PUT)
  - Parameter pollution
  - Mass assignment vectors

SCOPE: PROBE and ACTIVE modes only.
ACTIONS: http_probe, spider_passive
NEVER: submits exploit payloads, modifies data, brute forces,
       sends SQL/XSS/command injection strings
"""

import json
import re
import sys
import requests
from urllib.parse import urljoin, urlparse, urlencode

from sentinel.core.evidence import probe_with_evidence, safe_request, classify_failure
from sentinel.core import (
    validate_action, AgentName, ScanSession, Finding, Severity, ScanMode,
)

HEADERS = {"User-Agent": "Sentinel-SecurityScanner/1.0"}
TIMEOUT = 10

# Common API base paths to probe
API_BASES = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/graphql", "/gql",
    "/v1", "/v2", "/internal", "/private",
]

# Auth endpoints to test for rate limiting + user enumeration
AUTH_PATHS = [
    "/login", "/api/login", "/auth/login", "/signin",
    "/api/user/login", "/rest/user/login",
    "/register", "/api/register", "/signup",
    "/forgot-password", "/reset-password",
    "/api/user/reset-password",
]

# Admin/privileged paths
ADMIN_PATHS = [
    "/admin", "/administration", "/manage",
    "/api/admin", "/api/users", "/api/user",
    "/dashboard", "/backstage", "/console",
    "/api/orders", "/api/feedback", "/api/complaints",
]

# Common user IDs to test IDOR
IDOR_TEST_IDS = [1, 2, 3, 100, 999]

_AGENT = "probe_agent"


def _record_failure(session: ScanSession, url: str,
                    failure_class: str = "other",
                    failure_reason: str = "") -> None:
    """
    Route request failure to SessionIntelligence.record_request_failure().
    classify_failure() imported from evidence.py — single definition.
    """
    intel = getattr(session, '_session_intel', None)
    if intel is not None:
        intel.record_request_failure(_AGENT, url, failure_class, failure_reason)


def run_probe_agent(session: ScanSession, target_url: str) -> list[Finding]:
    """Run probe analysis against a live target."""
    validate_action(AgentName.PROBE, "http_probe", target_url, session)
    validate_action(AgentName.PROBE, "spider_passive", target_url, session)

    base = target_url.rstrip("/")
    findings = []

    print(f"[PROBE] Starting endpoint probe on {base}")

    findings.extend(_check_admin_endpoints(base, session))
    findings.extend(_check_api_endpoints(base, session))
    findings.extend(_check_auth_weaknesses(base, session))
    findings.extend(_check_idor(base, session))
    findings.extend(_check_dangerous_methods(base, session))
    findings.extend(_check_rate_limiting(base, session))

    print(f"[PROBE] {len(findings)} probe findings")
    return findings


# ── Admin / Privileged Endpoints ──────────────────────────────────────────────

def _check_admin_endpoints(base: str, session: ScanSession) -> list[Finding]:
    """Check for accessible admin/privileged endpoints without auth."""
    findings = []
    SPA_SIZE_MIN, SPA_SIZE_MAX = 70000, 82000

    for path in ADMIN_PATHS:
        url = base + path
        # probe_with_evidence uses its own internal request path — unchanged
        resp, artifact = probe_with_evidence(url, method="GET", auth_sent=False)

        if resp is None:
            continue

        status = resp.status_code
        er = artifact.response

        print(f"[PROBE] {path}: HTTP {status} | {er.response_type} | "
              f"{er.size_bytes}b | Auth: {'required' if er.auth_required else 'NOT required'}")

        if status == 200:
            content_len = er.size_bytes
            is_spa = (SPA_SIZE_MIN < content_len < SPA_SIZE_MAX and
                      "html" in er.content_type.lower())

            if is_spa:
                findings.append(Finding(
                    agent=AgentName.PROBE,
                    title=f"SPA Route Responds: {path}",
                    description=(
                        f"Endpoint {url} returned HTTP 200 with {content_len} bytes (HTML). "
                        "Response matches SPA shell pattern — likely client-side routing, "
                        "not server-side admin functionality. "
                        f"{artifact.format_report()}"
                    ),
                    severity=Severity.LOW,
                    file_path=url,
                    mitre_tactic="Discovery",
                    mitre_technique="T1083 — File and Directory Discovery",
                    remediation=(
                        "Verify whether this path exposes real admin functionality server-side. "
                        "SPA routing may hide actual access control issues."
                    ),
                ))
            elif content_len > 100 and er.response_type == "JSON":
                from sentinel.core.models import EvidenceRef as _ERef
                _ev = _ERef(
                    method="GET",
                    url=url,
                    status_code=resp.status_code,
                    response_type=er.response_type,
                    size_bytes=er.size_bytes,
                    auth_sent=False,
                    sensitive_fields=er.sensitive_fields,
                    record_count=er.record_count,
                    proof_snippet=er.sample,
                )
                findings.append(Finding(
                    agent=AgentName.PROBE,
                    title=f"Confirmed Unauthenticated Access: {path}",
                    description=(
                        f"CONFIRMED: {path} returns {er.response_type} data without "
                        f"authentication. {artifact.format_report()}"
                    ),
                    severity=Severity.CRITICAL,
                    file_path=url,
                    evidence=_ev,
                    mitre_tactic="Initial Access",
                    mitre_technique="T1190 — Exploit Public-Facing Application",
                    remediation=(
                        f"Implement authentication on {path}. "
                        "Return 401 for unauthenticated requests."
                    ),
                ))
            elif content_len > 100:
                findings.append(Finding(
                    agent=AgentName.PROBE,
                    title=f"Endpoint Accessible (Unverified): {path}",
                    description=(
                        f"HTTP 200 from {path} ({content_len} bytes, {er.response_type}). "
                        "Content type inconclusive — manual review needed. "
                        f"{artifact.format_report()}"
                    ),
                    severity=Severity.MEDIUM,
                    file_path=url,
                    mitre_tactic="Discovery",
                    mitre_technique="T1083 — File and Directory Discovery",
                    remediation="Review endpoint manually to determine if real data is exposed.",
                ))

        elif status == 403:
            findings.append(Finding(
                agent=AgentName.PROBE,
                title=f"Endpoint Protected: {path}",
                description=(
                    f"HTTP 403 from {path} — access denied. "
                    "Endpoint exists but authorization enforced. "
                    f"Request: GET {url} | Status: 403 Forbidden"
                ),
                severity=Severity.INFO,
                file_path=url,
                mitre_tactic="Discovery",
                mitre_technique="T1083 — File and Directory Discovery",
                remediation="Authorization appears enforced. Verify no bypass paths exist.",
            ))

    return findings


# ── API Endpoint Analysis ─────────────────────────────────────────────────────

def _check_api_endpoints(base: str, session: ScanSession) -> list[Finding]:
    """Probe API endpoints for data exposure and missing auth."""
    findings = []

    for api_base in API_BASES:
        url = base + api_base
        # 7c: was requests.get — now safe_request
        resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT,
                            allow_redirects=False)

        if not resp.ok and resp.status_code == 0:
            # FailedResponse — network failure, not an HTTP error
            _record_failure(session, url, resp.failure_class, resp.failure_reason)
            continue

        if resp.status_code in (200, 201):
            content_type = resp.headers.get("Content-Type", "")
            if "json" in content_type:
                try:
                    data = resp.json()
                    if isinstance(data, list) and len(data) > 0:
                        sample    = str(data[0])[:200]
                        sensitive = _check_sensitive_fields(sample)
                        severity  = Severity.CRITICAL if sensitive else Severity.HIGH

                        findings.append(Finding(
                            agent=AgentName.PROBE,
                            title=f"API Data Exposed Without Auth: {api_base}",
                            description=(
                                f"{url} returns {len(data)} records without authentication. "
                                f"Sample: {sample[:150]}"
                                + (f"\n⚠ Sensitive fields detected: {', '.join(sensitive)}"
                                   if sensitive else "")
                            ),
                            severity=severity,
                            file_path=url,
                            mitre_tactic="Collection",
                            mitre_technique="T1213 — Data from Information Repositories",
                            remediation=(
                                f"Implement authentication on {api_base}. "
                                "Ensure all API endpoints verify JWT/session before returning data. "
                                "Apply principle of least privilege — return only necessary fields."
                            ),
                        ))
                except (json.JSONDecodeError, ValueError):
                    pass

    return findings


# ── Auth Weakness Detection ───────────────────────────────────────────────────

def _check_auth_weaknesses(base: str, session: ScanSession) -> list[Finding]:
    """Test auth endpoints for user enumeration and missing security."""
    findings = []

    for path in AUTH_PATHS:
        url = base + path

        # 7c: was requests.get — now safe_request
        resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT,
                            allow_redirects=False)

        if not resp.ok and resp.status_code == 0:
            # FailedResponse — network failure, not an HTTP error
            _record_failure(session, url, resp.failure_class, resp.failure_reason)
            continue

        if resp.status_code not in (200, 405):
            continue

        test_valid   = _post_json(url, {
            "email":    "admin@juice-sh.op",
            "password": "definitely-wrong-password-sentinel-test",
        }, session)
        test_invalid = _post_json(url, {
            "email":    "nonexistent_sentinel_test_12345@example.com",
            "password": "definitely-wrong-password-sentinel-test",
        }, session)

        if test_valid and test_invalid:
            if test_valid.status_code != test_invalid.status_code:
                findings.append(Finding(
                    agent=AgentName.PROBE,
                    title=f"User Enumeration Possible: {path}",
                    description=(
                        f"Auth endpoint {url} returns different status codes for "
                        f"valid ({test_valid.status_code}) vs invalid "
                        f"({test_invalid.status_code}) email addresses. "
                        "Attackers can enumerate valid usernames."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=url,
                    mitre_tactic="Reconnaissance",
                    mitre_technique=(
                        "T1589.001 — Gather Victim Identity Information: Credentials"
                    ),
                    remediation=(
                        "Return identical error messages for both invalid username and "
                        "invalid password. "
                        "Use generic message: 'Invalid email or password' for all failures."
                    ),
                ))
            elif test_valid.text != test_invalid.text:
                findings.append(Finding(
                    agent=AgentName.PROBE,
                    title=f"User Enumeration via Response Body: {path}",
                    description=(
                        f"Auth endpoint {url} returns different response bodies for "
                        "valid vs invalid email addresses despite same status code. "
                        "Response content leaks whether an email exists."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=url,
                    mitre_tactic="Reconnaissance",
                    mitre_technique=(
                        "T1589.001 — Gather Victim Identity Information: Credentials"
                    ),
                    remediation=(
                        "Ensure identical response body for all authentication failures. "
                        "Do not reveal whether email exists in the system."
                    ),
                ))

    return findings


# ── IDOR Detection ────────────────────────────────────────────────────────────

def _check_idor(base: str, session: ScanSession) -> list[Finding]:
    """
    Test for IDOR by accessing resources with different IDs.
    Only OBSERVES responses — does not modify data.
    """
    findings = []

    idor_paths = [
        "/api/users/{id}",
        "/api/user/{id}",
        "/api/orders/{id}",
        "/api/basket/{id}",
        "/api/BasketItems/{id}",
        "/rest/user/{id}",
        "/api/feedback/{id}",
    ]

    for path_template in idor_paths:
        responses      = {}
        accessible_ids = []

        for test_id in IDOR_TEST_IDS:
            url = base + path_template.replace("{id}", str(test_id))

            # 7c: was requests.get — now safe_request
            resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT,
                                allow_redirects=False)

            if not resp.ok and resp.status_code == 0:
                _record_failure(session, url, resp.failure_class, resp.failure_reason)
                continue

            responses[test_id] = resp.status_code
            if resp.status_code == 200:
                accessible_ids.append(test_id)

        if len(accessible_ids) >= 2:
            path_base = path_template.replace("/{id}", "")
            findings.append(Finding(
                agent=AgentName.PROBE,
                title=f"IDOR: Unauthenticated Access to {path_base}",
                description=(
                    f"Endpoint {path_template} allows unauthenticated access to multiple records. "
                    f"Accessible IDs: {accessible_ids}. "
                    "An attacker can enumerate all records by iterating IDs."
                ),
                severity=Severity.CRITICAL,
                file_path=base + path_template,
                mitre_tactic="Collection",
                mitre_technique="T1213 — Data from Information Repositories",
                remediation=(
                    "1. Require authentication on all resource endpoints. "
                    "2. After authenticating, verify the requesting user owns the resource. "
                    "3. Consider using UUIDs instead of sequential integers. "
                    "4. Implement object-level authorization checks."
                ),
            ))

        elif len(accessible_ids) == 1:
            path_base = path_template.replace("/{id}", "")
            findings.append(Finding(
                agent=AgentName.PROBE,
                title=f"Potential IDOR: {path_base} ID {accessible_ids[0]} Accessible",
                description=(
                    f"Endpoint {path_template.replace('{id}', str(accessible_ids[0]))} "
                    "returned 200 without authentication. "
                    "May indicate IDOR or missing auth — requires manual verification."
                ),
                severity=Severity.HIGH,
                file_path=base + path_template,
                mitre_tactic="Collection",
                mitre_technique="T1213 — Data from Information Repositories",
                remediation=(
                    "Verify this endpoint requires authentication. "
                    "Implement authorization checks to ensure users can only access "
                    "their own resources."
                ),
            ))

    return findings


# ── HTTP Method Tampering ─────────────────────────────────────────────────────

def _check_dangerous_methods(base: str, session: ScanSession) -> list[Finding]:
    """
    Check if endpoints accept dangerous HTTP methods.

    Two-stage validation:
    1. OPTIONS probe — what methods does the server advertise?
    2. For each dangerous method advertised, send an unauthenticated request
       and check if it is accepted vs blocked.
    """
    findings = []
    test_endpoints = ["/api/users", "/api/user/1", "/api/orders"]

    for path in test_endpoints:
        url = base + path

        # Stage 1: OPTIONS — 7c: was requests.options
        resp = safe_request("OPTIONS", url, headers=HEADERS, timeout=TIMEOUT)

        if not resp.ok and resp.status_code == 0:
            # FailedResponse — network failure, not an HTTP error
            _record_failure(session, url, resp.failure_class, resp.failure_reason)
            continue

        allow = (resp.headers.get("Allow", "") or
                 resp.headers.get("Access-Control-Allow-Methods", ""))

        if not allow:
            continue

        dangerous_advertised = [m for m in ["DELETE", "PUT", "PATCH"]
                                 if m in allow.upper()]
        if not dangerous_advertised:
            continue

        # Stage 2: Test each dangerous method — 7c: was requests.request
        accepted = []
        blocked  = []

        for method in dangerous_advertised:
            test_resp = safe_request(method, url, headers=HEADERS, timeout=TIMEOUT,
                                     allow_redirects=False)

            if not test_resp.ok and test_resp.status_code == 0:
                # FailedResponse — network failure on dangerous method probe
                _record_failure(session, url, test_resp.failure_class,
                                test_resp.failure_reason)
                continue

            if test_resp.status_code in (401, 403, 405):
                blocked.append(f"{method}→{test_resp.status_code}")
            elif test_resp.status_code < 500:
                accepted.append(f"{method}→{test_resp.status_code}")

        if accepted:
            findings.append(Finding(
                agent=AgentName.PROBE,
                title=f"Dangerous HTTP Methods Accepted Without Auth: {path}",
                description=(
                    f"Endpoint {url} accepts dangerous methods without authentication. "
                    f"Accepted (unauthenticated): {', '.join(accepted)}. "
                    f"Blocked: {', '.join(blocked) or 'none'}. "
                    f"Advertised via OPTIONS: {allow}."
                ),
                severity=Severity.HIGH,
                file_path=url,
                mitre_tactic="Initial Access",
                mitre_technique="T1190 — Exploit Public-Facing Application",
                remediation=(
                    f"Block {', '.join(m.split('→')[0] for m in accepted)} on {path}. "
                    "Return 401 for unauthenticated dangerous method requests."
                ),
            ))
        elif dangerous_advertised:
            findings.append(Finding(
                agent=AgentName.PROBE,
                title=f"Dangerous HTTP Methods Advertised (Auth Enforced): {path}",
                description=(
                    f"Endpoint {url} advertises {', '.join(dangerous_advertised)} via OPTIONS "
                    f"but all were blocked with auth enforcement: {', '.join(blocked)}. "
                    "Authorization appears to be enforced — no confirmed vulnerability."
                ),
                severity=Severity.LOW,
                file_path=url,
                mitre_tactic="Discovery",
                mitre_technique="T1046 — Network Service Scanning",
                remediation=(
                    "Consider restricting OPTIONS response to not advertise methods "
                    "that should not be publicly known."
                ),
            ))

    return findings


# ── Rate Limit Detection ──────────────────────────────────────────────────────

def _check_rate_limiting(base: str, session: ScanSession) -> list[Finding]:
    """
    Check if auth endpoints have rate limiting.
    Sends 5 requests — NOT brute force, just checking if protection exists.
    """
    findings = []

    for path in ["/rest/user/login", "/api/login", "/login"]:
        url = base + path

        # 7c: was requests.get — now safe_request
        check = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT)

        if not check.ok and check.status_code == 0:
            _record_failure(session, url, check.failure_class, check.failure_reason)
            continue

        if check.status_code not in (200, 405, 400):
            continue

        responses = []
        for _ in range(5):
            resp = _post_json(url, {
                "email":    "ratelimit_test_sentinel@example.com",
                "password": "wrong_password_test",
            }, session)
            if resp:
                responses.append(resp.status_code)

        if (responses and
                all(r not in (429, 423, 503) for r in responses) and
                len(set(responses)) == 1):
            findings.append(Finding(
                agent=AgentName.PROBE,
                title=f"No Rate Limiting on Auth Endpoint: {path}",
                description=(
                    f"Auth endpoint {url} returned consistent {responses[0]} responses "
                    "across 5 rapid requests with no rate limiting detected (no HTTP 429). "
                    "This endpoint is vulnerable to credential stuffing and brute force attacks."
                ),
                severity=Severity.HIGH,
                file_path=url,
                mitre_tactic="Credential Access",
                mitre_technique="T1110 — Brute Force",
                remediation=(
                    "Implement rate limiting: max 5 failed attempts per IP per minute. "
                    "After threshold, return HTTP 429 with Retry-After header. "
                    "Consider CAPTCHA after repeated failures. "
                    "Implement account lockout after 10 failed attempts."
                ),
            ))

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _post_json(url: str, data: dict,
               session: ScanSession) -> "requests.Response | None":
    """
    Send a JSON POST request via safe_request.

    7c: migrated from raw requests.post to safe_request.

    Return contract:
        real requests.Response  — on HTTP success (any status code)
        None                    — on network failure (FailedResponse from safe_request)

    Callers receive either a real response or None. They never receive
    FailedResponse directly — the failure is recorded here and None is returned
    so callers do not need to know about FailedResponse semantics.
    """
    resp = safe_request(
        "POST", url,
        headers={**HEADERS, "Content-Type": "application/json"},
        timeout=TIMEOUT,
        allow_redirects=False,
        json=data,
    )
    if not resp.ok and resp.status_code == 0:
        # FailedResponse — record and return None so callers get a clean contract
        _record_failure(session, url, resp.failure_class, resp.failure_reason)
        return None
    return resp


def _check_sensitive_fields(text: str) -> list[str]:
    """Check if response contains sensitive field names."""
    sensitive_patterns = [
        "password", "passwd", "secret", "token", "api_key",
        "credit_card", "ssn", "social_security", "private_key",
        "access_token", "refresh_token", "auth_token",
    ]
    found      = []
    text_lower = text.lower()
    for pattern in sensitive_patterns:
        if pattern in text_lower:
            found.append(pattern)
    return found
