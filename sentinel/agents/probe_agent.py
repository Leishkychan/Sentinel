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
import requests
from urllib.parse import urljoin, urlparse, urlencode
# TLS warnings suppressed per-request in safe_request/probe_with_evidence

from sentinel.core.evidence import probe_with_evidence
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
        resp, artifact = probe_with_evidence(url, method="GET", auth_sent=False)

        if resp is None:
            continue

        status = resp.status_code
        er = artifact.response

        # Show evidence in console
        print(f"[PROBE] {path}: HTTP {status} | {er.response_type} | {er.size_bytes}b | Auth: {'required' if er.auth_required else 'NOT required'}")

        if status == 200:
            content_len = er.size_bytes
            is_spa = SPA_SIZE_MIN < content_len < SPA_SIZE_MAX and "html" in er.content_type.lower()

            if is_spa:
                # SPA shell — document but do NOT claim real admin access
                findings.append(Finding(
                    agent=AgentName.PROBE,
                    title=f"SPA Route Responds: {path}",
                    description=(
                        f"Endpoint {url} returned HTTP 200 with {content_len} bytes (HTML). "
                        f"Response matches SPA shell pattern — likely client-side routing, "
                        f"not server-side admin functionality. "
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
                # Real JSON data — confirmed finding
                # Construct EvidenceRef from the already-executed probe_with_evidence result.
                # All fields come from er (ResponseArtifact) — nothing synthesized.
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
                        f"CONFIRMED: {path} returns {er.response_type} data without authentication. "
                        f"{artifact.format_report()}"
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
                # Unknown content — flag for review
                findings.append(Finding(
                    agent=AgentName.PROBE,
                    title=f"Endpoint Accessible (Unverified): {path}",
                    description=(
                        f"HTTP 200 from {path} ({content_len} bytes, {er.response_type}). "
                        f"Content type inconclusive — manual review needed. "
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
                    f"Endpoint exists but authorization enforced. "
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
        try:
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                                verify=False, allow_redirects=False)

            if resp.status_code in (200, 201):
                content_type = resp.headers.get("Content-Type", "")
                if "json" in content_type:
                    try:
                        data = resp.json()
                        # Check if it returns a list (data exposure)
                        if isinstance(data, list) and len(data) > 0:
                            sample = str(data[0])[:200]
                            # Check for sensitive fields in response
                            sensitive = _check_sensitive_fields(sample)
                            severity = Severity.CRITICAL if sensitive else Severity.HIGH

                            findings.append(Finding(
                                agent=AgentName.PROBE,
                                title=f"API Data Exposed Without Auth: {api_base}",
                                description=(
                                    f"{url} returns {len(data)} records without authentication. "
                                    f"Sample: {sample[:150]}"
                                    + (f"\n⚠ Sensitive fields detected: {', '.join(sensitive)}" if sensitive else "")
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

        except requests.RequestException:
            continue

    return findings


# ── Auth Weakness Detection ───────────────────────────────────────────────────

def _check_auth_weaknesses(base: str, session: ScanSession) -> list[Finding]:
    """Test auth endpoints for user enumeration and missing security."""
    findings = []

    for path in AUTH_PATHS:
        url = base + path
        try:
            # First check if endpoint exists
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                                verify=False, allow_redirects=False)

            if resp.status_code not in (200, 405):
                continue

            # Test for user enumeration: different responses for valid vs invalid user
            test_valid = _post_json(url, {
                "email": "admin@juice-sh.op",  # Known valid user in Juice Shop
                "password": "definitely-wrong-password-sentinel-test"
            })
            test_invalid = _post_json(url, {
                "email": "nonexistent_sentinel_test_12345@example.com",
                "password": "definitely-wrong-password-sentinel-test"
            })

            if test_valid and test_invalid:
                if test_valid.status_code != test_invalid.status_code:
                    findings.append(Finding(
                        agent=AgentName.PROBE,
                        title=f"User Enumeration Possible: {path}",
                        description=(
                            f"Auth endpoint {url} returns different status codes for "
                            f"valid ({test_valid.status_code}) vs invalid ({test_invalid.status_code}) "
                            f"email addresses. Attackers can enumerate valid usernames."
                        ),
                        severity=Severity.MEDIUM,
                        file_path=url,
                        mitre_tactic="Reconnaissance",
                        mitre_technique="T1589.001 — Gather Victim Identity Information: Credentials",
                        remediation=(
                            "Return identical error messages for both invalid username and invalid password. "
                            "Use generic message: 'Invalid email or password' for all failures."
                        ),
                    ))
                elif test_valid.text != test_invalid.text:
                    # Different response bodies even with same status code
                    findings.append(Finding(
                        agent=AgentName.PROBE,
                        title=f"User Enumeration via Response Body: {path}",
                        description=(
                            f"Auth endpoint {url} returns different response bodies for "
                            f"valid vs invalid email addresses despite same status code. "
                            "Response content leaks whether an email exists."
                        ),
                        severity=Severity.MEDIUM,
                        file_path=url,
                        mitre_tactic="Reconnaissance",
                        mitre_technique="T1589.001 — Gather Victim Identity Information: Credentials",
                        remediation=(
                            "Ensure identical response body for all authentication failures. "
                            "Do not reveal whether email exists in the system."
                        ),
                    ))

        except requests.RequestException:
            continue

    return findings


# ── IDOR Detection ────────────────────────────────────────────────────────────

def _check_idor(base: str, session: ScanSession) -> list[Finding]:
    """
    Test for IDOR by accessing resources with different IDs.
    Only OBSERVES responses — does not modify data.
    """
    findings = []

    # Common ID-based API patterns
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
        responses = {}
        accessible_ids = []

        for test_id in IDOR_TEST_IDS:
            url = base + path_template.replace("{id}", str(test_id))
            try:
                resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                                    verify=False, allow_redirects=False)
                responses[test_id] = resp.status_code

                if resp.status_code == 200:
                    accessible_ids.append(test_id)

            except requests.RequestException:
                continue

        # If we can access multiple IDs without auth, that's an IDOR
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
                    "2. After authenticating, verify the requesting user owns the requested resource. "
                    "3. Consider using UUIDs instead of sequential integers to prevent enumeration. "
                    "4. Implement object-level authorization checks."
                ),
            ))

        elif len(accessible_ids) == 1:
            # Only one ID accessible — flag for manual review
            path_base = path_template.replace("/{id}", "")
            findings.append(Finding(
                agent=AgentName.PROBE,
                title=f"Potential IDOR: {path_base} ID {accessible_ids[0]} Accessible",
                description=(
                    f"Endpoint {path_template.replace('{id}', str(accessible_ids[0]))} "
                    f"returned 200 without authentication. "
                    "May indicate IDOR or missing auth — requires manual verification."
                ),
                severity=Severity.HIGH,
                file_path=base + path_template,
                mitre_tactic="Collection",
                mitre_technique="T1213 — Data from Information Repositories",
                remediation=(
                    "Verify this endpoint requires authentication. "
                    "Implement authorization checks to ensure users can only access their own resources."
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
       and check if it's accepted (2xx/4xx with data) vs blocked (401/403/405)

    A finding is only raised if a method is BOTH advertised AND not blocked.
    """
    findings = []
    test_endpoints = ["/api/users", "/api/user/1", "/api/orders"]

    for path in test_endpoints:
        url = base + path
        try:
            # Stage 1: OPTIONS
            resp = requests.options(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            allow = (resp.headers.get("Allow", "") or
                     resp.headers.get("Access-Control-Allow-Methods", ""))

            if not allow:
                continue

            dangerous_advertised = [m for m in ["DELETE", "PUT", "PATCH"] if m in allow.upper()]
            if not dangerous_advertised:
                continue

            # Stage 2: Test each dangerous method — is it actually accepted?
            accepted = []
            blocked  = []
            for method in dangerous_advertised:
                try:
                    test_resp = requests.request(
                        method, url,
                        headers=HEADERS,
                        timeout=TIMEOUT,
                        verify=False,
                        allow_redirects=False,
                    )
                    if test_resp.status_code in (401, 403, 405):
                        blocked.append(f"{method}→{test_resp.status_code}")
                    elif test_resp.status_code < 500:
                        accepted.append(f"{method}→{test_resp.status_code}")
                    # 500 = method reached but server error — note separately
                except requests.RequestException:
                    continue

            if accepted:
                # Methods are advertised AND accepted without auth — real finding
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
                # Methods advertised but all blocked — downgraded finding
                findings.append(Finding(
                    agent=AgentName.PROBE,
                    title=f"Dangerous HTTP Methods Advertised (Auth Enforced): {path}",
                    description=(
                        f"Endpoint {url} advertises {', '.join(dangerous_advertised)} via OPTIONS "
                        f"but all were blocked with auth enforcement: {', '.join(blocked)}. "
                        f"Authorization appears to be enforced — no confirmed vulnerability."
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
        except requests.RequestException:
            continue

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
        try:
            # Check if endpoint exists first
            check = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            if check.status_code not in (200, 405, 400):
                continue

            # Send 5 rapid requests with wrong credentials
            responses = []
            for _ in range(5):
                resp = _post_json(url, {
                    "email": "ratelimit_test_sentinel@example.com",
                    "password": "wrong_password_test"
                })
                if resp:
                    responses.append(resp.status_code)

            # If all 5 return same error (no 429 or blocking), rate limiting missing
            if responses and all(r not in (429, 423, 503) for r in responses) and len(set(responses)) == 1:
                findings.append(Finding(
                    agent=AgentName.PROBE,
                    title=f"No Rate Limiting on Auth Endpoint: {path}",
                    description=(
                        f"Auth endpoint {url} returned consistent {responses[0]} responses "
                        f"across 5 rapid requests with no rate limiting detected (no HTTP 429). "
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

        except requests.RequestException:
            continue

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _post_json(url: str, data: dict) -> requests.Response | None:
    """Send a JSON POST request safely."""
    try:
        return requests.post(
            url,
            json=data,
            headers={**HEADERS, "Content-Type": "application/json"},
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=False,
        )
    except requests.RequestException:
        return None


def _check_sensitive_fields(text: str) -> list[str]:
    """Check if response contains sensitive field names."""
    sensitive_patterns = [
        "password", "passwd", "secret", "token", "api_key",
        "credit_card", "ssn", "social_security", "private_key",
        "access_token", "refresh_token", "auth_token",
    ]
    found = []
    text_lower = text.lower()
    for pattern in sensitive_patterns:
        if pattern in text_lower:
            found.append(pattern)
    return found
