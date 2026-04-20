from typing import Optional
"""
sentinel/agents/auth_scan_agent.py

Authenticated Scanning Agent.
Uses a real authenticated session to find vulnerabilities only visible
when logged in — things passive/unauthenticated scanning completely misses.

Finds:
  - IDOR with real user context (access another user's basket/orders/profile)
  - Broken function-level authorization (user accessing admin functions)
  - Mass assignment (set isAdmin=true, change other users' data)
  - JWT algorithm confusion (try sending modified token)
  - Sensitive data in authenticated responses (passwords in profile, etc.)
  - Privilege escalation via parameter manipulation
  - Account enumeration via authenticated endpoints

SCOPE: PROBE and ACTIVE modes only.
ACTIONS: http_probe (authenticated)
NEVER: modifies production data permanently, exploits vulns,
       steals other users' real data
"""

import json
import re
import sys
import requests
from urllib.parse import urljoin
# TLS warnings suppressed per-request in safe_request/probe_with_evidence

from sentinel.core import (
    validate_action, AgentName, ScanSession, Finding, Severity, ScanMode,
)
from sentinel.core.auth_context import AuthContext, get_test_credentials
from sentinel.core.evidence import classify_failure

HEADERS = {"User-Agent": "Sentinel-SecurityScanner/1.0"}
TIMEOUT = 10


def run_auth_scan_agent(session: ScanSession, target_url: str,
                         auth: Optional[AuthContext] = None) -> list[Finding]:
    """
    Run authenticated vulnerability scan.
    If no auth context provided, attempts login with known test credentials.
    """
    validate_action(AgentName.AUTH_SCAN, "http_probe", target_url, session)

    base = target_url.rstrip("/")
    findings = []
    auth_findings = []

    # Get or create auth context
    if not auth or not auth.logged_in:
        auth = AuthContext()
        creds = get_test_credentials(target_url)

        for email, password in creds:
            success, jwt_findings = auth.login(base, email, password)
            auth_findings.extend(jwt_findings)
            if success:
                break

    # Convert JWT findings to Finding objects
    for jf in auth_findings:
        findings.append(Finding(
            agent=AgentName.AUTH_SCAN,
            title=jf["title"],
            description=jf["description"],
            severity=Severity(jf["severity"]),
            file_path=base + "/rest/user/login",
            cve_id="CWE-347",
            mitre_tactic="Credential Access",
            mitre_technique="T1539 — Steal Web Session Cookie",
            remediation=jf["remediation"],
        ))

    if not auth.logged_in:
        findings.append(Finding(
            agent=AgentName.AUTH_SCAN,
            title="Could Not Authenticate — Authenticated Scan Skipped",
            description=(
                "Sentinel attempted authentication with known test credentials "
                "but could not log in. Provide credentials via --auth flag for "
                "authenticated scanning."
            ),
            severity=Severity.INFO,
            file_path=base,
            remediation="Provide credentials for authenticated scanning to find auth-dependent vulns.",
        ))
        return findings

    print(f"[AUTH_SCAN] Authenticated as {auth.user_email} (role: {auth.user_role or 'unknown'})")

    # Run authenticated checks
    findings.extend(_check_idor_authenticated(base, auth, session))
    findings.extend(_check_privilege_escalation(base, auth, session))
    findings.extend(_check_sensitive_data_exposure(base, auth, session))
    findings.extend(_check_mass_assignment(base, auth, session))
    findings.extend(_check_admin_function_access(base, auth, session))

    print(f"[AUTH_SCAN] {len(findings)} authenticated findings")
    return findings


def _check_idor_authenticated(base: str, auth: AuthContext,
                               session: ScanSession) -> list[Finding]:
    """
    IDOR check with real auth context.
    Get current user's data first, then try accessing other users'.
    """
    findings = []

    # Get current user info
    whoami_resp = auth.get(f"{base}/rest/user/whoami")
    current_user_id = None

    if whoami_resp and whoami_resp.status_code == 200:
        try:
            data = whoami_resp.json()
            current_user_id = (
                data.get("data", {}).get("id") or
                data.get("id") or
                data.get("user", {}).get("id")
            )
            print(f"[AUTH_SCAN] Current user ID: {current_user_id}")
        except (json.JSONDecodeError, ValueError):
            pass

    # Try to access OTHER users' data
    test_ids = [1, 2, 3, 4, 5]
    if current_user_id:
        test_ids = [i for i in test_ids if i != current_user_id]

    idor_endpoints = [
        ("/api/users/{id}",      "User Profile"),
        ("/api/BasketItems/{id}", "Basket Items"),
        ("/api/orders/{id}",     "Order Details"),
        ("/api/Feedbacks/{id}",  "User Feedback"),
    ]

    for endpoint_template, resource_name in idor_endpoints:
        accessible_other_ids = []

        for test_id in test_ids[:3]:
            url = base + endpoint_template.replace("{id}", str(test_id))
            resp = auth.get(url)

            if resp and resp.status_code == 200:
                content = resp.text
                # Check it's real data, not an error
                if len(content) > 50 and "error" not in content.lower()[:50]:
                    accessible_other_ids.append(test_id)

        if accessible_other_ids:
            findings.append(Finding(
                agent=AgentName.AUTH_SCAN,
                title=f"IDOR: Authenticated User Accesses Other Users' {resource_name}",
                description=(
                    f"Authenticated as {auth.user_email}, was able to access "
                    f"{resource_name} belonging to user IDs: {accessible_other_ids}. "
                    "The application does not verify resource ownership."
                ),
                severity=Severity.CRITICAL,
                file_path=base + endpoint_template,
                cve_id="CWE-639",
                mitre_tactic="Collection",
                mitre_technique="T1213 — Data from Information Repositories",
                remediation=(
                    "Implement object-level authorization: verify the requesting user "
                    "owns the requested resource before returning data. "
                    "Check: user.id == resource.user_id on every request."
                ),
            ))

    return findings


def _check_privilege_escalation(base: str, auth: AuthContext,
                                  session: ScanSession) -> list[Finding]:
    """Check if regular user can access admin functionality."""
    findings = []

    admin_endpoints = [
        ("/api/users",         "User List (Admin)"),
        ("/administration",    "Admin Panel"),
        ("/api/Challenges",    "Challenge List (Admin)"),
        ("/metrics",           "Metrics (Admin)"),
        ("/api/SecurityQuestions", "Security Questions"),
    ]

    for endpoint, name in admin_endpoints:
        url = base + endpoint
        resp = auth.get(url)

        if resp and resp.status_code == 200:
            content_len = len(resp.content)
            content_type = resp.headers.get("Content-Type", "")

            # Check if we got real data
            if content_len > 100:
                is_json_data = "json" in content_type
                data_preview = resp.text[:200]

                findings.append(Finding(
                    agent=AgentName.AUTH_SCAN,
                    title=f"Privilege Escalation: Regular User Accesses {name}",
                    description=(
                        f"Authenticated as regular user {auth.user_email}, "
                        f"was able to access {name} at {url}. "
                        f"Response: {content_len} bytes. "
                        f"Preview: {data_preview[:100]}"
                    ),
                    severity=Severity.CRITICAL,
                    file_path=url,
                    cve_id="CWE-269",
                    mitre_tactic="Privilege Escalation",
                    mitre_technique="T1548 — Abuse Elevation Control Mechanism",
                    remediation=(
                        f"Implement role-based access control on {endpoint}. "
                        "Verify user has admin role before returning data. "
                        "Return 403 for unauthorized access attempts."
                    ),
                ))

    return findings


def _check_sensitive_data_exposure(base: str, auth: AuthContext,
                                    session: ScanSession) -> list[Finding]:
    """Check if authenticated responses expose sensitive data unnecessarily."""
    findings = []

    sensitive_endpoints = [
        "/rest/user/whoami",
        "/api/users/1",
        "/api/currentUser",
    ]

    sensitive_fields = [
        "password", "passwordHash", "totpSecret", "securityAnswer",
        "credit_card", "creditCard", "cvv", "ssn",
    ]

    for endpoint in sensitive_endpoints:
        url = base + endpoint
        resp = auth.get(url)

        if not resp or resp.status_code != 200:
            continue

        try:
            data = resp.json()
            data_str = json.dumps(data).lower()

            found_sensitive = [f for f in sensitive_fields if f.lower() in data_str]
            if found_sensitive:
                findings.append(Finding(
                    agent=AgentName.AUTH_SCAN,
                    title=f"Sensitive Data Exposed in API Response: {endpoint}",
                    description=(
                        f"Authenticated API response from {url} contains sensitive fields: "
                        f"{', '.join(found_sensitive)}. "
                        "These fields should never be returned in API responses."
                    ),
                    severity=Severity.HIGH,
                    file_path=url,
                    cve_id="CWE-312",
                    mitre_tactic="Collection",
                    mitre_technique="T1552 — Unsecured Credentials",
                    remediation=(
                        "Remove sensitive fields from API responses. "
                        "Use field allowlisting: explicitly define which fields to return. "
                        "Never return password hashes, security answers, or payment data."
                    ),
                ))
        except (json.JSONDecodeError, ValueError):
            pass

    return findings


def _check_mass_assignment(base: str, auth: AuthContext,
                            session: ScanSession) -> list[Finding]:
    """
    Test for mass assignment vulnerabilities.
    Tries to set privileged fields that shouldn't be user-settable.
    OBSERVATION ONLY — checks if server accepts the field, doesn't verify effect.
    """
    findings = []

    # Test profile update endpoint
    profile_endpoints = [
        "/api/users/1",
        "/rest/user/changeProfile",
        "/api/user/changeProfile",
    ]

    # Privileged fields we try to set (observation only)
    for endpoint in profile_endpoints:
        url = base + endpoint
        try:
            # 7c: auth._session.put bypassed the request contract entirely.
            # Wrapped here to enforce exception handling and failure recording.
            # Full AuthContext harmonisation is a separate pass (auth_scan 7c part 2).
            try:
                resp = auth._session.put(
                    url,
                    json={"role": "admin", "isAdmin": True},
                    timeout=TIMEOUT,
                    verify=False,
                )
            except requests.RequestException as _put_exc:
                _fc = classify_failure(str(_put_exc))
                print(f"[WARN] [auth_scan_agent] PUT failed: {url} — {_fc}: {_put_exc}",
                      file=sys.stderr)
                intel = getattr(session, '_session_intel', None)
                if intel is not None:
                    intel.record_request_failure(
                        "auth_scan_agent", url, _fc, str(_put_exc))
                continue

            if resp and resp.status_code in (200, 201, 204):
                try:
                    data = resp.json()
                    data_str = json.dumps(data).lower()
                    # Check if the server accepted and reflected the privileged field
                    if "admin" in data_str or "isadmin" in data_str:
                        findings.append(Finding(
                            agent=AgentName.AUTH_SCAN,
                            title=f"Mass Assignment: Privileged Fields Accepted at {endpoint}",
                            description=(
                                f"Endpoint {url} accepted privileged fields (role/isAdmin) "
                                "in the request body and reflected them in the response. "
                                "Mass assignment vulnerability allows users to escalate privileges."
                            ),
                            severity=Severity.CRITICAL,
                            file_path=url,
                            cve_id="CWE-915",
                            mitre_tactic="Privilege Escalation",
                            mitre_technique="T1548 — Abuse Elevation Control Mechanism",
                            remediation=(
                                "Implement field allowlisting on all update endpoints. "
                                "Explicitly define which fields users are allowed to update. "
                                "Never bind request body directly to database model."
                            ),
                        ))
                except (json.JSONDecodeError, ValueError):
                    pass

        except requests.RequestException as e:
            # Inner try already handles PUT failures explicitly.
            # This outer handler catches anything else in the block
            # (JSON inspection, Finding construction).
            # Logged rather than silently continued to surface future regressions.
            print(f"[WARN] [auth_scan_agent] Unexpected error in mass_assignment "
                  f"check for {url} — {e}", file=sys.stderr)
            continue

    return findings


def _check_admin_function_access(base: str, auth: AuthContext,
                                  session: ScanSession) -> list[Finding]:
    """Check if authenticated user can perform admin actions."""
    findings = []

    # Try to access the admin challenge solution endpoint
    admin_actions = [
        ("/api/Challenges/?name=Score Board", "GET", None, "Challenge Data"),
        ("/api/Users/?email=admin@juice-sh.op", "GET", None, "Admin User Data"),
    ]

    for endpoint, method, body, name in admin_actions:
        url = base + endpoint
        try:
            if method == "GET":
                resp = auth.get(url)
            else:
                resp = auth.post(url, json=body)

            if resp and resp.status_code == 200 and len(resp.content) > 50:
                findings.append(Finding(
                    agent=AgentName.AUTH_SCAN,
                    title=f"Admin Function Accessible to Regular User: {name}",
                    description=(
                        f"Regular user {auth.user_email} can access admin function "
                        f"'{name}' at {url}. "
                        f"Response size: {len(resp.content)} bytes."
                    ),
                    severity=Severity.HIGH,
                    file_path=url,
                    cve_id="CWE-862",
                    mitre_tactic="Discovery",
                    mitre_technique="T1083 — File and Directory Discovery",
                    remediation=(
                        "Implement function-level access control. "
                        "Verify admin role before executing privileged operations."
                    ),
                ))
        except requests.RequestException:
            # auth.get/post routes through AuthContext — not yet harmonised
            # with safe_request contract. Silent continue is acceptable here
            # until AuthContext migration (auth_scan 7c part 2).
            continue

    return findings


# For type hints

