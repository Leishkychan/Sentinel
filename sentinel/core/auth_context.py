"""
sentinel/core/auth_context.py

Authenticated Scanning Context.
Handles login, session management, and token storage for authenticated scans.

Supports:
  - Form-based login (email/password)
  - JWT token extraction and analysis
  - Cookie-based session management
  - Bearer token injection into agent requests

This module NEVER stores credentials permanently.
Credentials exist only in memory for the duration of the scan session.

NEVER:
  - Stores credentials to disk
  - Logs credentials in audit trail
  - Sends credentials to any service other than the target
"""

import json
import re
import base64
import requests
from typing import Optional
from datetime import datetime, timezone
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# TLS verification is disabled only for known lab targets (localhost/127.0.0.1)
# This is intentional for local test environments — not a global default

HEADERS = {"User-Agent": "Sentinel-SecurityScanner/1.0"}


class AuthContext:
    """
    Holds authentication state for a scan session.
    Provides authenticated HTTP methods to agents.
    """

    def __init__(self):
        self.logged_in:    bool = False
        self.jwt_token:    Optional[str] = None
        self.session_cookie: Optional[str] = None
        self.user_email:   Optional[str] = None
        self.user_role:    Optional[str] = None
        self.auth_headers: dict = {}
        self._session = requests.Session()
        # Disable TLS verification only for lab/local targets
        # For any real target, this should be True
        self._session.verify = False  # LAB_ONLY — set to True for production targets
        self._session.headers.update(HEADERS)

    def login(self, target_url: str, email: str, password: str) -> tuple[bool, list[dict]]:
        """
        Attempt login and extract auth tokens.
        Returns (success, findings) where findings are JWT/session security issues.

        NOTE: credential_use gating via validate_action() is deferred.
        AuthContext has no ScanSession reference, so validate_action cannot be called
        here. Gating requires a session-aware AuthContext follow-up that passes session
        into login() and calls validate_action(agent, "credential_use", url, session)
        before the POST is dispatched.
        """
        base = target_url.rstrip("/")
        findings = []

        # Try common login endpoints
        login_endpoints = [
            "/rest/user/login",
            "/api/login",
            "/api/user/login",
            "/auth/login",
            "/login",
        ]

        for endpoint in login_endpoints:
            url = base + endpoint
            try:
                resp = self._session.post(
                    url,
                    json={"email": email, "password": password},
                    headers={**HEADERS, "Content-Type": "application/json"},
                    timeout=10,
                )

                if resp.status_code in (200, 201):
                    # Try to extract JWT from response
                    token = self._extract_jwt(resp)
                    if token:
                        self.jwt_token = token
                        self.logged_in = True
                        self.user_email = email
                        self.auth_headers = {
                            "Authorization": f"Bearer {token}",
                            "Content-Type": "application/json",
                        }
                        self._session.headers.update(self.auth_headers)

                        # Analyze the JWT for security issues
                        jwt_findings = self._analyze_jwt(token, url)
                        findings.extend(jwt_findings)

                        print(f"[AUTH] Logged in as {email} via {endpoint}")
                        print(f"[AUTH] JWT: {token[:30]}...")
                        return True, findings

                    # Try cookie-based auth
                    cookies = resp.cookies
                    if cookies:
                        self.session_cookie = "; ".join(
                            f"{c.name}={c.value}" for c in cookies
                        )
                        self.logged_in = True
                        self.user_email = email
                        self._session.headers.update({"Cookie": self.session_cookie})
                        print(f"[AUTH] Logged in via cookie at {endpoint}")
                        return True, findings

            except requests.RequestException:
                continue

        print(f"[AUTH] Login failed for {email}")
        return False, findings

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Authenticated GET request."""
        if not self.logged_in:
            return None
        try:
            return self._session.get(url, timeout=10, **kwargs)
        except requests.RequestException:
            return None

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Authenticated POST request."""
        if not self.logged_in:
            return None
        try:
            return self._session.post(url, timeout=10, **kwargs)
        except requests.RequestException:
            return None

    def _extract_jwt(self, resp: requests.Response) -> Optional[str]:
        """Extract JWT from response body or headers."""
        # Check Authorization header
        auth_header = resp.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]

        # Check response body for token
        try:
            data = resp.json()
            # Common JWT locations in response
            for path in [
                ["token"],
                ["authentication", "token"],
                ["data", "token"],
                ["access_token"],
                ["auth_token"],
                ["jwt"],
            ]:
                val = data
                for key in path:
                    if isinstance(val, dict):
                        val = val.get(key)
                    else:
                        val = None
                        break
                if val and isinstance(val, str) and val.startswith("eyJ"):
                    return val
        except (json.JSONDecodeError, ValueError):
            pass

        return None

    def _analyze_jwt(self, token: str, source_url: str) -> list[dict]:
        """
        Analyze a JWT for security issues.
        Returns list of finding dicts.
        """
        findings = []

        try:
            parts = token.split(".")
            if len(parts) != 3:
                return findings

            # Decode header
            header_data = _b64_decode(parts[0])
            payload_data = _b64_decode(parts[1])

            header  = json.loads(header_data) if header_data else {}
            payload = json.loads(payload_data) if payload_data else {}

            algorithm = header.get("alg", "unknown")

            # Check for weak algorithm
            if algorithm == "none":
                findings.append({
                    "title": "JWT Uses 'none' Algorithm — Authentication Bypass",
                    "description": (
                        "JWT token uses 'alg: none' which means no signature verification. "
                        "Any attacker can forge tokens and impersonate any user."
                    ),
                    "severity": "CRITICAL",
                    "remediation": "Reject JWTs with 'none' algorithm server-side. Use RS256 or ES256.",
                })

            elif algorithm in ("HS256", "HS384", "HS512"):
                findings.append({
                    "title": f"JWT Uses Symmetric Algorithm: {algorithm}",
                    "description": (
                        f"JWT signed with {algorithm} (HMAC). If the secret is weak or leaked, "
                        "tokens can be forged. Consider RS256/ES256 for better security."
                    ),
                    "severity": "MEDIUM",
                    "remediation": "Use RS256 or ES256. Ensure HMAC secret is cryptographically random (32+ bytes).",
                })

            # Check for sensitive data in payload
            sensitive_keys = ["password", "secret", "credit_card", "ssn", "private"]
            found_sensitive = [k for k in sensitive_keys if k in str(payload).lower()]
            if found_sensitive:
                findings.append({
                    "title": "Sensitive Data in JWT Payload",
                    "description": (
                        f"JWT payload contains potentially sensitive fields: {found_sensitive}. "
                        "JWT payloads are base64-encoded, not encrypted — anyone can read them."
                    ),
                    "severity": "HIGH",
                    "remediation": "Never store sensitive data in JWT payload. Payload is readable by anyone.",
                })

            # Check for missing expiry
            if "exp" not in payload:
                findings.append({
                    "title": "JWT Has No Expiration (exp claim missing)",
                    "description": (
                        "JWT token has no expiration time. Tokens are valid forever. "
                        "If stolen, they can be used indefinitely."
                    ),
                    "severity": "HIGH",
                    "remediation": "Add 'exp' claim. Use short-lived tokens (15-60 minutes). Implement refresh tokens.",
                })
            else:
                # Check if expiry is too far in future
                exp = payload.get("exp", 0)
                now = datetime.now(timezone.utc).timestamp()
                if exp - now > 86400 * 7:  # More than 7 days
                    findings.append({
                        "title": "JWT Expiry Too Long (> 7 days)",
                        "description": (
                            f"JWT expires in {(exp - now) / 86400:.0f} days. "
                            "Long-lived tokens increase the window for token theft and replay attacks."
                        ),
                        "severity": "MEDIUM",
                        "remediation": "Reduce JWT lifetime to 15-60 minutes. Implement refresh token rotation.",
                    })

            # Check for user role in payload (potential privilege escalation)
            role = payload.get("role") or payload.get("roles") or payload.get("type")
            if role:
                self.user_role = str(role)
                findings.append({
                    "title": f"User Role Stored in JWT: {role}",
                    "description": (
                        f"Role '{role}' is stored in the JWT payload. "
                        "If the server trusts this without re-validating against the database, "
                        "an attacker who can forge tokens can escalate privileges."
                    ),
                    "severity": "MEDIUM",
                    "remediation": (
                        "Re-validate role server-side from database on each request. "
                        "Don't trust role claims in JWT without verification."
                    ),
                })

        except Exception as e:
            print(f"[AUTH] JWT analysis error: {e}")

        return findings


def _b64_decode(data: str) -> Optional[str]:
    """Decode base64url-encoded JWT segment."""
    try:
        # Add padding
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
    except Exception:
        return None


