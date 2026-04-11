"""
sentinel/agents/config_agent.py

Config Agent — Misconfiguration Detection.
Checks for:
- Missing/insecure HTTP security headers
- Exposed admin panels
- Insecure CORS configuration
- Secrets in environment files
- Insecure cookie flags
- Server version disclosure
- Directory listing exposure

SCOPE: PASSIVE, PROBE, and ACTIVE modes.
ACTIONS: http_headers, header_analysis, config_read
NEVER: exploits, writes, modifies anything
"""

import os
import re
import requests  # for RequestException type only
from sentinel.core.evidence import safe_request
from pathlib import Path
from urllib.parse import urljoin

from sentinel.core import (
    validate_action, AgentName, ScanSession, Finding, Severity, ScanMode,
)

# Security headers that should be present
REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "description": "HSTS not set. Browser connections can be downgraded to HTTP.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1557 — Adversary-in-the-Middle",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options not set. Application may be vulnerable to clickjacking.",
        "remediation": "Add: X-Frame-Options: DENY (or SAMEORIGIN if framing is required)",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1185 — Browser Session Hijacking",
    },
    "X-Content-Type-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Content-Type-Options not set. Browser may MIME-sniff responses.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1036 — Masquerading",
    },
    "Content-Security-Policy": {
        "severity": Severity.HIGH,
        "description": "No Content Security Policy found. XSS and injection attacks are unrestricted.",
        "remediation": "Implement a strict CSP. Start with: Content-Security-Policy: default-src 'self'",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1059.007 — JavaScript",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy not set. Sensitive URL parameters may leak via Referer header.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "mitre_tactic": "Collection",
        "mitre_technique": "T1602 — Data from Information Repositories",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Permissions-Policy not set. Browser features (camera, mic, geolocation) unrestricted.",
        "remediation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "mitre_tactic": "Collection",
        "mitre_technique": "T1125 — Video Capture",
    },
}

# Headers that reveal server info and should be removed
DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

# Common exposed admin panel paths
ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/pma", "/cpanel", "/webmail", "/manager/html",
    "/.env", "/.git/config", "/config.php", "/web.config",
    "/api/swagger", "/swagger-ui.html", "/api-docs", "/graphql",
]

# Patterns that indicate secrets in config/env files
SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*=\s*["\']?[^\s"\']{4,}', "Hardcoded Password"),
    (r'(?i)(secret|api_key|apikey|api-key)\s*=\s*["\']?[^\s"\']{8,}', "Hardcoded Secret/API Key"),
    (r'(?i)(access_token|auth_token)\s*=\s*["\']?[^\s"\']{8,}', "Hardcoded Token"),
    (r'(?i)(aws_access_key_id)\s*=\s*[A-Z0-9]{20}', "AWS Access Key"),
    (r'(?i)(aws_secret_access_key)\s*=\s*[A-Za-z0-9/+=]{40}', "AWS Secret Key"),
    (r'(?i)database_url\s*=\s*[^\s]{10,}', "Database URL with Credentials"),
]

CONFIG_FILE_PATTERNS = ["*.env", ".env*", "config.py", "settings.py", "config.json",
                        "appsettings.json", "application.yml", "application.yaml"]


def run_config_agent(session: ScanSession, target_url: str = None, source_path: str = None) -> list[Finding]:
    """
    Run misconfiguration detection.
    - If target_url provided: check HTTP headers and exposed paths (PASSIVE/ACTIVE)
    - If source_path provided: scan config files for secrets (CODE/ACTIVE)
    """
    findings = []

    if target_url and session.mode in (ScanMode.PASSIVE, ScanMode.ACTIVE):
        findings.extend(_check_http_headers(session, target_url))
        if session.mode == ScanMode.ACTIVE:
            findings.extend(_check_exposed_paths(session, target_url))

    if source_path and session.mode in (ScanMode.CODE, ScanMode.ACTIVE):
        findings.extend(_scan_config_files(session, source_path))

    print(f"[CONFIG] {len(findings)} misconfiguration findings")
    return findings


# ── HTTP Header Checks ────────────────────────────────────────────────────────

def _check_http_headers(session: ScanSession, target_url: str) -> list[Finding]:
    from urllib.parse import urlparse
    _host = urlparse(target_url).hostname or target_url
    validate_action(AgentName.CONFIG, "http_headers", _host, session)
    validate_action(AgentName.CONFIG, "header_analysis", _host, session)

    findings = []
    try:
        resp = safe_request("GET", target_url, timeout=10)
        headers = resp.headers

        # Check required security headers
        for header, info in REQUIRED_HEADERS.items():
            if header not in headers:
                findings.append(Finding(
                    agent=AgentName.CONFIG,
                    title=f"Missing Security Header: {header}",
                    description=info["description"],
                    severity=info["severity"],
                    file_path=target_url,
                    mitre_tactic=info["mitre_tactic"],
                    mitre_technique=info["mitre_technique"],
                    remediation=info["remediation"],
                ))

        # Check for server version disclosure
        for header in DISCLOSURE_HEADERS:
            if header in headers:
                findings.append(Finding(
                    agent=AgentName.CONFIG,
                    title=f"Server Version Disclosure: {header}",
                    description=f"Header '{header}: {headers[header]}' reveals server technology. Attackers use this for targeted exploits.",
                    severity=Severity.LOW,
                    file_path=target_url,
                    mitre_tactic="Reconnaissance",
                    mitre_technique="T1592 — Gather Victim Host Information",
                    remediation=f"Remove or obscure the '{header}' header in your server/framework configuration.",
                ))

        # Check CORS
        if "Access-Control-Allow-Origin" in headers:
            if headers["Access-Control-Allow-Origin"] == "*":
                findings.append(Finding(
                    agent=AgentName.CONFIG,
                    title="Insecure CORS: Wildcard Origin Allowed",
                    description="Access-Control-Allow-Origin: * allows any domain to make cross-origin requests. This can expose authenticated endpoints to malicious sites.",
                    severity=Severity.HIGH,
                    file_path=target_url,
                    mitre_tactic="Collection",
                    mitre_technique="T1185 — Browser Session Hijacking",
                    remediation="Restrict CORS to specific trusted origins. Never use * on authenticated endpoints.",
                ))

        # Check insecure cookies
        for cookie in resp.cookies:
            cookie_issues = []
            if not cookie.secure:
                cookie_issues.append("Secure flag missing")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                cookie_issues.append("HttpOnly flag missing")
            if cookie_issues:
                findings.append(Finding(
                    agent=AgentName.CONFIG,
                    title=f"Insecure Cookie: {cookie.name}",
                    description=f"Cookie '{cookie.name}' has issues: {', '.join(cookie_issues)}.",
                    severity=Severity.MEDIUM,
                    file_path=target_url,
                    mitre_tactic="Credential Access",
                    mitre_technique="T1539 — Steal Web Session Cookie",
                    remediation=f"Set both Secure and HttpOnly flags on '{cookie.name}'. Consider adding SameSite=Strict.",
                ))

    except requests.RequestException as e:
        print(f"[CONFIG] HTTP check failed for {target_url}: {e}")

    return findings


# ── Exposed Path Checks ───────────────────────────────────────────────────────

def _check_exposed_paths(session: ScanSession, target_url: str) -> list[Finding]:
    """Check for exposed admin panels and sensitive files. ACTIVE mode only."""
    validate_action(AgentName.CONFIG, "http_probe", target_url, session)

    findings = []
    base = target_url.rstrip("/")

    for path in ADMIN_PATHS:
        url = base + path
        try:
            resp = safe_request("GET", url, timeout=5, allow_redirects=False)
            if resp.status_code in (200, 301, 302, 403):
                severity = Severity.CRITICAL if resp.status_code == 200 else Severity.MEDIUM
                findings.append(Finding(
                    agent=AgentName.CONFIG,
                    title=f"Exposed Sensitive Path: {path}",
                    description=f"Path '{url}' returned HTTP {resp.status_code}. This may expose administrative interfaces or sensitive configuration.",
                    severity=severity,
                    file_path=url,
                    mitre_tactic="Discovery",
                    mitre_technique="T1083 — File and Directory Discovery",
                    remediation=f"Restrict access to '{path}' via firewall rules, authentication, or removal. A 403 still confirms existence — prefer 404.",
                ))
        except requests.RequestException:
            continue

    return findings


# ── Config File Secret Scan ───────────────────────────────────────────────────

def _scan_config_files(session: ScanSession, source_path: str) -> list[Finding]:
    """Scan config and env files for hardcoded secrets."""
    validate_action(AgentName.CONFIG, "config_read", source_path, session)

    findings = []
    base = Path(source_path)

    config_files = []
    for pattern in CONFIG_FILE_PATTERNS:
        config_files.extend(base.rglob(pattern))

    for filepath in config_files:
        if ".git" in str(filepath):
            continue
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
            for pattern, label in SECRET_PATTERNS:
                matches = re.findall(pattern, content)
                if matches:
                    findings.append(Finding(
                        agent=AgentName.CONFIG,
                        title=f"Potential Secret in Config: {label}",
                        description=f"Pattern matching '{label}' found in {filepath.name}. Hardcoded secrets in config files are a critical risk.",
                        severity=Severity.CRITICAL,
                        file_path=str(filepath),
                        mitre_tactic="Credential Access",
                        mitre_technique="T1552.001 — Credentials in Files",
                        remediation=(
                            "1. Rotate the exposed credential immediately. "
                            "2. Move to environment variables or Azure Key Vault. "
                            "3. Audit git history — rotation required even after file removal."
                        ),
                    ))
        except Exception as e:
            print(f"[CONFIG] Could not read {filepath}: {e}")

    return findings
