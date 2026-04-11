"""
sentinel/agents/js_analysis_agent.py

JavaScript Analysis Agent.
Downloads and analyzes client-side JavaScript files for:
  - Hardcoded API keys, tokens, secrets
  - Hidden/internal API endpoints
  - Commented-out debug routes
  - Source map exposure (leaks original source)
  - Sensitive business logic in frontend code
  - JWT secrets embedded in JS
  - Internal IP addresses and hostnames

SCOPE: PROBE and ACTIVE modes.
ACTIONS: http_probe (GET requests to fetch JS files only)
NEVER: executes JavaScript, modifies anything, sends payloads
"""

import re
import json
import requests  # for RequestException type only
from sentinel.core.evidence import safe_request
from urllib.parse import urljoin, urlparse
# TLS warnings suppressed per-request in safe_request/probe_with_evidence

from sentinel.core import (
    validate_action, AgentName, ScanSession, Finding, Severity,
)

HEADERS = {"User-Agent": "Sentinel-SecurityScanner/1.0"}
TIMEOUT = 10
MAX_JS_SIZE_KB = 2000  # Skip JS files larger than 2MB

# Patterns that indicate secrets in JavaScript
SECRET_PATTERNS = [
    (r'(?i)(api[_\-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9\-_]{20,})["\']', "API Key"),
    (r'(?i)(secret[_\-]?key|secret)\s*[:=]\s*["\']([A-Za-z0-9\-_/+=]{20,})["\']', "Secret Key"),
    (r'(?i)(access[_\-]?token)\s*[:=]\s*["\']([A-Za-z0-9\-_./+=]{20,})["\']', "Access Token"),
    (r'(?i)(password|passwd)\s*[:=]\s*["\']([^"\']{4,})["\']', "Hardcoded Password"),
    (r'(?i)(aws[_\-]?access[_\-]?key[_\-]?id)\s*[:=]\s*["\']([A-Z0-9]{20})["\']', "AWS Access Key"),
    (r'(?i)(private[_\-]?key)\s*[:=]\s*["\']([^"\']{20,})["\']', "Private Key"),
    (r'eyJ[A-Za-z0-9\-_]{20,}\.eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}', "JWT Token"),
    (r'(?i)(stripe[_\-]?key|stripe[_\-]?secret)\s*[:=]\s*["\']([A-Za-z0-9_]{20,})["\']', "Stripe Key"),
    (r'(?i)(sendgrid|mailgun|twilio)[_\-]?(key|secret|token)\s*[:=]\s*["\']([A-Za-z0-9\-_]{20,})["\']', "Service API Key"),
]

# Patterns that indicate internal endpoints
ENDPOINT_PATTERNS = [
    r'["\`]/api/[a-zA-Z0-9/_\-]{3,}["\`]',
    r'["\`]/rest/[a-zA-Z0-9/_\-]{3,}["\`]',
    r'["\`]/internal/[a-zA-Z0-9/_\-]{3,}["\`]',
    r'["\`]/admin/[a-zA-Z0-9/_\-]{3,}["\`]',
    r'["\`]/private/[a-zA-Z0-9/_\-]{3,}["\`]',
    r'["\`]/v[0-9]/[a-zA-Z0-9/_\-]{3,}["\`]',
]

# Internal infrastructure patterns
INTERNAL_PATTERNS = [
    (r'(?i)https?://(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d+\.\d+', "Internal IP Address"),
    (r'(?i)https?://[a-zA-Z0-9\-]+\.(?:internal|local|corp|intranet|lan)\b', "Internal Hostname"),
    (r'(?i)localhost:\d{4,5}', "Localhost Reference"),
    (r'(?i)127\.0\.0\.1:\d{4,5}', "Loopback Reference"),
]


def run_js_agent(session: ScanSession, target_url: str) -> list[Finding]:
    """Download and analyze all JavaScript files from the target."""
    validate_action(AgentName.JS, "http_probe", target_url, session)

    base = target_url.rstrip("/")
    findings = []

    # Find JS files from the main page
    js_urls = _discover_js_files(base)
    print(f"[JS] Found {len(js_urls)} JavaScript files to analyze")

    # Check for source map exposure
    for js_url in js_urls[:20]:  # Cap at 20 files
        findings.extend(_check_source_map(js_url, session))

    # Analyze JS content
    for js_url in js_urls[:10]:  # Deeper analysis on first 10
        content = _fetch_js(js_url)
        if not content:
            continue

        findings.extend(_find_secrets(content, js_url))
        findings.extend(_find_endpoints(content, js_url, base))
        findings.extend(_find_internal_references(content, js_url))

    print(f"[JS] {len(findings)} JavaScript findings")
    return findings


def _discover_js_files(base: str) -> list[str]:
    """Fetch the main page and extract all JS file URLs."""
    js_urls = []
    try:
        resp = safe_request("GET", base, headers=HEADERS, timeout=TIMEOUT)
        if resp.status_code != 200:
            return js_urls

        # Find all script src tags
        script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in script_pattern.finditer(resp.text):
            src = match.group(1)
            if src.startswith("http"):
                js_urls.append(src)
            else:
                js_urls.append(urljoin(base, src))

        # Also check common JS paths
        common_js = [
            "/main.js", "/app.js", "/bundle.js", "/vendor.js",
            "/runtime.js", "/polyfills.js", "/chunk.js",
            "/assets/js/main.js", "/static/js/main.js",
            "/js/app.js", "/dist/bundle.js",
        ]
        for path in common_js:
            url = base + path
            try:
                r = safe_request("HEAD", url, headers=HEADERS, timeout=5)
                if r.status_code == 200:
                    js_urls.append(url)
            except requests.RequestException:
                pass

    except requests.RequestException:
        pass

    return list(dict.fromkeys(js_urls))  # Deduplicate


def _fetch_js(url: str) -> str | None:
    """Fetch JS file content, skip if too large."""
    try:
        resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT)
        if resp.status_code != 200:
            return None
        size_kb = len(resp.content) / 1024
        if size_kb > MAX_JS_SIZE_KB:
            print(f"[JS] Skipping {url} — too large ({size_kb:.0f}KB)")
            return None
        # For large files, sample first 200KB + last 50KB (secrets often at top or bottom)
        text = resp.text
        if size_kb > 500:
            print(f"[JS] Large file ({size_kb:.0f}KB) — sampling key sections")
            text = text[:200000] + "\n/* ...SENTINEL SAMPLE... */\n" + text[-50000:]
        return text
    except requests.RequestException:
        return None


def _check_source_map(js_url: str, session: ScanSession) -> list[Finding]:
    """Check if a source map (.map) file is exposed for this JS file."""
    findings = []
    map_url = js_url + ".map"
    try:
        resp = safe_request("GET", map_url, headers=HEADERS, timeout=TIMEOUT)
        if resp.status_code == 200 and len(resp.content) > 100:
            try:
                data = resp.json()
                has_sources = bool(data.get("sources") or data.get("sourcesContent"))
                if has_sources:
                    findings.append(Finding(
                        agent=AgentName.JS,
                        title=f"Source Map Exposed: {js_url.split('/')[-1]}.map",
                        description=(
                            f"JavaScript source map exposed at {map_url}. "
                            "Source maps reveal the original unminified source code, "
                            "including comments, variable names, file structure, and business logic. "
                            f"Sources found: {data.get('sources', [])[:3]}"
                        ),
                        severity=Severity.HIGH,
                        file_path=map_url,
                        mitre_tactic="Reconnaissance",
                        mitre_technique="T1592 — Gather Victim Host Information",
                        remediation=(
                            "Remove .map files from production deployments. "
                            "Configure your build pipeline to exclude source maps in production. "
                            "If source maps are needed for error tracking, use a service "
                            "like Sentry that uploads maps privately."
                        ),
                    ))
            except (json.JSONDecodeError, ValueError):
                pass
    except requests.RequestException:
        pass
    return findings


def _find_secrets(content: str, js_url: str) -> list[Finding]:
    """Scan JS content for hardcoded secrets."""
    findings = []
    for pattern, label in SECRET_PATTERNS:
        matches = re.findall(pattern, content)
        if matches:
            # Get context around first match
            match = re.search(pattern, content)
            context = ""
            if match:
                start = max(0, match.start() - 30)
                end = min(len(content), match.end() + 30)
                context = content[start:end].strip()

            findings.append(Finding(
                agent=AgentName.JS,
                title=f"Hardcoded Secret in JavaScript: {label}",
                description=(
                    f"Found {label} hardcoded in {js_url.split('/')[-1]}. "
                    f"Context: ...{context}... "
                    "Secrets in JavaScript are visible to ALL users who load the page."
                ),
                severity=Severity.CRITICAL,
                file_path=js_url,
                mitre_tactic="Credential Access",
                mitre_technique="T1552.001 — Credentials in Files",
                remediation=(
                    "Remove the secret from JavaScript immediately. "
                    "Rotate/revoke the exposed credential. "
                    "Move secrets to server-side environment variables. "
                    "Use server-side API calls that don't expose keys to the browser."
                ),
            ))
    return findings


def _find_endpoints(content: str, js_url: str, base: str) -> list[Finding]:
    """Extract and report internal API endpoints found in JavaScript."""
    all_endpoints = set()
    for pattern in ENDPOINT_PATTERNS:
        for match in re.findall(pattern, content):
            # Clean up the endpoint string
            endpoint = match.strip('"`\'')
            if len(endpoint) > 3 and not endpoint.endswith(".js"):
                all_endpoints.add(endpoint)

    if len(all_endpoints) > 3:
        # Check if any are accessible without auth
        accessible = []
        for ep in list(all_endpoints)[:20]:
            url = base + ep if ep.startswith("/") else ep
            try:
                resp = safe_request("GET", url, headers=HEADERS, timeout=5)
                if resp.status_code == 200:
                    accessible.append(ep)
            except requests.RequestException:
                continue

        if accessible:
            # Build full URL list — stored in metadata for orchestrator to pass to session_intel
            all_urls = [
                base + ep if ep.startswith("/") else ep
                for ep in all_endpoints
            ]
            findings_list = []
            findings_list.append(Finding(
                agent=AgentName.JS,
                title=f"Hidden API Endpoints Discovered in JavaScript",
                description=(
                    f"Found {len(all_endpoints)} API endpoints in JavaScript source. "
                    f"Accessible without auth: {accessible[:5]}. "
                    "These endpoints may not be documented and could lack proper security controls."
                ),
                severity=Severity.HIGH,
                file_path=js_url,
                mitre_tactic="Discovery",
                mitre_technique="T1083 — File and Directory Discovery",
                remediation=(
                    "Audit all discovered endpoints for authentication and authorization. "
                    "Remove unnecessary endpoints. Ensure all endpoints are covered by security testing."
                ),
                metadata={"discovered_endpoints": all_urls[:30]},
            ))
            return findings_list

    return []


def _find_internal_references(content: str, js_url: str) -> list[Finding]:
    """Find internal IP addresses and hostnames leaked in JavaScript."""
    findings = []
    for pattern, label in INTERNAL_PATTERNS:
        matches = re.findall(pattern, content)
        # Filter out localhost:3000 type matches that are the target itself
        real_matches = [m for m in matches if "sentinel" not in m.lower()]
        if real_matches:
            findings.append(Finding(
                agent=AgentName.JS,
                title=f"Internal Infrastructure Exposed in JavaScript: {label}",
                description=(
                    f"JavaScript source reveals internal infrastructure: {real_matches[:3]}. "
                    "Internal addresses in client-side code leak network topology to attackers."
                ),
                severity=Severity.MEDIUM,
                file_path=js_url,
                mitre_tactic="Reconnaissance",
                mitre_technique="T1590 — Gather Victim Network Information",
                remediation=(
                    "Remove internal hostnames and IPs from client-side code. "
                    "Use relative URLs or environment-specific configuration. "
                    "Ensure development/staging URLs don't leak into production builds."
                ),
            ))
    return findings
