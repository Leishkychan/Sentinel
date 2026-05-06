"""
sentinel/agents/disclosure_agent.py

Information Disclosure Agent.
Finds:
  - Sensitive file exposure (.env, .git, backups, configs)
  - Error messages that leak stack traces
  - Debug endpoints left enabled
  - Version information disclosure
  - Directory listing enabled
  - Server-side path disclosure in errors
  - Database error messages
  - Framework/technology fingerprinting

SCOPE: PROBE and ACTIVE modes.
ACTIONS: http_probe
NEVER: exploits errors, injects payloads, modifies data
"""

import re
import requests  # for RequestException type only
from sentinel.core.evidence import safe_request, classify_failure

from sentinel.core import (
    validate_action, AgentName, ScanSession, Finding, Severity,
)

HEADERS = {"User-Agent": "Sentinel-SecurityScanner/1.0"}
TIMEOUT = 10

# Sensitive files that should never be publicly accessible
SENSITIVE_FILES = [
    # Environment and config files
    ("/.env",                  "Environment File",          Severity.CRITICAL),
    ("/.env.local",            "Local Environment File",    Severity.CRITICAL),
    ("/.env.production",       "Production Environment",    Severity.CRITICAL),
    ("/.env.backup",           "Environment Backup",        Severity.CRITICAL),
    ("/config.json",           "Configuration File",        Severity.HIGH),
    ("/config.yml",            "Configuration File",        Severity.HIGH),
    ("/config.yaml",           "Configuration File",        Severity.HIGH),
    ("/settings.json",         "Settings File",             Severity.HIGH),
    ("/application.yml",       "Application Config",        Severity.HIGH),

    # Git/VCS exposure
    ("/.git/config",           "Git Config",                Severity.CRITICAL),
    ("/.git/HEAD",             "Git Repository",            Severity.HIGH),
    ("/.gitignore",            "Git Ignore",                Severity.LOW),
    ("/.svn/entries",          "SVN Repository",            Severity.HIGH),

    # Backup files
    ("/backup.zip",            "Backup Archive",            Severity.CRITICAL),
    ("/backup.tar.gz",         "Backup Archive",            Severity.CRITICAL),
    ("/dump.sql",              "Database Dump",             Severity.CRITICAL),
    ("/db.sql",                "Database Dump",             Severity.CRITICAL),
    ("/database.sql",          "Database Dump",             Severity.CRITICAL),
    ("/backup.sql",            "Database Backup",           Severity.CRITICAL),

    # Log files
    ("/logs/app.log",          "Application Log",           Severity.HIGH),
    ("/log/app.log",           "Application Log",           Severity.HIGH),
    ("/app.log",               "Application Log",           Severity.HIGH),
    ("/error.log",             "Error Log",                 Severity.HIGH),
    ("/access.log",            "Access Log",                Severity.MEDIUM),
    ("/debug.log",             "Debug Log",                 Severity.HIGH),

    # Package/dependency files
    ("/package.json",          "NPM Package File",          Severity.LOW),
    ("/composer.json",         "PHP Composer File",         Severity.LOW),
    ("/requirements.txt",      "Python Requirements",       Severity.LOW),
    ("/Gemfile",               "Ruby Gemfile",              Severity.LOW),
    ("/yarn.lock",             "Yarn Lock File",            Severity.LOW),

    # FTP/file directories
    ("/ftp",                   "FTP Directory",             Severity.HIGH),
    ("/ftp/",                  "FTP Directory",             Severity.HIGH),
    ("/uploads",               "Uploads Directory",         Severity.MEDIUM),
    ("/files",                 "Files Directory",           Severity.MEDIUM),

    # Debug/test files
    ("/phpinfo.php",           "PHP Info Page",             Severity.HIGH),
    ("/info.php",              "PHP Info Page",             Severity.HIGH),
    ("/test.php",              "Test Page",                 Severity.MEDIUM),
    ("/debug",                 "Debug Endpoint",            Severity.HIGH),

    # Kubernetes/cloud
    ("/actuator",              "Spring Actuator",           Severity.HIGH),
    ("/actuator/env",          "Spring Actuator Env",       Severity.CRITICAL),
    ("/actuator/dump",         "Spring Actuator Dump",      Severity.HIGH),
    ("/.well-known/security.txt", "Security.txt",           Severity.INFO),
    ("/robots.txt",            "Robots.txt",                Severity.INFO),
    ("/sitemap.xml",           "Sitemap",                   Severity.INFO),
]

# Error trigger paths — these cause errors that may leak info
ERROR_TRIGGER_PATHS = [
    "/api/nonexistent_endpoint_sentinel_test",
    "/api/users/99999999",
    "/api/basket/99999999",
    "/'",
    "/api/%27",
]

# Stack trace indicators
STACK_TRACE_PATTERNS = [
    r"at\s+\w+\s*\(",           # Node.js stack traces
    r"Traceback \(most recent",  # Python stack traces
    r"java\.lang\.",             # Java stack traces
    r"System\.Web\.",            # .NET stack traces
    r"#\d+\s+0x[0-9a-f]+",      # C/C++ stack traces
    r"Error: Cannot ",           # Node.js errors
    r"SyntaxError:",             # JS syntax errors
    r"SequelizeError",           # Sequelize ORM errors
    r"MongooseError",            # Mongoose errors
    r"SQLITE_",                  # SQLite errors
    r"ORA-\d+",                  # Oracle errors
    r"mysql_",                   # MySQL errors
    r"PG::",                     # PostgreSQL errors
]

# Version disclosure patterns in error responses
VERSION_PATTERNS = [
    (r"Express\s+([\d.]+)",        "Express.js version"),
    (r"Node\.js\s+([\d.]+)",       "Node.js version"),
    (r"nginx/([\d.]+)",            "nginx version"),
    (r"Apache/([\d.]+)",           "Apache version"),
    (r"PHP/([\d.]+)",              "PHP version"),
    (r"ASP\.NET\s+([\d.]+)",       "ASP.NET version"),
    (r"Spring\s+([\d.]+)",         "Spring version"),
    (r"Django/([\d.]+)",           "Django version"),
    (r"Rails\s+([\d.]+)",          "Rails version"),
]

_AGENT = "disclosure_agent"


def _record_failure(session: ScanSession, url: str,
                    failure_class: str, failure_reason: str = "") -> None:
    """
    Route request failure to SessionIntelligence.record_request_failure().

    After 7b: call sites pass resp.failure_class and resp.failure_reason
    directly from FailedResponse — classified at the catch site in safe_request
    from the real exception, not a synthetic string.

    failure_class and failure_reason are also accepted as plain strings for
    the requests.RequestException catch paths that still run outside safe_request.
    """
    intel = getattr(session, '_session_intel', None)
    if intel is not None:
        intel.record_request_failure(_AGENT, url, failure_class, failure_reason)


def run_disclosure_agent(session: ScanSession, target_url: str) -> list[Finding]:
    """Run information disclosure analysis."""
    validate_action(AgentName.DISCLOSURE, "http_probe", target_url, session)

    base = target_url.rstrip("/")
    findings = []

    print(f"[DISCLOSURE] Scanning for sensitive file exposure and info disclosure on {base}")

    findings.extend(_check_sensitive_files(base, session))
    findings.extend(_check_monitoring_endpoints(base, session))
    findings.extend(_check_error_disclosure(base, session))
    findings.extend(_check_directory_listing(base, session))
    findings.extend(_check_debug_endpoints(base, session))

    print(f"[DISCLOSURE] {len(findings)} disclosure findings")
    return findings


# ── Sensitive File Exposure ───────────────────────────────────────────────────

def _check_sensitive_files(base: str, session: ScanSession) -> list[Finding]:
    """Check for publicly accessible sensitive files."""
    findings = []

    for path, label, severity in SENSITIVE_FILES:
        url = base + path
        try:
            resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT,
                                allow_redirects=False)

            # 7b: FailedResponse is falsy (status_code == 0, ok == False)
            # safe_request never returns None after 7b; this guard is a safety net
            if resp is None or resp.status_code == 0:
                _record_failure(session, url,
                                getattr(resp, "failure_class", "other") if resp is not None else "other",
                                getattr(resp, "failure_reason", "") if resp is not None else "None returned by safe_request")
                continue

            if resp.status_code == 200 and len(resp.content) > 0:
                content_preview = resp.text[:200].strip()

                if _is_real_file_response(resp, path):
                    findings.append(Finding(
                        agent=AgentName.DISCLOSURE,
                        title=f"Sensitive File Exposed: {path}",
                        description=(
                            f"{label} is publicly accessible at {url}. "
                            f"File size: {len(resp.content)} bytes. "
                            f"Preview: {content_preview[:100]}"
                        ),
                        severity=severity,
                        file_path=url,
                        mitre_tactic="Collection",
                        mitre_technique="T1005 — Data from Local System",
                        remediation=(
                            f"Remove {path} from the web root immediately. "
                            "Configure web server to deny access to sensitive file types. "
                            "Add these patterns to .htaccess or nginx config: "
                            f"deny access to "
                            f"{path.split('.')[-1] if '.' in path else 'this directory'} files."
                        ),
                    ))

        except requests.RequestException as e:
            _record_failure(session, url, classify_failure(str(e)), str(e))
            continue

    return findings


# ── Monitoring Endpoint Checks ────────────────────────────────────────────────

# Telemetry indicators — presence escalates to MEDIUM
_TELEMETRY_INDICATORS = [
    "diskspace", "heap", "memoryusage", "goroutine",
    "process_", "jvm_", '"db"', '"db":',
]

# Liveness body patterns — simple health probes, not disclosure
_LIVENESS_BODIES = {"ok", "healthy", "up", '{"status":"ok"}', '{"status":"up"}',
                    '{"status":"UP"}', '{"status":"healthy"}'}


def _check_monitoring_endpoints(base: str, session: ScanSession) -> list[Finding]:
    """
    Check /health, /metrics, /status with context-aware classification.
    Simple liveness probes → no finding.
    Accessible but benign → INFO.
    Contains internal telemetry → MEDIUM.
    """
    findings = []
    monitoring = [
        ("/health",  "Health Check Endpoint"),
        ("/metrics", "Metrics Endpoint"),
        ("/status",  "Status Page"),
    ]

    for path, label in monitoring:
        url = base + path
        try:
            resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT,
                                allow_redirects=False)

            if resp is None or resp.status_code == 0:
                _record_failure(session, url,
                                getattr(resp, "failure_class", "other") if resp is not None else "other",
                                getattr(resp, "failure_reason", "") if resp is not None else "None returned by safe_request")
                continue

            if resp.status_code != 200 or len(resp.content) == 0:
                continue

            body = resp.text.strip()
            body_lower = body.lower()

            # Simple liveness probe — not a disclosure issue
            if body_lower in {v.lower() for v in _LIVENESS_BODIES}:
                continue

            # Telemetry escalation check
            has_telemetry = any(ind in body_lower for ind in _TELEMETRY_INDICATORS)
            severity = Severity.MEDIUM if has_telemetry else Severity.INFO
            detail = (
                "Response contains internal telemetry (memory, process, or DB metrics) "
                "that could aid reconnaissance."
                if has_telemetry else
                "Endpoint is accessible but response appears benign."
            )

            findings.append(Finding(
                agent=AgentName.DISCLOSURE,
                title=f"Monitoring Endpoint Accessible: {path}",
                description=(
                    f"{label} is publicly accessible at {url}. {detail} "
                    f"Preview: {body[:150]}"
                ),
                severity=severity,
                file_path=url,
                mitre_tactic="Reconnaissance",
                mitre_technique="T1082 — System Information Discovery",
                remediation=(
                    f"Restrict {path} to internal networks or authenticated requests only. "
                    "Do not expose monitoring endpoints on public-facing interfaces."
                ),
            ))

        except Exception:
            continue

    return findings


# ── Error Message Analysis ────────────────────────────────────────────────────

def _check_error_disclosure(base: str, session: ScanSession) -> list[Finding]:
    """Trigger errors and check if stack traces or sensitive info is returned."""
    findings = []
    checked = set()

    for path in ERROR_TRIGGER_PATHS:
        url = base + path
        try:
            resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT,
                                allow_redirects=False)

            # 7b: FailedResponse is falsy (status_code == 0, ok == False)
            # safe_request never returns None after 7b; this guard is a safety net
            if resp is None or resp.status_code == 0:
                _record_failure(session, url,
                                getattr(resp, "failure_class", "other") if resp is not None else "other",
                                getattr(resp, "failure_reason", "") if resp is not None else "None returned by safe_request")
                continue

            if resp.status_code not in (400, 404, 500, 503):
                continue

            content = resp.text

            for pattern in STACK_TRACE_PATTERNS:
                if re.search(pattern, content) and "stack_trace" not in checked:
                    checked.add("stack_trace")
                    findings.append(Finding(
                        agent=AgentName.DISCLOSURE,
                        title="Stack Trace Leaked in Error Response",
                        description=(
                            f"Error response at {url} contains a stack trace. "
                            "Stack traces reveal internal file paths, function names, "
                            "framework versions, and application structure. "
                            f"Triggered by: {path}"
                        ),
                        severity=Severity.HIGH,
                        file_path=url,
                        mitre_tactic="Reconnaissance",
                        mitre_technique="T1592 — Gather Victim Host Information",
                        remediation=(
                            "Configure error handling to show generic error messages to users. "
                            "Log full errors server-side but never expose to clients. "
                            "Set NODE_ENV=production, DEBUG=false, or equivalent for your framework."
                        ),
                    ))
                    break

            for pattern, label in VERSION_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match and label not in checked:
                    checked.add(label)
                    findings.append(Finding(
                        agent=AgentName.DISCLOSURE,
                        title=f"Version Disclosure in Error: {label}",
                        description=(
                            f"Error response reveals {label}: {match.group(0)}. "
                            "Version information helps attackers identify specific CVEs."
                        ),
                        severity=Severity.MEDIUM,
                        file_path=url,
                        mitre_tactic="Reconnaissance",
                        mitre_technique="T1592 — Gather Victim Host Information",
                        remediation=(
                            "Configure framework to suppress version information in error responses. "
                            "Remove Server header or set to generic value. "
                            "Keep all frameworks patched to prevent version-specific exploits."
                        ),
                    ))

        except requests.RequestException as e:
            _record_failure(session, url, classify_failure(str(e)), str(e))
            continue

    return findings


# ── Directory Listing ─────────────────────────────────────────────────────────

def _check_directory_listing(base: str, session: ScanSession) -> list[Finding]:
    """Check if directory listing is enabled."""
    findings = []

    dirs_to_check = ["/", "/ftp", "/uploads", "/files", "/static", "/assets", "/public"]

    for path in dirs_to_check:
        url = base + path
        try:
            resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT,
                                allow_redirects=False)

            # 7b: FailedResponse is falsy (status_code == 0, ok == False)
            # safe_request never returns None after 7b; this guard is a safety net
            if resp is None or resp.status_code == 0:
                _record_failure(session, url,
                                getattr(resp, "failure_class", "other") if resp is not None else "other",
                                getattr(resp, "failure_reason", "") if resp is not None else "None returned by safe_request")
                continue

            if resp.status_code != 200:
                continue

            content = resp.text.lower()
            if (("index of" in content or "directory listing" in content or
                 "<title>index of" in content) and
                    ("<a href=" in content)):
                findings.append(Finding(
                    agent=AgentName.DISCLOSURE,
                    title=f"Directory Listing Enabled: {path}",
                    description=(
                        f"Directory listing is enabled at {url}. "
                        "This exposes all files in the directory to anyone. "
                        "Attackers can browse for sensitive files, backups, and configuration."
                    ),
                    severity=Severity.HIGH,
                    file_path=url,
                    mitre_tactic="Collection",
                    mitre_technique="T1005 — Data from Local System",
                    remediation=(
                        "Disable directory listing in your web server config. "
                        "nginx: remove 'autoindex on'. "
                        "Apache: add 'Options -Indexes'. "
                        "Ensure all directories have an index file."
                    ),
                ))

        except requests.RequestException as e:
            _record_failure(session, url, classify_failure(str(e)), str(e))
            continue

    return findings


# ── Debug Endpoints ───────────────────────────────────────────────────────────

def _check_debug_endpoints(base: str, session: ScanSession) -> list[Finding]:
    """Check for debug/development endpoints left enabled in production."""
    findings = []

    debug_paths = [
        ("/debug",              "Debug Endpoint"),
        ("/console",            "Console Interface"),
        ("/actuator/env",       "Spring Actuator Environment"),
        ("/actuator/mappings",  "Spring Actuator Mappings"),
        ("/actuator/beans",     "Spring Actuator Beans"),
        ("/metrics",            "Metrics Endpoint"),
        ("/trace",              "Request Trace"),
        ("/heapdump",           "Heap Dump"),
        ("/threaddump",         "Thread Dump"),
        ("/jolokia",            "Jolokia JMX"),
        ("/manage",             "Management Interface"),
        ("/monitor",            "Monitor Interface"),
        ("/_profiler",          "Symfony Profiler"),
        ("/__debug__/",         "Django Debug"),
        ("/webpack-dev-server", "Webpack Dev Server"),
    ]

    for path, label in debug_paths:
        url = base + path
        try:
            resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT,
                                allow_redirects=False)

            # 7b: FailedResponse is falsy (status_code == 0, ok == False)
            # safe_request never returns None after 7b; this guard is a safety net
            if resp is None or resp.status_code == 0:
                _record_failure(session, url,
                                getattr(resp, "failure_class", "other") if resp is not None else "other",
                                getattr(resp, "failure_reason", "") if resp is not None else "None returned by safe_request")
                continue

            if resp.status_code == 200 and len(resp.content) > 50:
                # Skip SPA fallback responses — same check used for sensitive files
                if not _is_real_file_response(resp, path):
                    continue
                findings.append(Finding(
                    agent=AgentName.DISCLOSURE,
                    title=f"Debug/Admin Endpoint Active in Production: {label}",
                    description=(
                        f"{label} endpoint accessible at {url} (HTTP {resp.status_code}). "
                        "Development/debug endpoints in production expose internal application "
                        "state, configuration, environment variables, and heap data."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=url,
                    mitre_tactic="Discovery",
                    mitre_technique="T1082 — System Information Discovery",
                    remediation=(
                        f"Disable {label} in production configuration. "
                        "Use environment variables to enable debug features only in development. "
                        "If monitoring is needed, restrict access to internal IPs or VPN only."
                    ),
                ))

        except requests.RequestException as e:
            _record_failure(session, url, classify_failure(str(e)), str(e))
            continue

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_real_file_response(resp: requests.Response, path: str) -> bool:
    """
    Verify the response is actually the requested file, not a generic
    200 response that the app returns for all paths (SPA behavior).

    NOTE: This helper types against requests.Response directly.
    When 7b introduces a structured response wrapper, this will need migration.
    """
    content = resp.text.lower()

    if "<html" in content and "<!doctype" in content[:200].lower():
        if "phpinfo" in content or "php version" in content:
            return True
        return False

    content_type = resp.headers.get("Content-Type", "")

    if path.endswith(".json") and "json" not in content_type:
        return False
    if path.endswith((".yml", ".yaml")) and "yaml" not in content_type and "text" not in content_type:
        return False

    return len(resp.content) > 10
