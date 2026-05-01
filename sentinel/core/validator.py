"""
sentinel/core/validator.py

THE SAFETY LAYER.
Every single agent action passes through validate_action() before execution.
If it doesn't pass, it doesn't run. Full stop.

This is not optional middleware. This is the contract.
"""

import os
from typing import Optional
from urllib.parse import urlparse
from .models import ScanMode, AgentName, ScanSession, AuditEntry
from .audit import log_audit_entry


# ── What each mode is allowed to do ───────────────────────────────────────────
# These are the ONLY permitted action types per mode.
# Anything not listed here is implicitly blocked.

MODE_PERMISSIONS: dict[ScanMode, set[str]] = {
    ScanMode.PASSIVE: {
        "dns_lookup",
        "whois_lookup",
        "http_headers",
        "whatweb_scan",
        "port_scan_passive",   # nmap -sn (ping scan only, no port probe)
        "config_read",
        "header_analysis",
    },
    ScanMode.CODE: {
        "sast_scan",
        "dependency_scan",
        "secrets_scan",
        "file_read",
        "logic_analysis",   # Claude code reasoning — no network
    },

    ScanMode.PROBE: {
        # Everything PASSIVE can do +
        "dns_lookup", "whois_lookup", "http_headers", "header_analysis",
        "port_scan_passive", "config_read",
        # PROBE-specific — active but safe probing
        "http_probe",           # Send HTTP requests, observe responses
        "spider_passive",       # Crawl links, do not submit forms
        "endpoint_discovery",   # Map API endpoints
        "error_trigger",        # Trigger errors to check for disclosure
        "injection_probe",      # Single-char error probing for injection conditions
        "authenticated_scan",   # Scan with auth context
    },
    ScanMode.ACTIVE: {
        "dns_lookup",
        "whois_lookup",
        "http_headers",
        "whatweb_scan",
        "port_scan_passive",
        "port_scan_active",
        "http_probe",
        "config_read",
        "header_analysis",
        "sast_scan",
        "dependency_scan",
        "secrets_scan",
        "file_read",
        "spider_passive",
        "nuclei_scan",
        "subfinder_scan",
        "logic_analysis",
        "network_topology",
        # PROBE actions also available in ACTIVE
        "http_probe",
        "spider_passive",
        "endpoint_discovery",
        "error_trigger",
        "injection_probe",
        "authenticated_scan",
    },
}

# Actions that are NEVER permitted regardless of mode or session
HARDCODED_BLOCKS: set[str] = {
    "exploit",
    "exploit_cve",
    "execute_payload",
    "upload_file",
    "write_file",
    "delete_file",
    "modify_config",
    "brute_force",
    "sql_injection_active",
    "xss_active",
    "command_injection",
    "reverse_shell",
    "credential_use",
    "credential_store",
    "lateral_movement",
    "privilege_escalation_active",
    "data_exfiltration",
}


# ── Exceptions ────────────────────────────────────────────────────────────────

class ScopeViolation(Exception):
    """Target is not in the approved scope for this session."""

class ModeViolation(Exception):
    """Action is not permitted in the current scan mode."""

class HardStop(Exception):
    """Action is permanently blocked regardless of mode or scope."""

class SessionNotApproved(Exception):
    """Session has not been authorized by the user."""

class ActiveModeNotConfirmed(Exception):
    """ACTIVE mode requires a second explicit confirmation."""


# ── Core Validator ────────────────────────────────────────────────────────────

def validate_action(
    agent:   AgentName,
    action:  str,
    target:  str,
    session: ScanSession,
    reason:  Optional[str] = None,
) -> bool:
    """
    Gate every agent action.
    Returns True if action is permitted.
    Raises a specific exception if not — never silently fails.

    Usage:
        validate_action(AgentName.SAST, "sast_scan", "/app/src", session)
    """

    # 1. Session must be approved by user
    if not session.approved:
        _block_and_log(agent, action, target, session, "Session not approved by user")
        raise SessionNotApproved("User has not authorized this scan session.")

    # 2. ACTIVE mode requires second confirmation
    if session.mode == ScanMode.ACTIVE and not session.active_confirmed:
        _block_and_log(agent, action, target, session, "ACTIVE mode requires second confirmation")
        raise ActiveModeNotConfirmed(
            "ACTIVE mode requires explicit second confirmation before any agents run."
        )

    # 3. Hard blocks — these never pass, ever
    if action.lower() in HARDCODED_BLOCKS:
        _block_and_log(agent, action, target, session, f"HARDCODED BLOCK: {action} is permanently prohibited")
        raise HardStop(
            f"Action '{action}' is permanently prohibited in Sentinel. "
            "Sentinel is a find-only tool. It does not exploit."
        )

    # 4. Target must be in approved scope
    approved_env = os.getenv("APPROVED_TARGETS", "localhost,127.0.0.1")
    approved_list = [t.strip() for t in approved_env.split(",")]
    all_approved = list(set(approved_list + session.approved_targets))

    if not _target_in_scope(target, all_approved):
        _block_and_log(agent, action, target, session, f"Target '{target}' not in approved scope")
        raise ScopeViolation(
            f"Target '{target}' is not in the approved scope for session {session.session_id}. "
            "Add it to APPROVED_TARGETS or the session scope before scanning."
        )

    # 5. Action must be permitted for this mode
    permitted = MODE_PERMISSIONS.get(session.mode, set())
    if action.lower() not in permitted:
        _block_and_log(agent, action, target, session, f"Action '{action}' not permitted in {session.mode} mode")
        raise ModeViolation(
            f"Action '{action}' is not permitted in {session.mode} mode. "
            f"Permitted actions: {sorted(permitted)}"
        )

    # ✅ All checks passed — log and allow
    _allow_and_log(agent, action, target, session, reason)
    return True


# ── Helpers ───────────────────────────────────────────────────────────────────

def _canonicalize_target(target: str) -> str:
    """
    Reduce a target to a canonical netloc for scope comparison.
    Full URL  → netloc  (e.g. "http://localhost:3000/api" → "localhost:3000")
    Bare host → as-is   (e.g. "localhost" → "localhost")
    Always lowercased and stripped.
    """
    target = target.strip().lower()
    parsed = urlparse(target)
    # urlparse only populates netloc when a scheme is present
    return parsed.netloc if parsed.netloc else target


def _target_in_scope(target: str, approved: list[str]) -> bool:
    """
    Check if target matches any approved entry.
    Both sides are canonicalized to netloc before comparison so agents
    that pass a full URL and agents that pass a bare hostname both work.
    Strict exact match only — no subdomain wildcards.
    """
    canonical_target = _canonicalize_target(target)
    for approved_target in approved:
        if canonical_target == _canonicalize_target(approved_target):
            return True
    return False


def _block_and_log(
    agent: AgentName,
    action: str,
    target: str,
    session: ScanSession,
    reason: str,
) -> None:
    entry = AuditEntry(
        session_id=session.session_id,
        agent=agent,
        action=action,
        target=target,
        mode=session.mode,
        allowed=False,
        reason=reason,
    )
    log_audit_entry(entry)


def _block_and_log_chokepoint(action: str, target: str, reason: str) -> None:
    """
    Log a hard stop at HTTP chokepoint (safe_request/probe_with_evidence).
    Called when exploit-shaped payload detected before session context available.
    
    Uses minimal entry without agent/session context.
    """
    entry = AuditEntry(
        session_id="chokepoint_detection",
        agent=AgentName.ORCHESTRATOR,  # sentinel agent name
        action=action,
        target=target,
        mode=ScanMode.PROBE,  # sentinel mode
        allowed=False,
        reason=reason,
    )
    log_audit_entry(entry)


def _allow_and_log(
    agent:   AgentName,
    action:  str,
    target:  str,
    session: ScanSession,
    reason:  Optional[str],
) -> None:
    entry = AuditEntry(
        session_id=session.session_id,
        agent=agent,
        action=action,
        target=target,
        mode=session.mode,
        allowed=True,
        reason=reason or "Passed all validation checks",
    )
    log_audit_entry(entry)


# ── Payload-shape inspector (CRITICAL #2 wire-up) ────────────────────────────

def detect_exploit_action(method: str, url: str, body: Optional[str]) -> Optional[str]:
    """
    Detect exploit-shaped payloads in URL and request body.
    Maps to HARDCODED_BLOCKS action names if pattern matches.

    Returns action name if exploit detected, None if safe probe.

    Patterns detect:
    - SQL injection: quote + logic operators, UNION SELECT, comment/semicolon markers
    - Command injection: $(), backticks, shell metacharacters with pipes/semicolons
    - XSS payloads: <script, event handlers, javascript: protocol
    - File operations: multipart upload, path traversal in upload filename

    Intentionally NOT flagged (legitimate discovery):
    - SQL keywords (SELECT, INSERT, DELETE) without injection operators — normal URL segments
    - POST with password/email fields — normal auth form probing
    - URLs containing .sh, .exe, .bat — legitimate exposure checks
    """
    import re

    payload = (url + " " + (body or "")).lower()

    # SQL injection patterns — all require quote or semicolon injection context
    sql_patterns = [
        r"'\s*(and|or)\s*\d+\s*=",          # ' AND 1=1 / ' OR 1=1
        r"'\s*(and|or|union)\s+",            # ' AND / ' OR / ' UNION
        r"union\s+select",                   # UNION SELECT
        r";\s*(drop|delete|update|insert)",  # ; DROP/DELETE/UPDATE/INSERT
        r"--\s*$",                           # SQL comment end-of-line
        r"/\*.*\*/",                         # SQL comment block
    ]

    for pattern in sql_patterns:
        if re.search(pattern, payload):
            return "sql_injection_active"

    # Command injection patterns
    cmd_patterns = [
        r"\$\(",                                                          # $(...) command substitution
        r"`[^`]*`",                                                       # backtick command substitution
        r";\s*(cat|ls|whoami|id|pwd|curl|wget|nc|bash|sh|powershell)",   # ; cmd
        r"\|\s*(cat|ls|nc|curl|wget|xargs|bash|sh)",                     # | cmd (pipe)
        r"&&\s*(cat|nc|bash|powershell)",                                 # && cmd
        r"\|\s*nc\s+",                                                    # pipe to netcat
        r">\s*/dev/tcp/",                                                 # bash TCP redirection
        r">\s*/dev/udp/",                                                 # bash UDP redirection
    ]

    for pattern in cmd_patterns:
        if re.search(pattern, payload):
            return "command_injection"

    # XSS payload patterns
    xss_patterns = [
        r"<\s*script[^>]*>",                # <script> tag
        r"javascript\s*:",                  # javascript: protocol
        r"on\w+\s*=",                       # onerror=, onclick=, onload=, etc.
        r"<\s*img[^>]*on",                  # <img onerror
        r"<\s*svg[^>]*on",                  # <svg onerror
        r"eval\s*\(",                       # eval(
        r"expression\s*\(",                 # expression(
    ]

    for pattern in xss_patterns:
        if re.search(pattern, payload):
            return "xss_active"

    # File upload patterns — require multipart or path traversal context
    file_patterns = [
        r"(upload|file)\s*=\s*@",           # multipart file upload
        r"filename\s*=\s*\.\./",            # path traversal in upload filename
    ]

    for pattern in file_patterns:
        if re.search(pattern, payload):
            return "upload_file"

    # Path traversal with write/delete operation context
    if any(kw in payload for kw in ["../", "..\\", "%2e%2e", "%252e"]):
        if any(op in payload for op in ["write", "delete", "mkdir", "rmdir", "rm ", "del "]):
            return "write_file"

    # No exploit pattern detected
    return None
