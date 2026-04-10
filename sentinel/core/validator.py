"""
sentinel/core/validator.py

THE SAFETY LAYER.
Every single agent action passes through validate_action() before execution.
If it doesn't pass, it doesn't run. Full stop.

This is not optional middleware. This is the contract.
"""

import os
from typing import Optional
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

def _target_in_scope(target: str, approved: list[str]) -> bool:
    """
    Check if target matches any approved entry.
    Supports exact match and subdomain matching.
    """
    target = target.strip().lower()
    for approved_target in approved:
        approved_target = approved_target.strip().lower()
        if target == approved_target:
            return True
        # Allow subdomain match: dvwa.local matches *.local? No — exact only.
        # Subdomain matching is a footgun. Keep it strict.
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
