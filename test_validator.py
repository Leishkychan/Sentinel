"""
tests/test_validator.py

Tests for the validate_action safety layer.
These tests are the most critical in the project.
If these break, the entire safety model breaks.
"""

import pytest
from sentinel.core.models import ScanMode, AgentName, ScanSession
from sentinel.core.validator import (
    validate_action,
    ScopeViolation, ModeViolation, HardStop,
    SessionNotApproved, ActiveModeNotConfirmed,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_session(
    target="localhost",
    mode=ScanMode.CODE,
    approved=True,
    active_confirmed=False,
    extra_targets=None,
) -> ScanSession:
    return ScanSession(
        target=target,
        mode=mode,
        approved=approved,
        active_confirmed=active_confirmed,
        approved_targets=extra_targets or [],
    )


# ── Session Authorization ─────────────────────────────────────────────────────

def test_blocks_unapproved_session():
    session = make_session(approved=False)
    with pytest.raises(SessionNotApproved):
        validate_action(AgentName.SAST, "sast_scan", "localhost", session)


def test_blocks_active_mode_without_second_confirm():
    session = make_session(mode=ScanMode.ACTIVE, approved=True, active_confirmed=False)
    with pytest.raises(ActiveModeNotConfirmed):
        validate_action(AgentName.RECON, "port_scan_active", "localhost", session)


def test_allows_active_mode_with_second_confirm():
    session = make_session(mode=ScanMode.ACTIVE, approved=True, active_confirmed=True)
    result = validate_action(AgentName.RECON, "port_scan_active", "localhost", session)
    assert result is True


# ── Hard Blocks ───────────────────────────────────────────────────────────────

def test_blocks_exploit_always():
    session = make_session(mode=ScanMode.ACTIVE, approved=True, active_confirmed=True)
    with pytest.raises(HardStop):
        validate_action(AgentName.SAST, "exploit", "localhost", session)


def test_blocks_exploit_cve_always():
    session = make_session(mode=ScanMode.ACTIVE, approved=True, active_confirmed=True)
    with pytest.raises(HardStop):
        validate_action(AgentName.SAST, "exploit_cve", "localhost", session)


def test_blocks_reverse_shell_always():
    session = make_session(mode=ScanMode.ACTIVE, approved=True, active_confirmed=True)
    with pytest.raises(HardStop):
        validate_action(AgentName.SAST, "reverse_shell", "localhost", session)


def test_blocks_data_exfiltration_always():
    session = make_session(mode=ScanMode.ACTIVE, approved=True, active_confirmed=True)
    with pytest.raises(HardStop):
        validate_action(AgentName.SAST, "data_exfiltration", "localhost", session)


def test_blocks_brute_force_always():
    session = make_session(mode=ScanMode.ACTIVE, approved=True, active_confirmed=True)
    with pytest.raises(HardStop):
        validate_action(AgentName.SAST, "brute_force", "localhost", session)


# ── Scope Enforcement ─────────────────────────────────────────────────────────

def test_blocks_out_of_scope_target(monkeypatch):
    monkeypatch.setenv("APPROVED_TARGETS", "localhost,127.0.0.1")
    session = make_session(target="evil-target.com")
    with pytest.raises(ScopeViolation):
        validate_action(AgentName.SAST, "sast_scan", "evil-target.com", session)


def test_allows_target_in_env_approved_list(monkeypatch):
    monkeypatch.setenv("APPROVED_TARGETS", "localhost,127.0.0.1,dvwa.local")
    session = make_session(target="dvwa.local")
    result = validate_action(AgentName.SAST, "sast_scan", "dvwa.local", session)
    assert result is True


def test_allows_target_in_session_scope(monkeypatch):
    monkeypatch.setenv("APPROVED_TARGETS", "localhost")
    session = make_session(target="juice-shop.local", extra_targets=["juice-shop.local"])
    result = validate_action(AgentName.SAST, "sast_scan", "juice-shop.local", session)
    assert result is True


# ── Mode Enforcement ──────────────────────────────────────────────────────────

def test_blocks_sast_in_passive_mode():
    session = make_session(mode=ScanMode.PASSIVE)
    with pytest.raises(ModeViolation):
        validate_action(AgentName.SAST, "sast_scan", "localhost", session)


def test_blocks_port_scan_active_in_code_mode():
    session = make_session(mode=ScanMode.CODE)
    with pytest.raises(ModeViolation):
        validate_action(AgentName.RECON, "port_scan_active", "localhost", session)


def test_allows_sast_scan_in_code_mode():
    session = make_session(mode=ScanMode.CODE)
    result = validate_action(AgentName.SAST, "sast_scan", "localhost", session)
    assert result is True


def test_allows_dependency_scan_in_code_mode():
    session = make_session(mode=ScanMode.CODE)
    result = validate_action(AgentName.DEPS, "dependency_scan", "localhost", session)
    assert result is True


def test_allows_dns_lookup_in_passive_mode():
    session = make_session(mode=ScanMode.PASSIVE)
    result = validate_action(AgentName.RECON, "dns_lookup", "localhost", session)
    assert result is True


def test_blocks_http_probe_in_passive_mode():
    session = make_session(mode=ScanMode.PASSIVE)
    with pytest.raises(ModeViolation):
        validate_action(AgentName.RECON, "http_probe", "localhost", session)


def test_allows_all_permitted_actions_in_active_mode():
    session = make_session(mode=ScanMode.ACTIVE, active_confirmed=True)
    allowed_actions = ["sast_scan", "dependency_scan", "dns_lookup", "http_probe", "port_scan_active"]
    for action in allowed_actions:
        result = validate_action(AgentName.SAST, action, "localhost", session)
        assert result is True, f"Expected {action} to be allowed in ACTIVE mode"
