"""
sentinel/agents/sast_agent.py

SAST Agent — Static Application Security Testing.
Runs:
  - Bandit     → Python-specific security issues
  - Semgrep    → Multi-language (Python, JS, Java, Go, PHP, Ruby, C/C++)
  - TruffleHog → Hardcoded secrets across all file types

SCOPE: CODE and ACTIVE modes.
ACTIONS: sast_scan, secrets_scan, file_read
NEVER: executes code, touches network, writes files
"""

import subprocess
import json
import os
from pathlib import Path

from sentinel.core import (
    validate_action, AgentName, ScanSession, Finding, Severity, ScanMode,
    ModeViolation,
)

# Semgrep rulesets to run — ordered by signal quality
SEMGREP_RULESETS = [
    "p/default",           # Semgrep's curated high-confidence rules
    "p/security-audit",    # Broader security audit rules
    "p/owasp-top-ten",     # OWASP Top 10 mapped rules
    "p/secrets",           # Secret detection
    "p/sql-injection",     # SQLi specific
    "p/xss",               # XSS specific
    "p/command-injection", # Command injection
]


def run_sast_agent(session: ScanSession, source_path: str) -> list[Finding]:
    """Run full SAST pipeline: Bandit + Semgrep + TruffleHog."""
    validate_action(
        agent=AgentName.SAST,
        action="sast_scan",
        target=source_path,
        session=session,
        reason=f"SAST scan on {source_path}",
    )

    if session.mode == ScanMode.PASSIVE:
        raise ModeViolation("SAST agent cannot run in PASSIVE mode.")

    path = Path(source_path)
    if not path.exists():
        print(f"[SAST] Source path does not exist: {source_path}")
        return []

    findings: list[Finding] = []

    findings.extend(_run_bandit(source_path, session))
    findings.extend(_run_semgrep(source_path, session))
    findings.extend(_run_secrets_scan(source_path, session))

    # Deduplicate: same file + same line + same title
    findings = _deduplicate(findings)

    print(f"[SAST] {len(findings)} findings after dedup from {source_path}")
    return findings


# ── Bandit (Python) ───────────────────────────────────────────────────────────

def _run_bandit(source_path: str, session: ScanSession) -> list[Finding]:
    try:
        result = subprocess.run(
            ["bandit", "-r", "-f", "json", "-ll", source_path],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode not in (0, 1):
            return []
        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        return [_bandit_to_finding(r) for r in data.get("results", [])]

    except subprocess.TimeoutExpired:
        print("[SAST/Bandit] Timed out")
        return []
    except FileNotFoundError:
        print("[SAST/Bandit] Not installed: pip install bandit")
        return []
    except json.JSONDecodeError:
        return []


def _bandit_to_finding(r: dict) -> Finding:
    sev_map = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
    cwe = r.get("issue_cwe", {})
    cwe_id = f"CWE-{cwe.get('id')}" if isinstance(cwe, dict) and cwe.get("id") else None
    return Finding(
        agent=AgentName.SAST,
        title=f"[Bandit] {r.get('test_name', 'Unknown')}",
        description=r.get("issue_text", ""),
        severity=sev_map.get(r.get("issue_severity", "LOW"), Severity.LOW),
        file_path=r.get("filename"),
        line_number=r.get("line_number"),
        cve_id=cwe_id,
        mitre_tactic=_bandit_mitre(r.get("test_id", "")),
        remediation=f"Fix {r.get('test_name')}. See CWE-{cwe.get('id', '?')} and Bandit docs.",
        raw_output=json.dumps(r),
    )


# ── Semgrep (Multi-language) ──────────────────────────────────────────────────

def _run_semgrep(source_path: str, session: ScanSession) -> list[Finding]:
    """
    Run Semgrep with multiple rulesets.
    Falls back to a single combined run if individual sets fail.
    """
    try:
        # Run all rulesets in one pass for efficiency
        rulesets = " ".join(f"--config {r}" for r in SEMGREP_RULESETS)
        result = subprocess.run(
            [
                "semgrep",
                "--json",
                "--quiet",
                "--no-git-ignore",
                "--timeout", "60",
                "--max-memory", "512",
                "--config", "p/default",
                "--config", "p/security-audit",
                "--config", "p/owasp-top-ten",
                "--config", "p/secrets",
                "--config", "p/sql-injection",
                "--config", "p/xss",
                "--config", "p/command-injection",
                source_path,
            ],
            capture_output=True, text=True, timeout=300,
        )

        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        findings = []
        for r in data.get("results", []):
            f = _semgrep_to_finding(r)
            if f:
                findings.append(f)

        print(f"[SAST/Semgrep] {len(findings)} findings")
        return findings

    except subprocess.TimeoutExpired:
        print("[SAST/Semgrep] Timed out (300s)")
        return []
    except FileNotFoundError:
        print("[SAST/Semgrep] Not installed: pip install semgrep")
        return []
    except json.JSONDecodeError as e:
        print(f"[SAST/Semgrep] JSON parse error: {e}")
        return []


def _semgrep_to_finding(r: dict) -> Finding | None:
    try:
        meta     = r.get("extra", {}).get("metadata", {})
        severity_raw = r.get("extra", {}).get("severity", "WARNING").upper()
        sev_map  = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
        severity = sev_map.get(severity_raw, Severity.LOW)

        # Escalate to CRITICAL if CWE or OWASP top-level
        cwe_list = meta.get("cwe", [])
        critical_cwes = {"CWE-89", "CWE-78", "CWE-94", "CWE-502", "CWE-798"}
        if any(c in str(cwe_list) for c in critical_cwes):
            severity = Severity.CRITICAL

        cve = meta.get("cve", None)
        owasp = meta.get("owasp", [])
        mitre = meta.get("attack-technique", None)

        references = meta.get("references", [])
        ref_str = f" See: {references[0]}" if references else ""

        return Finding(
            agent=AgentName.SAST,
            title=f"[Semgrep] {r.get('check_id', 'Unknown Rule').split('.')[-1]}",
            description=r.get("extra", {}).get("message", "No description"),
            severity=severity,
            file_path=r.get("path"),
            line_number=r.get("start", {}).get("line"),
            cve_id=cve or (cwe_list[0] if cwe_list else None),
            mitre_tactic=_owasp_to_tactic(owasp),
            mitre_technique=mitre,
            remediation=(
                f"{r.get('extra', {}).get('fix', 'Review the flagged code and apply secure coding practices.')}"
                f"{ref_str}"
            ),
            raw_output=json.dumps(r),
        )
    except Exception:
        return None


# ── TruffleHog (Secrets) ──────────────────────────────────────────────────────

def _run_secrets_scan(source_path: str, session: ScanSession) -> list[Finding]:
    validate_action(AgentName.SAST, "secrets_scan", source_path, session)
    try:
        result = subprocess.run(
            ["trufflehog", "filesystem", source_path, "--json", "--no-update"],
            capture_output=True, text=True, timeout=120,
        )
        findings = []
        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                hit = json.loads(line)
                findings.append(_trufflehog_to_finding(hit))
            except json.JSONDecodeError:
                continue
        return findings
    except subprocess.TimeoutExpired:
        print("[SAST/TruffleHog] Timed out")
        return []
    except FileNotFoundError:
        print("[SAST/TruffleHog] Not installed: pip install truffleHog3")
        return []


def _trufflehog_to_finding(hit: dict) -> Finding:
    detector = hit.get("DetectorName", "Unknown Secret Type")
    file_path = hit.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file")
    return Finding(
        agent=AgentName.SAST,
        title=f"[TruffleHog] Hardcoded Secret: {detector}",
        description=(
            f"A {detector} secret was detected in source code. "
            "Hardcoded secrets can be extracted from source, history, or binaries."
        ),
        severity=Severity.CRITICAL,
        file_path=file_path,
        mitre_tactic="Credential Access",
        mitre_technique="T1552.001 — Credentials in Files",
        remediation=(
            "1. Rotate the credential immediately — assume it is compromised. "
            "2. Move to environment variables or Azure Key Vault. "
            "3. Audit git history — credential must be rotated even after removal. "
            "4. Add pre-commit hooks (e.g. gitleaks) to block future commits."
        ),
        raw_output=json.dumps(hit),
    )


# ── Deduplication ─────────────────────────────────────────────────────────────

def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings by (file, line, title) key."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.file_path, f.line_number, f.title[:50])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ── Mapping helpers ───────────────────────────────────────────────────────────

def _bandit_mitre(test_id: str) -> str:
    tactic_map = {
        "B105": "Credential Access", "B106": "Credential Access", "B107": "Credential Access",
        "B201": "Initial Access", "B301": "Execution", "B307": "Execution",
        "B501": "Defense Evasion", "B602": "Execution", "B603": "Execution",
        "B608": "Initial Access",
    }
    return tactic_map.get(test_id, "Unknown")


def _owasp_to_tactic(owasp: list) -> str:
    owasp_str = str(owasp).lower()
    if "a01" in owasp_str or "access control" in owasp_str:
        return "Privilege Escalation"
    if "a02" in owasp_str or "cryptograph" in owasp_str:
        return "Credential Access"
    if "a03" in owasp_str or "injection" in owasp_str:
        return "Initial Access"
    if "a07" in owasp_str or "auth" in owasp_str:
        return "Credential Access"
    if "a08" in owasp_str or "deserializ" in owasp_str:
        return "Execution"
    if "a09" in owasp_str or "logging" in owasp_str:
        return "Defense Evasion"
    return "Initial Access"
