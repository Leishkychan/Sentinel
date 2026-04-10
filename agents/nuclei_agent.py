"""
sentinel/agents/nuclei_agent.py

Nuclei Agent — Template-based vulnerability scanning.
Uses 9,000+ community-maintained Nuclei templates covering:
  - CVEs (known vulnerabilities in specific versions)
  - Misconfigurations
  - Exposed panels (admin, login, management interfaces)
  - Exposed files (.env, .git, backup files)
  - Default credentials
  - DNS misconfigurations
  - Network service vulnerabilities
  - SSL/TLS issues
  - Web application vulnerabilities

SCOPE: ACTIVE mode only. Sends HTTP requests to live target.
ACTIONS: http_probe (scoped to safe template categories)
NEVER: exploits vulnerabilities, uses exploit templates,
       brute forces credentials, performs DoS
"""

import subprocess
import json
from pathlib import Path

from sentinel.core import (
    validate_action, AgentName, ScanSession, Finding, Severity, ScanMode,
    ModeViolation,
)

# Safe template categories for blue team use
# Explicitly excluding: exploits, brute-force, fuzzing, dos
SAFE_NUCLEI_TAGS = [
    "misconfig",
    "exposure",
    "cve",
    "default-login",
    "info",
    "ssl",
    "dns",
    "headers",
    "takeover",
    "tech",
]

# Template categories we explicitly block
BLOCKED_NUCLEI_TAGS = [
    "exploit",
    "brute-force",
    "fuzzing",
    "dos",
    "rce",
]

# Severity mapping from Nuclei to our model
NUCLEI_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
    "unknown":  Severity.INFO,
}


def run_nuclei_agent(session: ScanSession, target_url: str) -> list[Finding]:
    """
    Run Nuclei against a live target using safe template categories only.
    ACTIVE mode required.
    """
    if session.mode != ScanMode.ACTIVE:
        raise ModeViolation("Nuclei agent requires ACTIVE mode — it sends requests to a live target.")

    validate_action(
        agent=AgentName.NUCLEI,
        action="http_probe",
        target=target_url,
        session=session,
        reason="Nuclei template scan on live target",
    )

    print(f"[NUCLEI] Starting template scan on {target_url}")
    print(f"[NUCLEI] Tags: {', '.join(SAFE_NUCLEI_TAGS)}")
    print(f"[NUCLEI] Blocked: {', '.join(BLOCKED_NUCLEI_TAGS)}")

    findings = _run_nuclei(target_url, session)
    print(f"[NUCLEI] {len(findings)} findings")
    return findings


def _run_nuclei(target_url: str, session: ScanSession) -> list[Finding]:
    """Execute Nuclei with safe flags and parse JSONL output."""
    try:
        tags_arg = ",".join(SAFE_NUCLEI_TAGS)
        exclude_tags_arg = ",".join(BLOCKED_NUCLEI_TAGS)

        result = subprocess.run(
            [
                "nuclei",
                "-target",       target_url,
                "-tags",         tags_arg,
                "-etags",        exclude_tags_arg,   # exclude blocked tags
                "-jsonl",                             # JSON Lines output
                "-silent",                            # suppress banner
                "-no-color",
                "-timeout",      "10",               # 10s per request
                "-rate-limit",   "50",               # max 50 req/sec — respectful
                "-bulk-size",    "25",               # concurrent templates
                "-c",            "10",               # concurrent targets
                "-severity",     "low,medium,high,critical,info",
                "-stats",
            ],
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute max
        )

        findings = []
        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                hit = json.loads(line)
                f = _nuclei_hit_to_finding(hit, target_url)
                if f:
                    findings.append(f)
            except json.JSONDecodeError:
                continue

        return findings

    except subprocess.TimeoutExpired:
        print("[NUCLEI] Scan timed out after 600s")
        return []
    except FileNotFoundError:
        print("[NUCLEI] Nuclei not installed.")
        print("[NUCLEI] Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        print("[NUCLEI] Or: brew install nuclei")
        return []


def _nuclei_hit_to_finding(hit: dict, target_url: str) -> Finding | None:
    """Convert a Nuclei JSONL hit to a Finding."""
    try:
        info        = hit.get("info", {})
        template_id = hit.get("template-id", "unknown")
        name        = info.get("name", template_id)
        severity    = NUCLEI_SEVERITY_MAP.get(info.get("severity", "info").lower(), Severity.INFO)
        description = info.get("description", "No description.")
        matched_at  = hit.get("matched-at", target_url)
        matched_url = hit.get("url", matched_at)

        # Extract CVE if present in template tags
        tags = info.get("tags", [])
        cve  = next((t for t in tags if t.upper().startswith("CVE-")), None)

        # Reference links
        refs = info.get("reference", [])
        ref_str = f" Ref: {refs[0]}" if refs else ""

        # MITRE classification from tags
        tactic, technique = _nuclei_tags_to_mitre(tags, name)

        # Remediation from info
        remediation = info.get("remediation") or _default_remediation(name, tags)

        # Extract curl command for evidence (if available) — read only, no exploitation
        curl_cmd = hit.get("curl-command", "")
        evidence = f"\nEvidence URL: {matched_url}"
        if curl_cmd:
            evidence += f"\nVerification: {curl_cmd[:200]}"

        return Finding(
            agent=AgentName.NUCLEI,
            title=f"[Nuclei] {name}",
            description=f"{description}{evidence}",
            severity=severity,
            file_path=matched_url,
            cve_id=cve,
            mitre_tactic=tactic,
            mitre_technique=technique,
            remediation=remediation + ref_str,
            raw_output=json.dumps(hit),
        )
    except Exception as e:
        print(f"[NUCLEI] Failed to parse hit: {e}")
        return None


def _nuclei_tags_to_mitre(tags: list, name: str) -> tuple[str, str]:
    """Map Nuclei template tags to MITRE ATT&CK."""
    tags_lower = [t.lower() for t in tags]
    name_lower = name.lower()

    if "exposure" in tags_lower or "config" in tags_lower:
        return "Discovery", "T1083 — File and Directory Discovery"
    if "default-login" in tags_lower:
        return "Initial Access", "T1078 — Valid Accounts"
    if "cve" in tags_lower:
        return "Initial Access", "T1190 — Exploit Public-Facing Application"
    if "ssl" in tags_lower or "tls" in tags_lower:
        return "Defense Evasion", "T1553 — Subvert Trust Controls"
    if "dns" in tags_lower:
        return "Reconnaissance", "T1590.002 — DNS"
    if "misconfig" in tags_lower:
        return "Initial Access", "T1190 — Exploit Public-Facing Application"
    if "takeover" in tags_lower:
        return "Resource Development", "T1584 — Compromise Infrastructure"
    if "tech" in tags_lower or "info" in tags_lower:
        return "Reconnaissance", "T1592 — Gather Victim Host Information"

    return "Initial Access", "T1190 — Exploit Public-Facing Application"


def _default_remediation(name: str, tags: list) -> str:
    tags_lower = [t.lower() for t in tags]

    if "exposure" in tags_lower:
        return "Remove or restrict access to the exposed resource. Ensure sensitive files are not web-accessible."
    if "default-login" in tags_lower:
        return "Change default credentials immediately. Restrict admin interface access by IP if possible."
    if "ssl" in tags_lower:
        return "Update TLS configuration. Use TLS 1.2+ with strong cipher suites. Obtain valid certificates."
    if "misconfig" in tags_lower:
        return "Review and harden the identified misconfiguration. Consult vendor security hardening guides."
    if "cve" in tags_lower:
        return "Apply the vendor patch for this CVE. Check vendor advisories for specific remediation steps."
    return "Review the identified issue and apply appropriate security controls."
