"""
sentinel/agents/logic_agent.py

Logic Analysis Agent — The thing no static tool finds.
Uses Claude to reason about code INTENT, not just syntax.

Finds:
  - Auth bypass vulnerabilities (can you skip the auth check?)
  - IDOR (Insecure Direct Object References)
  - Broken access control (can role A access role B's data?)
  - Business logic flaws (can you order -1 items? transfer to yourself?)
  - Race condition windows (TOCTOU patterns)
  - Mass assignment vulnerabilities
  - JWT/session validation flaws
  - API endpoint authorization gaps

This is what separates Sentinel from pattern-matching tools.
Claude reads the actual code and reasons about what an attacker could do.

SCOPE: CODE and ACTIVE modes.
ACTIONS: file_read
NEVER: exploits, probes, modifies anything
"""

import os
import json
from pathlib import Path
from typing import Optional
from anthropic import Anthropic

from sentinel.core import (
    validate_action, AgentName, ScanSession, Finding, Severity, ScanMode,
)

_client = None

def _get_client():
    """Lazy Anthropic client — not created until first use."""
    global _client
    if _client is None:
        _client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    return _client
MODEL  = os.getenv("ORCHESTRATOR_MODEL", "claude-sonnet-4-20250514")

# File extensions to analyze for logic flaws
ANALYZABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".java", ".go", ".rb", ".php",
    ".cs", ".cpp", ".c", ".swift", ".kt"
}

# Keywords that indicate auth/access control code — prioritize these files
AUTH_KEYWORDS = [
    "auth", "login", "session", "token", "jwt", "permission",
    "role", "admin", "user", "access", "middleware", "decorator",
    "require", "guard", "policy", "acl", "rbac", "oauth"
]

MAX_FILE_SIZE_KB = 100  # Skip files larger than this


LOGIC_ANALYSIS_PROMPT = """You are a senior application security engineer performing a security code review.
Your job is to find logical security vulnerabilities that static analysis tools miss.

Focus on:
1. AUTH BYPASS — Can authentication be circumvented? Are there paths that skip auth checks?
2. IDOR — Can a user access/modify another user's resources by changing an ID?
3. BROKEN ACCESS CONTROL — Can a low-privilege user access high-privilege functionality?
4. BUSINESS LOGIC FLAWS — Can the application flow be abused? (negative values, skipped steps, etc.)
5. RACE CONDITIONS (TOCTOU) — Is there a gap between checking and using a resource?
6. MASS ASSIGNMENT — Can users set fields they shouldn't (isAdmin=true, etc.)?
7. JWT/SESSION FLAWS — Weak validation, algorithm confusion, missing expiry checks?
8. MISSING AUTHORIZATION — Endpoints that authenticate but don't authorize?

For each issue found, output a JSON array:
[
  {
    "type": "AUTH_BYPASS|IDOR|BROKEN_ACCESS_CONTROL|BUSINESS_LOGIC|RACE_CONDITION|MASS_ASSIGNMENT|SESSION_FLAW|MISSING_AUTHZ",
    "title": "Short descriptive title",
    "description": "What the flaw is and why it matters",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "location": "function_name or line description",
    "attack_scenario": "How an attacker would abuse this (defensive framing only)",
    "remediation": "Specific code fix or architectural change needed"
  }
]

Critical rules:
- Only report REAL logical flaws, not theoretical edge cases
- Attack scenario must be defensive framing: "An attacker could..." not instructions
- Return [] if no logical flaws found
- Return ONLY the JSON array
"""


def run_logic_agent(session: ScanSession, source_path: str) -> list[Finding]:
    """
    Run logic analysis on source code.
    Prioritizes auth/access control files, then analyzes all others.
    """
    if session.mode == ScanMode.PASSIVE:
        return []

    validate_action(AgentName.LOGIC, "file_read", source_path, session)

    path = Path(source_path)
    if not path.exists():
        return []

    # Find and prioritize files
    files = _find_analyzable_files(path)
    if not files:
        print(f"[LOGIC] No analyzable files found in {source_path}")
        return []

    print(f"[LOGIC] Analyzing {len(files)} files for logic flaws...")
    all_findings = []

    for filepath in files[:20]:  # Cap at 20 files for context/cost
        findings = _analyze_file(filepath, session)
        all_findings.extend(findings)

    print(f"[LOGIC] {len(all_findings)} logic flaws found")
    return all_findings


def _find_analyzable_files(base: Path) -> list[Path]:
    """Find all code files, sorted by auth relevance."""
    all_files = []
    auth_files = []

    for ext in ANALYZABLE_EXTENSIONS:
        for f in base.rglob(f"*{ext}"):
            if ".git" in str(f) or "node_modules" in str(f) or "venv" in str(f):
                continue
            size_kb = f.stat().st_size / 1024
            if size_kb > MAX_FILE_SIZE_KB:
                continue

            # Check if file has auth-related keywords
            name_lower = f.name.lower()
            if any(kw in name_lower for kw in AUTH_KEYWORDS):
                auth_files.append(f)
            else:
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                    if any(kw in content.lower() for kw in AUTH_KEYWORDS[:5]):
                        auth_files.append(f)
                    else:
                        all_files.append(f)
                except Exception:
                    all_files.append(f)

    # Auth files first (most likely to have logic flaws)
    return auth_files + all_files


def _analyze_file(filepath: Path, session: ScanSession) -> list[Finding]:
    """Send a single file to Claude for logic analysis."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        if not content.strip() or len(content) < 50:
            return []

        response = _get_client().messages.create(
            model=MODEL,
            max_tokens=2000,
            system=LOGIC_ANALYSIS_PROMPT,
            messages=[{
                "role": "user",
                "content": f"File: {filepath.name}\nLanguage: {filepath.suffix}\n\n```\n{content[:6000]}\n```"
            }],
        )

        raw = response.content[0].text.strip()
        return _parse_logic_findings(raw, str(filepath))

    except Exception as e:
        print(f"[LOGIC] Failed to analyze {filepath}: {e}")
        return []


def _parse_logic_findings(raw: str, filepath: str) -> list[Finding]:
    """Parse Claude's logic analysis response into Finding objects."""
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    try:
        data = json.loads(raw)
        if not isinstance(data, list) or not data:
            return []

        sev_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH":     Severity.HIGH,
            "MEDIUM":   Severity.MEDIUM,
            "LOW":      Severity.LOW,
        }

        type_to_mitre = {
            "AUTH_BYPASS":          ("Initial Access",       "T1078 — Valid Accounts"),
            "IDOR":                  ("Privilege Escalation", "T1548 — Abuse Elevation Control"),
            "BROKEN_ACCESS_CONTROL":("Privilege Escalation", "T1548 — Abuse Elevation Control"),
            "BUSINESS_LOGIC":       ("Defense Evasion",      "T1562 — Impair Defenses"),
            "RACE_CONDITION":       ("Privilege Escalation", "T1548 — Abuse Elevation Control"),
            "MASS_ASSIGNMENT":      ("Privilege Escalation", "T1548 — Abuse Elevation Control"),
            "SESSION_FLAW":         ("Credential Access",    "T1539 — Steal Web Session Cookie"),
            "MISSING_AUTHZ":        ("Initial Access",       "T1190 — Exploit Public-Facing Application"),
        }

        findings = []
        for item in data:
            flaw_type   = item.get("type", "UNKNOWN")
            tactic, technique = type_to_mitre.get(flaw_type, ("Initial Access", "T1190"))

            findings.append(Finding(
                agent=AgentName.LOGIC,
                title=f"[Logic] {item.get('title', 'Logic Flaw')}",
                description=(
                    f"{item.get('description', '')}\n"
                    f"Attack scenario: {item.get('attack_scenario', '')}"
                ),
                severity=sev_map.get(item.get("severity", "MEDIUM"), Severity.MEDIUM),
                file_path=f"{filepath}:{item.get('location', '')}",
                mitre_tactic=tactic,
                mitre_technique=technique,
                remediation=item.get("remediation", "Review access control logic."),
                raw_output=json.dumps(item),
            ))
        return findings

    except json.JSONDecodeError:
        return []
