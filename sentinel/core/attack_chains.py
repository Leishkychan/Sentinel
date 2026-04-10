"""
sentinel/core/attack_chains.py

Attack Chain Reasoning — The differentiator.
Uses Claude to analyze ALL findings together and identify:

1. Attack chains — sequences of findings that form a viable breach path
2. Blast radius — what an attacker could reach if a chain is exploited
3. Priority ranking — which chains to remediate first

This is what separates Sentinel from a script that runs tools.
Most scanners list findings in isolation. Real attackers think in chains.

Example chain:
  [MEDIUM] Missing auth on /api/internal
  + [LOW]  Server version disclosed (nginx 1.14.0)
  + [HIGH] CVE-2019-1234 affects nginx 1.14.0
  = CRITICAL CHAIN: Unauthenticated access to /api/internal via known nginx CVE

Claude reasons about these combinations.
Humans read the chain, not the individual findings.
"""

import os
import json
from dataclasses import dataclass, field
from typing import Optional
from anthropic import Anthropic

from .models import Finding, Severity, ScanResult

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
MODEL  = os.getenv("ORCHESTRATOR_MODEL", "claude-sonnet-4-20250514")


@dataclass
class AttackChain:
    chain_id:     str
    title:        str
    severity:     str          # CRITICAL / HIGH / MEDIUM
    description:  str          # What the chain is
    attack_path:  list[str]    # Step-by-step attacker perspective
    blast_radius: str          # What the attacker can reach
    finding_ids:  list[str]    # IDs of findings that make up this chain
    remediation_priority: str  # What to fix first to break the chain
    confidence:   str          # HIGH / MEDIUM / LOW — how confident is this chain


CHAIN_SYSTEM_PROMPT = """You are Sentinel's Attack Chain Analyst — a senior red team thinker
working for the blue team.

Your job: Given a set of vulnerability findings, identify combinations that form
viable attack chains. Think like an attacker who will combine multiple weaknesses
to achieve a goal.

Rules:
- Only identify chains that are PLAUSIBLE given the findings — don't speculate wildly
- A chain needs at least 2 connected findings to be valid
- Rank chains by actual exploitability + impact, not just individual severity
- Be specific about the attack path — generic "attacker gains access" is useless
- Blast radius must be concrete — "database contents" not "data breach"
- Remediation must identify the ONE finding that, if fixed, breaks the entire chain
- Confidence: HIGH = direct connection between findings, MEDIUM = plausible combination,
  LOW = theoretical but worth noting

Output ONLY a valid JSON array of chain objects. No preamble, no markdown fences.

Each chain object:
{
  "chain_id": "CHAIN-001",
  "title": "Short descriptive title of the attack path",
  "severity": "CRITICAL|HIGH|MEDIUM",
  "description": "What this chain represents in plain English",
  "attack_path": [
    "Step 1: Attacker does X using finding Y",
    "Step 2: Using access from step 1, attacker does Z",
    "Step 3: Attacker reaches final objective"
  ],
  "blast_radius": "Concrete description of what attacker can access/do",
  "finding_ids": ["finding-id-1", "finding-id-2"],
  "remediation_priority": "Fix [specific finding] first — this breaks the chain at step X",
  "confidence": "HIGH|MEDIUM|LOW"
}

If no meaningful chains exist, return an empty array: []
"""


def analyze_attack_chains(result: ScanResult) -> list[AttackChain]:
    """
    Main entry point.
    Takes a completed ScanResult, passes all findings to Claude,
    and returns identified attack chains.
    """
    if result.total == 0:
        return []

    # Only chain findings that are CONFIRMED or at minimum INFERRED
    # UNCONFIRMED hypotheses cannot form attack chains — that's assumption stacking
    meaningful = [
        f for f in result.findings
        if f.severity not in (Severity.INFO,)
        and not f.title.startswith("[UNCONFIRMED]")
    ]
    # Tag which findings are confirmed vs inferred for Claude
    confirmed   = [f for f in meaningful if "blast radius (measured)" in (f.description or "").lower()
                   or f.title.startswith("[Alpha] Unauthenticated")
                   or f.agent in ("probe_agent", "config_agent", "recon_agent",
                                  "injection_agent", "auth_scan_agent")]
    inferred    = [f for f in meaningful if f not in confirmed]
    print(f"[CHAIN] Confirmed findings: {len(confirmed)} | Inferred: {len(inferred)}")

    if len(meaningful) < 2:
        return []  # Can't form a chain with 1 finding

    print(f"[CHAIN] Analyzing {len(meaningful)} findings for attack chains...")

    findings_json = _serialize_findings_with_status(confirmed, inferred)
    raw_chains    = _call_claude(result.target, result.mode, findings_json)
    chains        = _parse_chains(raw_chains)

    print(f"[CHAIN] Identified {len(chains)} attack chains")
    return chains


def _serialize_findings(findings: list[Finding]) -> str:
    """Serialize findings to a compact format for Claude's context."""
    items = []
    for f in findings:
        items.append({
            "id":          f.finding_id,
            "severity":    f.severity,
            "title":       f.title,
            "description": f.description[:300],
            "file":        f.file_path,
            "agent":       f.agent,
            "mitre":       f.mitre_tactic,
            "cve":         f.cve_id,
        })
    return json.dumps(items, indent=2, default=str)


def _serialize_findings_with_status(confirmed: list[Finding],
                                     inferred: list[Finding]) -> str:
    """
    Serialize findings with explicit confirmation status.
    Claude must not chain INFERRED findings as if they were CONFIRMED.
    """
    items = []
    for f in confirmed:
        items.append({
            "id":          f.finding_id,
            "status":      "CONFIRMED",
            "severity":    f.severity,
            "title":       f.title,
            "description": (f.description or "")[:300],
            "agent":       f.agent,
            "mitre":       f.mitre_tactic,
        })
    for f in inferred:
        items.append({
            "id":          f.finding_id,
            "status":      "INFERRED — not directly confirmed",
            "severity":    f.severity,
            "title":       f.title,
            "description": (f.description or "")[:200],
            "agent":       f.agent,
        })
    return json.dumps(items, indent=2, default=str)


def _call_claude(target: str, mode, findings_json: str) -> str:
    """Send findings to Claude for attack chain analysis."""
    user_msg = f"""
Analyze these security findings from a scan of: {target}
Scan mode: {mode}

Findings:
{findings_json}

Identify all viable attack chains. Return the JSON array only.
"""
    response = client.messages.create(
        model=MODEL,
        max_tokens=4000,
        system=CHAIN_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    )
    return response.content[0].text.strip()


def _parse_chains(raw: str) -> list[AttackChain]:
    """Parse Claude's JSON response into AttackChain objects."""
    # Strip markdown fences if present
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    try:
        data = json.loads(raw)
        if not isinstance(data, list):
            return []

        chains = []
        for item in data:
            try:
                chains.append(AttackChain(
                    chain_id=item.get("chain_id", f"CHAIN-{len(chains)+1:03d}"),
                    title=item.get("title", "Unnamed Chain"),
                    severity=item.get("severity", "MEDIUM"),
                    description=item.get("description", ""),
                    attack_path=item.get("attack_path", []),
                    blast_radius=item.get("blast_radius", "Unknown"),
                    finding_ids=item.get("finding_ids", []),
                    remediation_priority=item.get("remediation_priority", ""),
                    confidence=item.get("confidence", "MEDIUM"),
                ))
            except Exception:
                continue

        # Sort by severity
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        chains.sort(key=lambda c: order.get(c.severity, 4))
        return chains

    except json.JSONDecodeError as e:
        print(f"[CHAIN] Failed to parse Claude response: {e}")
        print(f"[CHAIN] Raw response: {raw[:500]}")
        return []


def chains_to_dict(chains: list[AttackChain]) -> list[dict]:
    """Serialize chains for JSON report output."""
    return [
        {
            "chain_id":             c.chain_id,
            "title":                c.title,
            "severity":             c.severity,
            "confidence":           c.confidence,
            "description":          c.description,
            "attack_path":          c.attack_path,
            "blast_radius":         c.blast_radius,
            "finding_ids":          c.finding_ids,
            "remediation_priority": c.remediation_priority,
        }
        for c in chains
    ]
