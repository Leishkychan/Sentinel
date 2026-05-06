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

_client = None

def _get_client():
    """Lazy Anthropic client — not created until first use."""
    global _client
    if _client is None:
        _client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    return _client
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

Your job: Given CONFIRMED vulnerability findings, identify multi-step attack paths where
one finding enables or escalates another. Think: what can an attacker DO with these findings
in combination that they CANNOT do with either alone?

Rules:
- A chain MUST have at least 2 DIFFERENT findings — a finding cannot chain with itself
- Each step must ESCALATE capability: access → privilege, exposure → extraction, recon → exploit
- Generic "attacker gains access" steps are useless — be specific about what changes at each step
- Blast radius must be measured data — cite record counts, endpoint names, specific data types
- Confidence: HIGH = direct proven connection, MEDIUM = plausible combination, LOW = theoretical
- If the only confirmed findings are two separate API exposures at same privilege level, they do NOT
  form a chain — they are parallel findings. Only return a chain if one genuinely enables the other.
- Remediation must identify the ONE fix that breaks the chain — not a list of general improvements

Output ONLY a valid JSON array. If no real chains exist, return: []

Each chain object:
{
  "chain_id": "CHAIN-001",
  "title": "Specific: Finding A enables Finding B",
  "severity": "CRITICAL|HIGH|MEDIUM",
  "description": "What this chain enables that neither finding alone provides",
  "attack_path": [
    "Step 1: Using [specific confirmed finding], attacker obtains [specific capability]",
    "Step 2: That capability enables [specific next action] via [specific mechanism]",
    "Step 3: Final objective: [concrete impact with measured data]"
  ],
  "blast_radius": "Measured: cite exact record counts, endpoint names, or data types confirmed",
  "finding_ids": ["finding-id-1", "finding-id-2"],
  "remediation_priority": "Fix [specific finding] first — this breaks the chain at step X",
  "confidence": "HIGH|MEDIUM|LOW"
}
"""


def analyze_attack_chains(result: ScanResult) -> list[AttackChain]:
    """
    Main entry point.
    Takes a completed ScanResult, passes all findings to Claude,
    and returns identified attack chains.
    """
    if result.total == 0:
        return []

    # Get confirmed URLs from session_intel — the authoritative source
    # NOT a heuristic — only findings that passed the pipeline
    session = getattr(result, '_session', None)
    intel = getattr(session, '_session_intel', None) if session else None

    confirmed_urls: set = set()
    if intel:
        confirmed_urls = intel.confirmed_urls

    # Build confirmed and inferred lists
    # CONFIRMED: URL appears in session_intel confirmed_urls
    # INFERRED: everything else (cannot anchor a chain)
    meaningful = [
        f for f in result.findings
        if f.severity not in (Severity.INFO,)
    ]

    confirmed = [f for f in meaningful
                 if f.file_path and f.file_path in confirmed_urls]
    inferred  = [f for f in meaningful if f not in confirmed]

    print(f"[CHAIN] Confirmed findings: {len(confirmed)} | Inferred: {len(inferred)}")

    # Hard rule: chains require at least 2 CONFIRMED findings
    # If we have fewer, return empty — no chains allowed
    if len(confirmed) < 2:
        print(f"[CHAIN] Insufficient confirmed findings ({len(confirmed)}) — no chains built")
        return []

    print(f"[CHAIN] Analyzing {len(confirmed)} confirmed findings for chains...")

    # ONLY confirmed findings go to Claude — inferred are context only if needed
    # This prevents Claude from inventing chains from unverified signals
    findings_json = _serialize_findings_with_status(confirmed, [])  # Empty inferred list
    raw_chains    = _call_claude(result.target, result.mode, findings_json)
    chains        = _parse_chains(raw_chains)

    # Hard cap: cannot have more chains than confirmed findings
    if len(chains) > len(confirmed):
        chains = chains[:len(confirmed)]

    print(f"[CHAIN] Identified {len(chains)} attack chains")
    return chains


def _serialize_findings_with_status(confirmed: list[Finding],
                                     inferred: list[Finding]) -> str:
    """
    Serialize CONFIRMED findings for Claude chain analysis.
    Inferred parameter kept for API compatibility but is never used —
    only confirmed findings can anchor chains.
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
    # inferred findings are intentionally excluded — they cannot anchor chains
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
    response = _get_client().messages.create(
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
