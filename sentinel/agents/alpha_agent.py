"""
sentinel/agents/alpha_agent.py

ALPHA AGENT — Autonomous Strategic Threat Investigator.

Alpha sits above everything. It commands, reasons, and decides.
It never scans directly — it thinks, then directs.

Architecture:
  Alpha → reads findings → builds hypothesis → directs orchestrator
       → evaluates results → updates hypothesis → directs again
       → decides when it understands the full picture → stops

Alpha uses the most capable model available.
Alpha reasons like a senior red teamer working for the blue team.

Alpha's decision loop:
  1. What do the current findings tell me?
  2. What's the most likely attack path from here?
  3. What's the highest-value thing to investigate next?
  4. If that fails, what's my fallback?
  5. What does this mean for the defender?

Alpha NEVER:
  - Suggests exploitation
  - Builds payloads
  - Acts on findings directly
  - Stops investigating prematurely
  - Retries a method the safety guard has already blocked
  - Uses DELETE, PUT, PATCH, or PATCH in targeted probes — these are BLOCKED
  - Wastes cycles repeating failed paths

Alpha ALWAYS:
  - Reasons about findings in combination, not isolation
  - Builds attack path hypotheses before testing them
  - Pivots intelligently when a path is blocked
  - Produces a threat narrative, not just a finding list
"""

import os
import json
import time
from typing import Optional
from anthropic import Anthropic
from sentinel.core.models import (
    ScanMode, AgentName, ScanSession, Finding, ScanResult, Severity,
)
from sentinel.core.audit import log_audit_entry
from sentinel.core.models import AuditEntry

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# Alpha uses the most capable model — claude-opus-4-5-20251001 if available, else sonnet
ALPHA_MODEL = os.getenv("ALPHA_MODEL", "claude-opus-4-5-20251001")
FALLBACK_MODEL = os.getenv("ORCHESTRATOR_MODEL", "claude-sonnet-4-20250514")

MAX_ALPHA_CYCLES = 8  # Max investigation cycles before forcing conclusion
MIN_FINDINGS_TO_REASON = 2  # Need at least this many findings to reason about


ALPHA_SYSTEM = """You are Sentinel's Alpha Agent — an autonomous strategic threat investigator.

You are the most senior analyst in a blue team security operation.
Your job is to reason about vulnerability findings like an attacker would,
then use that understanding to direct the investigation toward maximum impact.

You operate in cycles:
1. ANALYZE — What do the findings tell you? What patterns do you see?
2. HYPOTHESIZE — What attack paths exist? Which is most likely to succeed?
3. DIRECT — What should be investigated next to confirm/deny your hypothesis?
4. EVALUATE — What did we learn? Does it confirm or change your theory?
5. CONCLUDE — When do you have enough to write a complete threat picture?

Your reasoning style:
- Think in attack chains, not individual findings
- Every finding is a potential pivot point — what does it enable?
- Combine findings that individually look low/medium into critical chains
- Always have a primary path AND a fallback path
- Know when to go deeper vs when to pivot to a different attack surface

Your investigation targets:
You can direct these agents: recon_agent, config_agent, network_agent,
probe_agent, js_agent, api_agent, disclosure_agent,
sast_agent (needs source_path), deps_agent (needs source_path),
logic_agent (needs source_path), nuclei_agent (ACTIVE mode only)

You can also direct TARGETED PROBES — specific HTTP requests to specific URLs
when you need to test a precise hypothesis without running a full agent.

CRITICAL: Targeted probes are READ-ONLY. Only GET, POST (auth testing), OPTIONS, HEAD are allowed.
DELETE, PUT, PATCH are permanently blocked. Do not attempt them.
If you want to document that an endpoint ALLOWS dangerous methods, create a finding — don't probe it.
After a method is blocked once, NEVER suggest it again in any cycle.

Hard rules — you NEVER break these:
- Never suggest exploitation of any finding
- Never recommend actions that could damage the target
- Never fabricate findings or CVE IDs
- All investigation is READ-ONLY — observe, never modify
- You work for defenders, not attackers

Output format:
Always return valid JSON. Structure depends on what you're doing:

For directing investigation:
{
  "cycle": <number>,
  "status": "investigating",
  "hypothesis": "What I think is happening and why",
  "confidence": "LOW|MEDIUM|HIGH",
  "primary_path": {
    "action": "run_agent|targeted_probe",
    "agent": "agent_name" (if run_agent),
    "probe": {"url": "...", "method": "GET|POST", "headers": {}, "body": {}} (if targeted_probe),
    "rationale": "Why this is the highest value next step"
  },
  "fallback_path": {
    "action": "run_agent|targeted_probe",
    "agent": "agent_name",
    "probe": {"url": "...", "method": "GET"},
    "rationale": "If primary fails, try this instead"
  },
  "fallback_path_2": {
    "action": "run_agent|targeted_probe", 
    "agent": "agent_name",
    "rationale": "Third option if first two fail"
  }
}

For concluding investigation:
{
  "cycle": <number>,
  "status": "complete",
  "threat_narrative": "Complete plain-English threat picture for defenders",
  "attack_paths": [
    {
      "path_id": "PATH-001",
      "title": "Short attack path name",
      "severity": "CRITICAL|HIGH|MEDIUM",
      "steps": ["Step 1", "Step 2", "Step 3"],
      "confirmed": true/false,
      "blast_radius": "What attacker achieves",
      "break_point": "The single fix that stops this path"
    }
  ],
  "immediate_actions": ["Action 1", "Action 2", "Action 3"],
  "risk_score": "CRITICAL|HIGH|MEDIUM|LOW"
}
"""


class AlphaAgent:
    """
    Alpha Agent — autonomous threat investigator.
    Maintains state across investigation cycles.
    """

    def __init__(self, session: ScanSession, source_path: Optional[str] = None):
        self.session       = session
        self.source_path   = source_path
        self.cycle         = 0
        self.all_findings: list[Finding] = []
        self.investigation_log: list[dict] = []
        self.current_hypothesis = None
        self.completed_paths: set[str] = set()
        self.failed_paths: set[str] = set()
        self.blocked_methods: set[str] = set()  # Methods the safety guard blocked
        self.learned_constraints: list[str] = []  # What Alpha has learned this session
        self.threat_narrative: Optional[str] = None
        self.confirmed_attack_paths: list[dict] = []
        self.model = self._get_best_model()

    def _get_best_model(self) -> str:
        """Try the most capable model, fall back gracefully."""
        try:
            # Quick test call to see if opus is available
            client.messages.create(
                model=ALPHA_MODEL,
                max_tokens=10,
                messages=[{"role": "user", "content": "test"}]
            )
            print(f"[ALPHA] Using {ALPHA_MODEL}")
            return ALPHA_MODEL
        except Exception:
            print(f"[ALPHA] {ALPHA_MODEL} unavailable, using {FALLBACK_MODEL}")
            return FALLBACK_MODEL

    def add_findings(self, findings: list[Finding]):
        """Add new findings from an agent run."""
        self.all_findings.extend(findings)

    def think(self) -> dict:
        """
        Core reasoning cycle. Returns Alpha's decision on what to do next.
        """
        self.cycle += 1
        print(f"\n[ALPHA] ═══ Cycle {self.cycle} ═══")
        print(f"[ALPHA] Reasoning over {len(self.all_findings)} findings...")

        if self.cycle > MAX_ALPHA_CYCLES:
            print(f"[ALPHA] Max cycles reached — concluding investigation")
            return self._force_conclusion()

        if len(self.all_findings) < MIN_FINDINGS_TO_REASON:
            return {"status": "need_more_data", "cycle": self.cycle}

        prompt = self._build_reasoning_prompt()

        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=2000,
                system=ALPHA_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.content[0].text.strip()
            decision = self._parse_decision(raw)
            self._log_cycle(decision)
            return decision

        except Exception as e:
            print(f"[ALPHA] Reasoning error: {e}")
            return {"status": "error", "cycle": self.cycle}

    def evaluate_result(self, action_taken: str, findings_returned: list[Finding],
                        success: bool) -> str:
        """
        After an action, Alpha evaluates what happened.
        Returns: "confirmed" | "pivoting" | "new_hypothesis" | "complete"
        """
        if findings_returned:
            self.add_findings(findings_returned)

        critical_new = [f for f in findings_returned
                        if f.severity in (Severity.CRITICAL, Severity.HIGH)]

        if success and critical_new:
            print(f"[ALPHA] ✓ Action confirmed hypothesis — {len(critical_new)} critical findings")
            self.completed_paths.add(action_taken)
            return "confirmed"
        elif not success or not findings_returned:
            print(f"[ALPHA] ✗ Action failed or empty — pivoting to fallback")
            self.failed_paths.add(action_taken)
            return "pivoting"
        else:
            print(f"[ALPHA] ~ Action returned low-signal results — updating hypothesis")
            return "new_hypothesis"

    def conclude(self) -> dict:
        """Force Alpha to write its final threat narrative."""
        print(f"\n[ALPHA] Writing final threat narrative...")

        findings_text = self._serialize_findings(self.all_findings)
        log_text = json.dumps(self.investigation_log[-5:], indent=2)  # Last 5 cycles

        prompt = f"""You have completed your investigation of {self.session.target}.

Total findings: {len(self.all_findings)}
Severity breakdown: {self._severity_breakdown()}

All findings:
{findings_text}

Investigation log (last cycles):
{log_text}

Write your final threat assessment. Return the "complete" status JSON.
Focus on:
1. What an attacker can actually achieve against this target
2. The specific attack paths in order of severity
3. What single action breaks each chain
4. The overall risk to the organization
"""

        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=3000,
                system=ALPHA_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.content[0].text.strip()
            conclusion = self._parse_decision(raw)
            self.threat_narrative = conclusion.get("threat_narrative", "")
            self.confirmed_attack_paths = conclusion.get("attack_paths", [])
            return conclusion
        except Exception as e:
            print(f"[ALPHA] Conclusion error: {e}")
            return self._force_conclusion()

    # ── Private ───────────────────────────────────────────────────────────────

    def _build_reasoning_prompt(self) -> str:
        findings_text = self._serialize_findings(self.all_findings)
        completed = list(self.completed_paths)[:5]
        failed    = list(self.failed_paths)[:5]
        hyp = self.current_hypothesis or "No hypothesis yet — this is cycle 1"

        mode_context = f"Scan mode: {self.session.mode.value}"
        source_context = f"Source code available: {'Yes' if self.source_path else 'No'}"

        # Build learned constraints
        blocked = list(getattr(self.session, '_alpha_blocked_methods', set()))
        constraints = ""
        if blocked:
            constraints = f"\n\nLEARNED CONSTRAINTS (do not attempt these):\n"
            constraints += f"- HTTP methods blocked by safety guard: {blocked}\n"
            constraints += "- Only use GET, POST, OPTIONS, HEAD for targeted probes\n"
            constraints += "- To test dangerous method exposure, note it as a finding — don't try to execute it\n"

        return f"""Target: {self.session.target}
{mode_context}
{source_context}
Investigation cycle: {self.cycle}

Current hypothesis:
{hyp}

Paths completed: {completed if completed else 'None yet'}
Paths that failed/empty: {failed if failed else 'None yet'}
{constraints}
Current findings ({len(self.all_findings)} total):
{findings_text}

What should I investigate next? What's my primary path, and what are my fallbacks?
Focus on READ-ONLY probes (GET requests). Do not suggest DELETE/PUT/PATCH.
Return your reasoning and direction as JSON."""

    def _serialize_findings(self, findings: list[Finding]) -> str:
        # Sort by severity, take top 20
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_f = sorted(findings,
                          key=lambda f: order.get(str(f.severity).split(".")[-1], 5))[:20]
        lines = []
        for f in sorted_f:
            sev = str(f.severity).split(".")[-1]
            lines.append(f"[{sev}] {f.title}: {f.description[:150]}")
        return "\n".join(lines)

    def _severity_breakdown(self) -> dict:
        breakdown = {}
        for f in self.all_findings:
            sev = str(f.severity).split(".")[-1]
            breakdown[sev] = breakdown.get(sev, 0) + 1
        return breakdown

    def _parse_decision(self, raw: str) -> dict:
        if raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1] if len(parts) > 1 else raw
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"status": "error", "raw": raw[:200]}

    def _log_cycle(self, decision: dict):
        self.investigation_log.append({
            "cycle":      self.cycle,
            "hypothesis": decision.get("hypothesis", ""),
            "action":     decision.get("primary_path", {}),
            "status":     decision.get("status", "unknown"),
        })
        if decision.get("hypothesis"):
            self.current_hypothesis = decision["hypothesis"]

        # Print Alpha's reasoning
        if decision.get("hypothesis"):
            print(f"[ALPHA] Hypothesis: {decision['hypothesis'][:150]}")
        if decision.get("primary_path"):
            p = decision["primary_path"]
            action = p.get("agent") or p.get("probe", {}).get("url", "unknown")
            print(f"[ALPHA] Primary path: {p.get('action','?')} → {action}")
            print(f"[ALPHA] Rationale: {p.get('rationale','')[:100]}")
        if decision.get("fallback_path"):
            fb = decision["fallback_path"]
            action = fb.get("agent") or fb.get("probe", {}).get("url", "unknown")
            print(f"[ALPHA] Fallback: {fb.get('action','?')} → {action}")
        if decision.get("confidence"):
            print(f"[ALPHA] Confidence: {decision['confidence']}")

    def _force_conclusion(self) -> dict:
        """Emergency conclusion when max cycles hit or errors occur."""
        breakdown = self._severity_breakdown()
        return {
            "status": "complete",
            "cycle": self.cycle,
            "threat_narrative": (
                f"Investigation of {self.session.target} completed after {self.cycle} cycles. "
                f"Found {len(self.all_findings)} total findings: {breakdown}. "
                "Review individual findings for detailed remediation guidance."
            ),
            "attack_paths": [],
            "immediate_actions": [
                "Review all CRITICAL findings immediately",
                "Implement authentication on all exposed admin endpoints",
                "Enable HTTPS and configure security headers",
            ],
            "risk_score": "CRITICAL" if breakdown.get("CRITICAL", 0) > 0 else "HIGH",
        }


# ── Targeted Probe Executor ───────────────────────────────────────────────────

def execute_targeted_probe(probe: dict, session: ScanSession) -> list[Finding]:
    """
    Execute a specific HTTP probe directed by Alpha.
    Read-only — GET requests observe, POST only tests auth (no mutations).
    """
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    from sentinel.core.validator import validate_action

    url     = probe.get("url", "")
    method  = probe.get("method", "GET").upper()
    headers = {
        "User-Agent": "Sentinel-SecurityScanner/1.0",
        **probe.get("headers", {}),
    }
    body = probe.get("body", None)

    if not url:
        return []

    # Safety: only allow safe methods in targeted probes
    if method not in ("GET", "POST", "OPTIONS", "HEAD"):
        print(f"[ALPHA/PROBE] Method {method} blocked — targeted probes are read-only")
        return []

    # Validate against scope
    from urllib.parse import urlparse
    host = urlparse(url).hostname or url
    try:
        validate_action(AgentName.PROBE, "http_probe", host, session)
    except Exception as e:
        print(f"[ALPHA/PROBE] Validation failed: {e}")
        return []

    findings = []
    try:
        if method == "GET":
            resp = requests.get(url, headers=headers, timeout=10, verify=False)
        elif method == "POST":
            resp = requests.post(url, json=body, headers=headers, timeout=10, verify=False)
        elif method == "OPTIONS":
            resp = requests.options(url, headers=headers, timeout=10, verify=False)
        else:
            resp = requests.head(url, headers=headers, timeout=10, verify=False)

        # Analyze response
        finding = _analyze_probe_response(url, method, resp, probe.get("hypothesis", ""))
        if finding:
            findings.append(finding)

    except requests.RequestException as e:
        print(f"[ALPHA/PROBE] Request failed: {e}")

    return findings


def _analyze_probe_response(url: str, method: str, resp,
                             hypothesis: str) -> Optional[Finding]:
    """Analyze a targeted probe response and return a Finding if significant."""
    import requests

    status = resp.status_code
    content_len = len(resp.content)
    content_type = resp.headers.get("Content-Type", "")
    content_preview = resp.text[:300] if resp.text else ""

    # Unauthenticated access to what should be protected
    if status == 200 and content_len > 100:
        severity = Severity.CRITICAL
        description = (
            f"Targeted probe: {method} {url} returned HTTP {status} "
            f"with {content_len} bytes. "
            f"Hypothesis tested: {hypothesis}. "
        )

        # Check for sensitive data in response
        sensitive_indicators = [
            "password", "token", "secret", "admin", "role",
            "email", "credit", "ssn", "key", "auth"
        ]
        found_sensitive = [s for s in sensitive_indicators
                          if s in content_preview.lower()]
        if found_sensitive:
            description += f"Sensitive fields in response: {', '.join(found_sensitive)}."
            severity = Severity.CRITICAL

        return Finding(
            agent=AgentName.PROBE,
            title=f"[Alpha] Targeted Probe Success: {url.split('?')[0]}",
            description=description,
            severity=severity,
            file_path=url,
            mitre_tactic="Initial Access",
            mitre_technique="T1190 — Exploit Public-Facing Application",
            remediation=(
                "Implement authentication on this endpoint. "
                "Verify server-side authorization before returning data."
            ),
        )

    elif status == 403:
        # Protected but confirms existence
        return Finding(
            agent=AgentName.PROBE,
            title=f"[Alpha] Endpoint Confirmed (Protected): {url.split('?')[0]}",
            description=f"Endpoint exists but returns 403. Hypothesis: {hypothesis}",
            severity=Severity.LOW,
            file_path=url,
            remediation="Endpoint is protected. Verify access controls are correct.",
        )

    return None


# For type hints
from typing import Optional
