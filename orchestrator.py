"""
sentinel/agents/orchestrator.py

The main brain. Powered by Claude.
- Receives a scan session (target + mode)
- Plans which sub-agents to run and in what order
- Dispatches agents sequentially
- Aggregates all findings
- NEVER executes tools directly — it only plans and routes

The orchestrator CANNOT call validate_action itself.
Each sub-agent is responsible for validating its own actions.
The orchestrator trusts that sub-agents will hard-stop on violations.
"""

import os
import json
from typing import Optional
from anthropic import Anthropic

from sentinel.core import (
    ScanMode, AgentName, ScanSession, ScanResult, Finding,
)
from sentinel.agents.sast_agent import run_sast_agent
from sentinel.agents.deps_agent import run_deps_agent


client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

ORCHESTRATOR_MODEL = os.getenv("ORCHESTRATOR_MODEL", "claude-sonnet-4-20250514")


SYSTEM_PROMPT = """You are Sentinel's Orchestrator — a blue team AI security coordinator.

Your job:
1. Analyze the scan target and mode provided
2. Decide which sub-agents to dispatch (in order)
3. Synthesize their findings into a coherent threat picture
4. Produce a final structured report

Your hard rules — non-negotiable:
- You NEVER suggest exploitation of any finding
- You NEVER output commands that could be used to attack a target
- You NEVER recommend actions that go beyond the authorized scan mode
- You NEVER fabricate CVE IDs or severity scores — only report what agents found
- If findings are ambiguous, mark them INFO and flag for human review
- Remediation suggestions are required for every finding, but must be defensive

You are a blue team tool. Your purpose is to help defenders, not attackers.
When in doubt, surface the finding with LOW severity and let the human decide.

Output format for your dispatch plan:
Return a JSON object with:
{
  "agents_to_run": ["sast_agent", "deps_agent"],
  "rationale": "Brief explanation of why these agents for this target/mode",
  "scan_notes": "Any observations about the target that agents should know"
}
"""


def run_orchestrator(session: ScanSession, source_path: Optional[str] = None) -> ScanResult:
    """
    Main entry point. Given an authorized session, run the full scan pipeline.

    Args:
        session:     Authorized ScanSession (approved=True required)
        source_path: Path to source code (required for CODE mode)

    Returns:
        ScanResult with all findings aggregated
    """
    if not session.approved:
        raise ValueError("Session must be approved before orchestrator runs.")

    if session.mode == ScanMode.ACTIVE and not session.active_confirmed:
        raise ValueError("ACTIVE mode requires second confirmation.")

    print(f"\n[ORCHESTRATOR] Starting scan — target={session.target} mode={session.mode}")

    # Step 1: Ask Claude to build a dispatch plan
    plan = _build_dispatch_plan(session, source_path)
    print(f"[ORCHESTRATOR] Dispatch plan: {plan['agents_to_run']}")
    print(f"[ORCHESTRATOR] Rationale: {plan['rationale']}")

    # Step 2: Execute agents per plan
    all_findings: list[Finding] = []
    agents_run: list[AgentName] = []

    for agent_name in plan["agents_to_run"]:

        if agent_name == AgentName.SAST and source_path:
            print(f"[ORCHESTRATOR] → Dispatching SAST agent on {source_path}")
            findings = run_sast_agent(session, source_path)
            all_findings.extend(findings)
            agents_run.append(AgentName.SAST)

        elif agent_name == AgentName.DEPS and source_path:
            print(f"[ORCHESTRATOR] → Dispatching Deps agent on {source_path}")
            findings = run_deps_agent(session, source_path)
            all_findings.extend(findings)
            agents_run.append(AgentName.DEPS)

        # Phase 2+: recon_agent, config_agent added here

    # Step 3: Build final result
    result = _build_result(session, all_findings, agents_run)

    # Step 4: Enrich with Claude summary
    result.summary = _generate_summary(session, result)

    print(f"[ORCHESTRATOR] Scan complete — {result.total} findings")
    return result


# ── Private ───────────────────────────────────────────────────────────────────

def _build_dispatch_plan(session: ScanSession, source_path: Optional[str]) -> dict:
    """Ask Claude which agents to run given the session context."""

    user_msg = f"""
Scan request:
- Target: {session.target}
- Mode: {session.mode}
- Source code available: {"Yes, at: " + source_path if source_path else "No"}
- Session ID: {session.session_id}

Based on the mode and available inputs, which agents should I dispatch?
Respond with the JSON format specified in your instructions.
"""

    response = client.messages.create(
        model=ORCHESTRATOR_MODEL,
        max_tokens=1000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    )

    raw = response.content[0].text.strip()

    # Strip markdown fences if present
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    try:
        plan = json.loads(raw)
    except json.JSONDecodeError:
        # Fallback: infer from mode
        plan = _default_plan(session, source_path)

    # Normalize agent names to AgentName enum values
    plan["agents_to_run"] = [
        AgentName(a) for a in plan.get("agents_to_run", [])
        if a in [e.value for e in AgentName]
    ]
    return plan


def _default_plan(session: ScanSession, source_path: Optional[str]) -> dict:
    """Fallback plan when Claude response can't be parsed."""
    if session.mode == ScanMode.CODE and source_path:
        return {
            "agents_to_run": [AgentName.SAST, AgentName.DEPS],
            "rationale": "CODE mode with source — running static analysis and dependency scan.",
            "scan_notes": "",
        }
    elif session.mode == ScanMode.PASSIVE:
        return {
            "agents_to_run": [],  # Recon/Config agents added in Phase 2
            "rationale": "PASSIVE mode — recon agents not yet implemented.",
            "scan_notes": "",
        }
    return {"agents_to_run": [], "rationale": "Could not determine plan.", "scan_notes": ""}


def _build_result(
    session: ScanSession,
    findings: list[Finding],
    agents_run: list[AgentName],
) -> ScanResult:
    """Aggregate findings into a ScanResult."""
    by_severity: dict = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    return ScanResult(
        session_id=session.session_id,
        target=session.target,
        mode=session.mode,
        findings=findings,
        total=len(findings),
        by_severity=by_severity,
        agents_run=agents_run,
    )


def _generate_summary(session: ScanSession, result: ScanResult) -> str:
    """Ask Claude to write a human-readable summary of the findings."""
    if result.total == 0:
        return "No findings detected in this scan. This does not guarantee the absence of vulnerabilities."

    findings_text = "\n".join([
        f"- [{f.severity}] {f.title}: {f.description[:120]}"
        for f in result.findings[:20]  # Cap at 20 for context window
    ])

    response = client.messages.create(
        model=ORCHESTRATOR_MODEL,
        max_tokens=800,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"""
Write a blue team threat summary for this scan result.
Target: {result.target}
Mode: {result.mode}
Total findings: {result.total}
By severity: {result.by_severity}

Top findings:
{findings_text}

Summary should:
- Be 3-5 sentences
- Prioritize the most critical findings
- Recommend immediate next steps (defensive only)
- NOT mention exploitation
"""
        }],
    )
    return response.content[0].text.strip()
