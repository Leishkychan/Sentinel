"""
sentinel/agents/orchestrator.py
Iterative orchestrator — re-plans after each agent based on findings.
"""
import os, json
from typing import Optional
from anthropic import Anthropic
from sentinel.core.models import ScanMode, AgentName, ScanSession, ScanResult, Finding, Severity
from sentinel.core.mitre import enrich_all
from sentinel.core.attack_chains import analyze_attack_chains, chains_to_dict
from sentinel.core.delta import compute_delta, delta_to_markdown
from sentinel.core.threat_intel import load_attack_data, enrich_finding_intel
from sentinel.core.nvd_lookup import scan_service_versions

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
MODEL  = os.getenv("ORCHESTRATOR_MODEL", "claude-sonnet-4-20250514")
MAX_ITERATIONS = 5

SYSTEM = """You are Sentinel's Orchestrator — a blue team AI security coordinator.
Plan scans, adapt based on findings, think like a defender finding every vulnerability first.

Available agents: sast_agent, deps_agent, logic_agent, config_agent, recon_agent, network_agent, nuclei_agent

Rules: Never suggest exploitation. Never fabricate CVEs. Only dispatch agents valid for the mode.
PASSIVE=recon/config/network only. CODE=sast/deps/logic only. ACTIVE=all agents.

Return JSON only. No markdown, no preamble.
Initial plan format: {"agents_to_run": ["agent_name"], "rationale": "why"}
Replan format: {"continue": true/false, "next_agents": ["agent_name"], "reason": "why"}
"""


def run_orchestrator(session: ScanSession, source_path: Optional[str] = None) -> ScanResult:
    if not session.approved:
        raise ValueError("Session must be approved.")
    if session.mode == ScanMode.ACTIVE and not session.active_confirmed:
        raise ValueError("ACTIVE mode requires second confirmation.")

    print(f"\n[ORCHESTRATOR] Target={session.target} Mode={session.mode}")
    load_attack_data()

    all_findings: list[Finding] = []
    agents_run:   list[AgentName] = []
    done:         set = set()
    iteration     = 0

    plan  = _initial_plan(session, source_path)
    queue = list(plan.get("agents_to_run", _default_agents(session, source_path)))
    print(f"[ORCHESTRATOR] Plan: {queue} | {plan.get('rationale','')}")

    while queue and iteration < MAX_ITERATIONS:
        iteration += 1
        agent = queue.pop(0)
        if agent in done:
            continue

        print(f"[ORCHESTRATOR] [{iteration}] Dispatching {agent}...")
        new_findings = _dispatch(agent, session, source_path)
        done.add(agent)

        if new_findings:
            all_findings.extend(new_findings)
            try: agents_run.append(AgentName(agent))
            except ValueError: pass
            print(f"[ORCHESTRATOR] → {len(new_findings)} findings")
            for f in sorted(new_findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(
                    x.severity if x.severity in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else "INFO"))[:3]:
                print(f"  [{f.severity}] {f.title[:70]}")

        if not queue or any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in new_findings):
            replan = _replan(session, source_path, all_findings, done, queue)
            if replan.get("continue") and replan.get("next_agents"):
                adds = [a for a in replan["next_agents"] if a not in done]
                if adds:
                    print(f"[ORCHESTRATOR] Replan → {adds} | {replan.get('reason','')}")
                    queue.extend(adds)

    all_findings = enrich_all(all_findings)
    all_findings = _enrich_intel(all_findings)
    all_findings.extend(_nvd_check(session, all_findings))

    result = _build_result(session, all_findings, agents_run)

    print(f"[ORCHESTRATOR] Running attack chain analysis...")
    chains = analyze_attack_chains(result)
    result.attack_chains = chains_to_dict(chains)
    for c in chains:
        print(f"  [{c.severity}] {c.title} ({c.confidence})")

    delta = compute_delta(result, session.target)
    result.delta_summary  = delta.summary
    result.delta_markdown = delta_to_markdown(delta)

    result.summary = _summary(result, chains)
    print(f"[ORCHESTRATOR] DONE: {result.total} findings | {len(chains)} chains")
    return result


def _dispatch(agent: str, session: ScanSession, source_path: Optional[str]) -> list[Finding]:
    try:
        if agent == "sast_agent" and source_path:
            from sentinel.agents.sast_agent import run_sast_agent
            return run_sast_agent(session, source_path)
        elif agent == "deps_agent" and source_path:
            from sentinel.agents.deps_agent import run_deps_agent
            return run_deps_agent(session, source_path)
        elif agent == "logic_agent" and source_path:
            from sentinel.agents.logic_agent import run_logic_agent
            return run_logic_agent(session, source_path)
        elif agent == "config_agent":
            from sentinel.agents.config_agent import run_config_agent
            url = session.target if session.target.startswith("http") else None
            return run_config_agent(session, target_url=url, source_path=source_path)
        elif agent == "recon_agent":
            from sentinel.agents.recon_agent import run_recon_agent
            return run_recon_agent(session, session.target)
        elif agent == "network_agent":
            from sentinel.agents.network_agent import run_network_agent
            return run_network_agent(session, session.target)
        elif agent == "nuclei_agent" and session.mode == ScanMode.ACTIVE:
            from sentinel.agents.nuclei_agent import run_nuclei_agent
            url = session.target if session.target.startswith("http") else f"http://{session.target}"
            return run_nuclei_agent(session, url)
        else:
            return []
    except Exception as e:
        print(f"[ORCHESTRATOR] {agent} error: {e}")
        return []


def _initial_plan(session: ScanSession, source_path: Optional[str]) -> dict:
    try:
        resp = client.messages.create(
            model=MODEL, max_tokens=400, system=SYSTEM,
            messages=[{"role": "user", "content":
                f"Target: {session.target}\nMode: {session.mode.value}\n"
                f"Source: {'Yes: '+source_path if source_path else 'No'}\n"
                f"Return initial agent plan JSON."}])
        plan = json.loads(_clean(resp.content[0].text))
        plan["agents_to_run"] = [a for a in plan.get("agents_to_run", [])
                                  if a in [e.value for e in AgentName]]
        return plan if plan["agents_to_run"] else {"agents_to_run": _default_agents(session, source_path)}
    except Exception:
        return {"agents_to_run": _default_agents(session, source_path)}


def _replan(session, source_path, findings, done, queue) -> dict:
    if not findings: return {"continue": False}
    by_sev = {}
    for f in findings: by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    top = [f"[{f.severity}] {f.title[:60]}" for f in findings[:5]]
    try:
        resp = client.messages.create(
            model=MODEL, max_tokens=300, system=SYSTEM,
            messages=[{"role": "user", "content":
                f"Target: {session.target} Mode: {session.mode.value}\n"
                f"Source: {'Yes' if source_path else 'No'}\n"
                f"Findings: {by_sev}\nTop: {chr(10).join(top)}\n"
                f"Done: {', '.join(done)}\nQueued: {', '.join(queue)}\n"
                f"Continue? Return replan JSON."}])
        replan = json.loads(_clean(resp.content[0].text))
        replan["next_agents"] = [a for a in replan.get("next_agents", [])
                                  if a in [e.value for e in AgentName] and a not in done]
        return replan
    except Exception:
        return {"continue": False}


def _default_agents(session: ScanSession, source_path: Optional[str]) -> list[str]:
    if session.mode == ScanMode.CODE:
        return ["sast_agent", "deps_agent", "logic_agent"] if source_path else []
    elif session.mode == ScanMode.PASSIVE:
        return ["recon_agent", "config_agent", "network_agent"]
    elif session.mode == ScanMode.ACTIVE:
        agents = ["recon_agent", "config_agent", "network_agent"]
        if source_path: agents += ["sast_agent", "deps_agent", "logic_agent"]
        agents.append("nuclei_agent")
        return agents
    return []


def _enrich_intel(findings: list[Finding]) -> list[Finding]:
    enriched = 0
    for f in findings:
        if f.mitre_technique:
            intel = enrich_finding_intel(f.title, f.description, f.mitre_tactic or "", f.mitre_technique or "")
            if intel.get("apt_groups"):
                f.description += f"\n⚠ Used by APT groups: {', '.join(intel['apt_groups'][:3])}"
                enriched += 1
    if enriched: print(f"[ORCHESTRATOR] ATT&CK intel enriched {enriched} findings")
    return findings


def _nvd_check(session: ScanSession, findings: list[Finding]) -> list[Finding]:
    import re
    services = {}
    for f in findings:
        if f.agent in (AgentName.RECON, AgentName.NETWORK, AgentName.CONFIG):
            for service, version in re.findall(r'(\w+)[/\s]+([\d.]+)', f.description or ""):
                if service.lower() not in ("http","the","a","at","on"):
                    services[service.lower()] = version
    if not services: return []
    print(f"[ORCHESTRATOR] NVD checking: {services}")
    nvd_results = scan_service_versions(services)
    nvd_findings = []
    sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
    for item in nvd_results:
        nvd_findings.append(Finding(
            agent=AgentName.RECON,
            title=f"[NVD] {item['cve_id']} — {item['service']} {item['version']}",
            description=f"{item['service']} {item['version']}: {item['description']} (CVSS: {item['cvss_score']})",
            severity=sev_map.get(item["severity"], Severity.MEDIUM),
            cve_id=item["cve_id"],
            mitre_tactic="Initial Access",
            mitre_technique="T1190 — Exploit Public-Facing Application",
            remediation=f"Upgrade {item['service']}. References: {' '.join(item.get('references',[])[:2])}",
        ))
    if nvd_findings: print(f"[ORCHESTRATOR] NVD: {len(nvd_findings)} CVEs found")
    return nvd_findings


def _build_result(session, findings, agents_run):
    by_sev = {}
    for f in findings: by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return ScanResult(session_id=session.session_id, target=session.target, mode=session.mode,
                      findings=findings, total=len(findings), by_severity=by_sev, agents_run=agents_run)


def _summary(result: ScanResult, chains: list) -> str:
    if result.total == 0:
        return "No findings detected. This does not guarantee absence of vulnerabilities."
    top = "\n".join(f"- [{f.severity}] {f.title}: {f.description[:100]}"
                    for f in result.findings[:10])
    chain_txt = "\n".join(f"- [{c.severity}] {c.title}" for c in chains[:3]) if chains else ""
    try:
        resp = client.messages.create(
            model=MODEL, max_tokens=500, system=SYSTEM,
            messages=[{"role": "user", "content":
                f"Write 3-5 sentence blue team executive summary.\n"
                f"Target: {result.target} | Mode: {result.mode} | Total: {result.total}\n"
                f"Severity: {result.by_severity}\nTop findings:\n{top}\n"
                f"{'Chains:\n'+chain_txt if chain_txt else ''}\n"
                f"Lead with critical chains. Defensive next steps only."}])
        return resp.content[0].text.strip()
    except Exception:
        return f"Scan complete. {result.total} findings. Review CRITICAL and HIGH items first."


def _clean(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("```"):
        parts = raw.split("```")
        raw = parts[1] if len(parts) > 1 else raw
        if raw.startswith("json"): raw = raw[4:]
    return raw.strip()
