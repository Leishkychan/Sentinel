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
from sentinel.agents.queen_agent import QueenAgent

_client = None

def _get_client():
    """Lazy Anthropic client — not created until first use."""
    global _client
    if _client is None:
        _client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    return _client
MODEL  = os.getenv("ORCHESTRATOR_MODEL", "claude-sonnet-4-20250514")
MAX_ITERATIONS = 5

SYSTEM = """You are Sentinel's Orchestrator — a blue team AI security coordinator.
Plan scans, adapt based on findings, think like a defender finding every vulnerability first.

Available agents: sast_agent, deps_agent, logic_agent, config_agent, recon_agent, network_agent, nuclei_agent, probe_agent, js_agent, api_agent, disclosure_agent, injection_agent, auth_scan_agent

Rules:
- Never suggest exploitation. Never fabricate CVEs.
- Only dispatch agents valid for the mode.
- PASSIVE=recon/config/network only. CODE=sast/deps/logic only. PROBE=all probe agents. ACTIVE=all agents.
- In PROBE/ACTIVE mode: probe_agent, js_agent, api_agent, disclosure_agent MUST all run eventually.
- When replanning: you may reorder agents but never permanently drop probe agents.
- If critical findings exist, prioritize agents that reveal blast radius and attack chains.
- Think: "Given what I found, what do I need to run next to understand the full risk?"

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

    # Initialize eval harness and wire to scoring engine
    from sentinel.core.eval_harness import EvalHarness
    eval_harness = EvalHarness(session.target, session.mode.value)
    import sentinel.agents._eval_ref as _eref
    _eref.current_harness = eval_harness

    # Initialize session intelligence (shared between Queen and Alpha)
    from sentinel.core.session_intelligence import SessionIntelligence
    session._session_intel = SessionIntelligence(session.target, session.mode.value)



    all_findings: list[Finding] = []
    agents_run:   list[AgentName] = []
    done:         set = set()
    iteration     = 0

    # PROBE mode always runs all probe agents — don't let Claude skip them
    if session.mode == ScanMode.PROBE:
        queue = _default_agents(session, source_path)
        print(f"[ORCHESTRATOR] PROBE mode — full agent suite: {queue}")
    else:
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

            # Feed findings into session_intel immediately — so the next agent
            # and Alpha never re-probe what this agent already settled
            _populate_intel_from_findings(new_findings, session)

        # Autonomous replanning — Claude decides what to run next based on findings
        if not queue or any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in new_findings):
            replan = _replan(session, source_path, all_findings, done, queue)
            if replan.get("continue") and replan.get("next_agents"):
                adds = [a for a in replan["next_agents"] if a not in done]
                if adds:
                    print(f"[ORCHESTRATOR] Replan → {adds} | {replan.get('reason','')}")
                    queue.extend(adds)

        # Autonomous safety net — for PROBE/ACTIVE, reason about dropped agents
        # Don't just blindly add them — ask Claude if they're still needed given findings
        if session.mode in (ScanMode.PROBE, ScanMode.ACTIVE):
            probe_agents = ["probe_agent", "js_agent", "api_agent", "disclosure_agent"]
            dropped = [a for a in probe_agents if a not in done and a not in queue]
            if dropped and all_findings:
                decision = _should_run_dropped(dropped, all_findings, session)
                for agent, reason in decision.items():
                    if agent not in done and agent not in queue:
                        print(f"[ORCHESTRATOR] Autonomous decision → adding {agent}: {reason}")
                        queue.append(agent)

    all_findings = enrich_all(all_findings)

    # NOTE: session_intel is populated per-agent at line 96 above.
    # No second call needed here — enrichment only adds MITRE fields,
    # it does not change URLs or confirmation state.

    # Enrich with OWASP standards mapping
    from sentinel.core.standards import enrich_finding_with_standards
    for f in all_findings:
        standards = enrich_finding_with_standards(f.title, f.description or "")
        if standards.get("control_family") != "Uncategorized":
            if not f.mitre_tactic or f.mitre_tactic == "Unknown":
                f.mitre_tactic = standards.get("control_family", f.mitre_tactic)
            refs = standards.get("formatted_short", "")
            if refs and refs not in (f.description or ""):
                f.description = (f.description or "") + f"\n📋 {refs}"

    # Deduplicate and group root causes
    all_findings = _deduplicate_findings(all_findings)
    root_causes = _group_root_causes(all_findings, session)
    if root_causes:
        print(f"[ORCHESTRATOR] Root causes: {len(root_causes)} groups")
        for rc in root_causes:
            print(f"  [{rc['severity']}] {rc['title']}: {len(rc['endpoints'])} endpoints")
        # Promote root causes to primary findings — replaces individual endpoint findings
        # with a single grouped finding that names all affected endpoints
        rc_findings = _root_causes_to_findings(root_causes)
        all_findings.extend(rc_findings)
    all_findings = _enrich_intel(all_findings)
    all_findings.extend(_nvd_check(session, all_findings))

    # QUEEN — sovereign commander
    # Queen takes control for PROBE and ACTIVE modes
    # She commands Alphas, correlates findings, delivers the final verdict
    if session.mode in (ScanMode.PROBE, ScanMode.ACTIVE) and all_findings:
        print(f"\n[ORCHESTRATOR] Queen taking command...")
        queen = QueenAgent(session, source_path)
        queen_findings = queen.command(all_findings, done)
        if queen_findings:
            all_findings.extend(queen_findings)
            print(f"[ORCHESTRATOR] Queen contributed {len(queen_findings)} additional findings")

    result = _build_result(session, all_findings, agents_run)

    print(f"[ORCHESTRATOR] Running attack chain analysis...")
    # Wire session onto result so chain engine can read session_intel confirmed URLs
    result._session = session
    chains = analyze_attack_chains(result)

    # Filter: only chains that pass eval validation reach the report
    # eval_harness validates chains against confirmed_urls before scoring
    # We pre-filter here so reporter never sees invalid chains
    intel = getattr(session, '_session_intel', None)
    confirmed_urls = intel.confirmed_urls if intel else set()
    valid_chains = [
        c for c in chains
        if _chain_is_valid(c, confirmed_urls)
    ]
    if len(valid_chains) < len(chains):
        print(f"[CHAIN] Filtered {len(chains) - len(valid_chains)} invalid chains — "
              f"{len(valid_chains)} valid chains remain")
    chains = valid_chains
    result.attack_chains = chains_to_dict(chains)
    for c in chains:
        print(f"  [{c.severity}] {c.title} ({c.confidence})")

    delta = compute_delta(result, session.target)
    result.delta_summary  = delta.summary
    result.delta_markdown = delta_to_markdown(delta)

    result.summary = _summary(result, chains)

    # Surface pipeline summary from session_intel (authoritative)
    if hasattr(session, '_session_intel') and session._session_intel:
        si = session._session_intel
        si_summary = si.get_summary()
        total_probed = si_summary.get('total_requests', 0)
        confirmed    = si_summary.get('confirmed', 0)
        disproven    = si_summary.get('disproven', 0)
        rate         = round(confirmed / max(total_probed, 1), 2)

        print(f"[PIPELINE] Summary: {total_probed} tested | "
              f"{confirmed} confirmed | "
              f"{disproven} refuted | "
              f"confirmation rate: {rate:.0%}")

        result.pipeline_summary = {
            'hypotheses_tested':    total_probed,
            'confirmed_findings':   confirmed,
            'refuted_findings':     disproven,
            'inconclusive':         si_summary.get('inconclusive', 0),
            'confirmation_rate':    rate,
            'probes_prevented':     si_summary.get('probes_prevented', 0),
            'root_causes':          si_summary.get('root_causes', 0),
            'chain_candidates':     si_summary.get('chain_candidates', 0),
            'attack_graph':         si.attack_graph.get_summary() if si.attack_graph else {},
        }
        result.negative_validations = disproven

    # Run eval scoring
    eval_run = eval_harness.score(result)
    print(f"\n[EVAL] {eval_run.format_scorecard()}")
    eval_harness.save_run(eval_run)
    # Store as dict (Pydantic requires serializable types)
    import dataclasses
    result.eval_run = dataclasses.asdict(eval_run) if dataclasses.is_dataclass(eval_run) else {}

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
        elif agent == "probe_agent":
            from sentinel.agents.probe_agent import run_probe_agent
            url = session.target if session.target.startswith("http") else f"http://{session.target}"
            return run_probe_agent(session, url)
        elif agent == "js_agent":
            from sentinel.agents.js_analysis_agent import run_js_agent
            url = session.target if session.target.startswith("http") else f"http://{session.target}"
            return run_js_agent(session, url)
        elif agent == "api_agent":
            from sentinel.agents.api_agent import run_api_agent
            url = session.target if session.target.startswith("http") else f"http://{session.target}"
            return run_api_agent(session, url)
        elif agent == "disclosure_agent":
            from sentinel.agents.disclosure_agent import run_disclosure_agent
            url = session.target if session.target.startswith("http") else f"http://{session.target}"
            return run_disclosure_agent(session, url)
        elif agent == "injection_agent":
            from sentinel.agents.injection_agent import run_injection_agent
            url = session.target if session.target.startswith("http") else f"http://{session.target}"
            return run_injection_agent(session, url)
        elif agent == "auth_scan_agent":
            from sentinel.agents.auth_scan_agent import run_auth_scan_agent
            url = session.target if session.target.startswith("http") else f"http://{session.target}"
            return run_auth_scan_agent(session, url)
        else:
            return []
    except Exception as e:
        print(f"[ORCHESTRATOR] {agent} error: {e}")
        return []


def _initial_plan(session: ScanSession, source_path: Optional[str]) -> dict:
    try:
        resp = _get_client().messages.create(
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
        resp = _get_client().messages.create(
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
    elif session.mode == ScanMode.PROBE:
        return ["recon_agent", "config_agent", "network_agent",
                "probe_agent", "js_agent", "api_agent", "disclosure_agent",
                "injection_agent", "auth_scan_agent"]
    elif session.mode == ScanMode.ACTIVE:
        agents = ["recon_agent", "config_agent", "network_agent",
                  "probe_agent", "js_agent", "api_agent", "disclosure_agent",
                  "injection_agent", "auth_scan_agent"]
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

    # Strict allowlist — only real software names we care about CVEs for
    KNOWN_SERVICES = {
        "nginx", "apache", "iis", "tomcat", "jetty", "node", "nodejs",
        "express", "django", "flask", "rails", "spring", "struts",
        "openssl", "openssh", "wordpress", "drupal", "joomla",
        "mysql", "postgresql", "redis", "mongodb", "elasticsearch",
        "jenkins", "gitlab", "jira", "confluence", "grafana",
        "php", "python", "ruby", "java", "golang",
    }

    # Match "nginx/1.14.0" or "Apache 2.4.1" style version strings only
    VERSION_PATTERN = re.compile(r'\b([\w\-\.]+)[/\s]+([\d]+\.[\d]+[\.[\d]*]*)\b')

    services = {}
    for f in findings:
        if f.agent in (AgentName.RECON, AgentName.NETWORK, AgentName.CONFIG):
            text = (f.title or "") + " " + (f.description or "")
            for service, version in VERSION_PATTERN.findall(text):
                service_clean = service.lower().strip()
                # Must be known service AND have real version (not port numbers)
                try:
                    major = int(version.split(".")[0])
                except Exception:
                    continue
                if (service_clean in KNOWN_SERVICES and
                        len(version) < 15 and
                        major < 100):
                    services[service_clean] = version

    if not services:
        return []
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




def _execute_alpha_action(action: dict, session: ScanSession,
                           source_path: Optional[str],
                           agents_done: set) -> tuple[list[Finding], bool]:
    """Execute a single Alpha-directed action. Returns (findings, success)."""
    action_type = action.get("action", "")

    if action_type == "targeted_probe":
        probe = action.get("probe", {})
        if not probe:
            return [], False
        print(f"[ALPHA] Targeted probe → {probe.get('url', '?')}")
        findings = execute_targeted_probe(probe, session)
        return findings, True

    elif action_type == "run_agent":
        agent_name = action.get("agent", "")
        if not agent_name or agent_name in agents_done:
            return [], False

        print(f"[ALPHA] Directing agent → {agent_name}")
        findings = _dispatch(agent_name, session, source_path)
        agents_done.add(agent_name)
        return findings, len(findings) > 0

    return [], False


def _should_run_dropped(dropped: list[str], findings: list[Finding],
                         session: ScanSession) -> dict[str, str]:
    """
    Autonomous reasoning: given what we found, should we run agents
    that were dropped from the queue?

    Claude reasons about the findings and decides which dropped agents
    are still needed and why — not a blanket "run everything."

    Returns dict of {agent_name: reason_to_run}
    """
    if not dropped or not findings:
        return {}

    # Build context for Claude
    critical_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    finding_summary = "\n".join([
        f"- [{f.severity}] {f.title}: {f.description[:100]}"
        for f in critical_high[:10]
    ])

    agent_purposes = {
        "probe_agent":       "Tests endpoints for auth bypass, IDOR, rate limiting, method tampering",
        "js_agent":          "Analyzes JavaScript for secrets, hidden endpoints, source map exposure",
        "api_agent":         "Tests GraphQL introspection, Swagger exposure, API auth weaknesses",
        "disclosure_agent":  "Checks for sensitive file exposure, stack traces, debug endpoints, directory listing",
    }

    dropped_desc = "\n".join([
        f"- {a}: {agent_purposes.get(a, 'Unknown')}"
        for a in dropped
    ])

    prompt = f"""You are Sentinel's autonomous decision engine.

We found these security issues so far:
{finding_summary}

These agents were dropped from the scan queue and haven't run yet:
{dropped_desc}

For each dropped agent, decide:
1. Is it still relevant given what we found?
2. Would running it reveal additional blast radius or attack vectors?
3. Should it run NOW (before other agents) or can it wait?

Return JSON only:
{{
  "agent_name": "specific reason this agent should run given the findings above",
  "agent_name2": "specific reason"
}}

Only include agents that SHOULD run. If an agent is not relevant, omit it.
If no agents should run, return {{}}.
"""

    try:
        resp = _get_client().messages.create(
            model=MODEL, max_tokens=400, system=SYSTEM,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = _clean(resp.content[0].text)
        decision = json.loads(raw)
        # Validate — only return known agent names
        return {k: v for k, v in decision.items()
                if k in [e.value for e in AgentName]}
    except Exception:
        # Fallback: if Claude fails, use rule-based logic
        result = {}
        titles = " ".join(f.title.lower() for f in findings)

        if "api_agent" in dropped:
            if any(kw in titles for kw in ["unauthenticated", "idor", "admin", "endpoint", "api"]):
                result["api_agent"] = "Critical auth findings require API depth analysis"

        if "disclosure_agent" in dropped:
            if any(kw in titles for kw in ["exposed", "hidden", "javascript", "endpoint", "admin"]):
                result["disclosure_agent"] = "Exposed endpoints found — check for sensitive file disclosure"

        if "js_agent" in dropped:
            if any(kw in titles for kw in ["api", "endpoint", "admin", "token"]):
                result["js_agent"] = "API/admin findings warrant JavaScript source analysis"

        if "probe_agent" in dropped:
            result["probe_agent"] = "Probe agent should always run in PROBE mode"

        return result




def _populate_intel_from_findings(findings: list, session):
    """
    Orchestrator reads structured metadata from findings and populates session_intel.
    This keeps agents pure — they return findings, orchestrator coordinates intel.
    Works for any target, not just Juice Shop.

    Called after EVERY agent dispatch — ensures session_intel stays current
    so Alpha never re-probes what any earlier agent already settled.

    Writes to SessionIntelligence in this priority order:
      - DISPROVEN: for 401/403 and SPA fallback (deterministic HTTP signals)
      - INCONCLUSIVE: for HTTP 500 (deterministic HTTP signal)
      - CONFIRMED: only when f.evidence is present AND passes is_sufficient_for_confirmation()
      - Queue additions: JS-discovered endpoints (not state transitions)
    Any finding without structured evidence that claims confirmation via text alone
    is left as supporting detail only — not promoted into authoritative session state.
    """
    intel = getattr(session, '_session_intel', None)
    if not intel:
        return

    from sentinel.core.session_intelligence import DisproveReason as _DR

    for f in findings:
        url = f.file_path or ""
        if not url or not url.startswith("http"):
            continue

        title = (f.title or "").lower()
        desc  = (f.description or "").lower()

        # DISPROVEN: 401/403 — authentication enforced (deterministic HTTP signal)
        if "401" in desc or "auth: required" in desc or "authentication enforced" in desc:
            if url not in intel.disproven_urls:
                intel.record_disproven(url, _DR.AUTH_ENFORCED)

        # DISPROVEN: SPA shell — client-side route, no server data (deterministic size+type signal)
        elif "spa route" in title or "spa shell" in desc or "spa fallback" in desc:
            if url not in intel.disproven_urls:
                intel.record_disproven(url, _DR.SPA_FALLBACK)

        # INCONCLUSIVE: HTTP 500 — server error, cannot determine safe or unsafe (deterministic)
        elif "500" in desc or "server error" in desc or "inconclusive" in title:
            if url not in intel.inconclusive_urls:
                intel.record_inconclusive(url, reason="HTTP 500 from probe_agent")

        # CONFIRMED: only when f.evidence carries real structured proof from probe_with_evidence.
        # Double-write is prevented by checking confirmed_urls first — record_confirmed is also
        # idempotent, but the check avoids the call entirely when Alpha already settled this URL.
        # If evidence fails is_sufficient_for_confirmation(), the finding is left as supporting
        # detail only — record_inconclusive is NOT called for failed confirmation evidence.
        elif f.evidence is not None and url not in intel.confirmed_urls:
            ok, _ = f.evidence.is_sufficient_for_confirmation()
            if ok:
                intel.record_confirmed(url, f.evidence)
            # else: leave as supporting detail — do not write any state

        # Extract discovered endpoints from JS agent metadata (structured field, not freeform text)
        meta = getattr(f, 'metadata', {}) or {}
        discovered = meta.get('discovered_endpoints', [])
        for ep_url in discovered:
            if (ep_url not in intel.confirmed_urls and
                ep_url not in intel.disproven_urls and
                ep_url not in intel.untested_queue):
                intel.untested_queue.append(ep_url)

    if intel.untested_queue:
        queued = len([u for u in intel.untested_queue
                      if u not in intel.confirmed_urls
                      and u not in intel.disproven_urls])
        if queued:
            print(f"[INTEL] Queued {queued} discovered endpoints for Alpha")



def _root_causes_to_findings(root_causes: list[dict]) -> list[Finding]:
    """
    Convert root cause groups into primary findings.
    Each root cause becomes one finding listing all affected endpoints.
    This is the professional output — not 6 separate /api findings,
    but one root cause with 6 affected endpoints.
    """
    from sentinel.core.models import Severity as _Sev
    rc_findings = []
    sev_map = {"CRITICAL": _Sev.CRITICAL, "HIGH": _Sev.HIGH,
               "MEDIUM": _Sev.MEDIUM, "LOW": _Sev.LOW}

    for rc in root_causes:
        endpoints = rc.get("endpoints", [])
        if len(endpoints) < 2:
            continue  # Only worth surfacing if 2+ endpoints share root cause

        sev = sev_map.get(rc.get("severity", "HIGH"), _Sev.HIGH)
        ep_list = "\n".join(f"  - {ep}" for ep in endpoints[:10])

        rc_findings.append(Finding(
            agent=AgentName.PROBE,
            title=f"[Root Cause] {rc['title']}",
            description=(
                f"Root issue: {rc['title']}\n"
                f"Pattern: {rc.get('pattern', 'unknown')}\n"
                f"Affected endpoints ({len(endpoints)}):\n{ep_list}\n"
                f"Next action: {rc.get('next_action', 'Manual review required')}"
            ),
            severity=sev,
            file_path=endpoints[0] if endpoints else "",
            mitre_tactic="Multiple",
            mitre_technique="Multiple — see individual findings",
            remediation=(
                f"Fix the root cause, not individual endpoints. "
                f"Apply authentication middleware at the framework/router level "
                f"to cover all {len(endpoints)} affected endpoints."
            ),
        ))
    return rc_findings

def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings — same URL + same type = one finding."""
    seen = {}
    unique = []
    for f in findings:
        # Key: finding type + URL (normalized)
        url = (f.file_path or "").split("?")[0].rstrip("/")
        title_key = f.title[:40].lower().replace("[alpha]", "").replace("[probe]", "").strip()
        key = f"{title_key}|{url}"
        if key not in seen:
            seen[key] = True
            unique.append(f)
    
    removed = len(findings) - len(unique)
    if removed:
        print(f"[ORCHESTRATOR] Deduplicated: removed {removed} duplicate findings")
    return unique


def _group_root_causes(findings: list[Finding], session: ScanSession) -> list[dict]:
    """
    Group findings by root cause pattern.
    
    Rules:
    - CONFIRMED endpoints only anchor a root cause group
    - INFERRED (detected, untested) can be listed as candidates separately
    - REFUTED endpoints (401/403) are NEVER included — auth enforced is not a gap
    - Requires 2+ endpoints to form a group
    """
    intel = getattr(session, '_session_intel', None)
    if not intel:
        return []

    confirmed_urls  = intel.confirmed_urls
    disproven_urls  = intel.disproven_urls

    pattern_groups: dict = {}
    for f in findings:
        url   = f.file_path or ""
        title = (f.title or "").lower()
        desc  = (f.description or "").lower()

        # Hard rule: skip anything that was refuted
        if url in disproven_urls:
            continue
        # Hard rule: skip 401/403 findings — auth enforcement is GOOD
        if "401" in desc or "auth: required" in desc or "authentication enforced" in desc:
            continue

        # Classify pattern
        if "unauthenticated" in title or "no auth" in title:
            pattern = "unauthenticated_api"
        elif "rate limit" in title:
            pattern = "no_rate_limiting"
        elif "dangerous" in title and "method" in title:
            pattern = "dangerous_methods"
        elif "sql" in title or "injection" in title:
            pattern = "sql_injection"
        elif "spa route" in title or "spa fallback" in desc:
            pattern = "spa_fallback"
        else:
            continue

        if pattern not in pattern_groups:
            pattern_groups[pattern] = {
                "confirmed": [],
                "inferred":  [],
                "severity":  str(f.severity).split(".")[-1],
            }

        if url in confirmed_urls:
            if url not in pattern_groups[pattern]["confirmed"]:
                pattern_groups[pattern]["confirmed"].append(url)
        else:
            if url not in pattern_groups[pattern]["inferred"]:
                pattern_groups[pattern]["inferred"].append(url)

    # Build root cause dicts
    # Only include groups with at least 1 confirmed endpoint
    # NOTE: intel.root_causes is already populated by record_confirmed → _update_root_cause
    # Do NOT call _update_root_cause here with synthetic evidence — that would double-count
    # and write fake evidence into the authoritative state layer.
    # This function reads from intel.root_causes, it does not write to it.
    _ = pattern_groups  # pattern_groups is used above to build confirmed/inferred groups

    return [
        {
            "root_id":   rc.root_id,
            "title":     rc.title,
            "severity":  rc.severity,
            "pattern":   rc.pattern,
            "endpoints": rc.endpoints,
            "next_action": rc.next_action,
        }
        for rc in intel.root_causes
    ]


def _chain_is_valid(chain, confirmed_urls: set) -> bool:
    """
    A chain is valid only if it references confirmed finding URLs.
    Chains with no finding_ids or unconfirmed URLs are invalid — never reach reporter.
    """
    import re
    attack_path = chain.attack_path if hasattr(chain, 'attack_path') else []
    # Extract URLs from attack path steps
    path_urls = []
    for step in attack_path:
        path_urls.extend(re.findall(r'https?://[^\s\'"]+', str(step)))

    if path_urls:
        return all(
            any(confirmed in url or url in confirmed for confirmed in confirmed_urls)
            for url in path_urls
        )
    # No URLs in path — require HIGH confidence
    confidence = chain.confidence if hasattr(chain, 'confidence') else ''
    return confidence == 'HIGH'


def _build_result(session, findings, agents_run):
    by_sev = {}
    for f in findings: by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return ScanResult(session_id=session.session_id, target=session.target, mode=session.mode,
                      findings=findings, total=len(findings), by_severity=by_sev, agents_run=agents_run)


def _summary(result: ScanResult, chains: list) -> str:
    session       = getattr(result, '_session', None)
    intel         = getattr(session, '_session_intel', None) if session else None
    confirmed_urls = intel.confirmed_urls if intel else set()

    # Build confirmed findings list — this is the ground truth for the summary
    confirmed_findings = [
        f for f in result.findings
        if f.file_path and f.file_path in confirmed_urls
    ]
    inferred_findings = [
        f for f in result.findings
        if f not in confirmed_findings
        and str(f.severity).split(".")[-1].upper() not in ("INFO",)
    ]

    # Fallback summary that doesn't require an API call
    # Used if Claude call fails — must mention actual confirmed findings
    if confirmed_findings:
        top_confirmed = confirmed_findings[0]
        desc_snippet  = (top_confirmed.description or "")[:120].split("\n")[0]
        fallback = (
            f"Scan confirmed {len(confirmed_findings)} vulnerabilit"
            f"{'y' if len(confirmed_findings)==1 else 'ies'} at {result.target}. "
            f"Top confirmed: [{str(top_confirmed.severity).split('.')[-1]}] "
            f"{top_confirmed.title} — {desc_snippet}. "
            f"{len(inferred_findings)} additional conditions detected but not confirmed. "
            f"Review confirmed findings first."
        )
    else:
        fallback = (
            f"Scan complete. {result.total} findings at {result.target}. "
            f"No findings met confirmation criteria this run. "
            f"{len(inferred_findings)} conditions detected but unverified."
        )

    if result.total == 0:
        return "No findings detected. This does not guarantee absence of vulnerabilities."

    confirmed_top = "\n".join(
        f"[CONFIRMED] [{str(f.severity).split('.')[-1]}] {f.title}: "
        f"{(f.description or '')[:120].split(chr(10))[0]}"
        for f in confirmed_findings[:6]
    ) or "No confirmed findings this scan."

    inferred_top = "\n".join(
        f"[UNVERIFIED] [{str(f.severity).split('.')[-1]}] {f.title}"
        for f in inferred_findings[:4]
    ) or ""

    chain_txt = "\n".join(
        f"- [{getattr(c, 'severity', c.get('severity','?') if isinstance(c, dict) else '?')}] "
        f"{getattr(c, 'title', c.get('title','?') if isinstance(c, dict) else '?')}"
        for c in chains[:3]
    ) if chains else ""

    SUMMARY_SYSTEM = (
        "You are a blue team security analyst writing an executive summary. "
        "Respond with plain prose only — 3 to 5 sentences. "
        "No JSON, no markdown headers, no bullet points. "
        "Start directly with your assessment."
    )
    try:
        resp = _get_client().messages.create(
            model=MODEL, max_tokens=400, system=SUMMARY_SYSTEM,
            messages=[{"role": "user", "content":
                f"Target: {result.target} | Mode: {result.mode}\n\n"
                f"CONFIRMED findings (proven — lead with these):\n{confirmed_top}\n\n"
                f"UNVERIFIED conditions (mention as unverified only):\n{inferred_top}\n"
                f"{'Confirmed chains:\n'+chain_txt if chain_txt else ''}\n\n"
                f"STRICT RULES:\n"
                f"- Your first sentence MUST reference a specific confirmed finding by name\n"
                f"- If no confirmed findings exist, say so explicitly\n"
                f"- Never say 'systematic' unless 3+ confirmed findings share a pattern\n"
                f"- Never say 'across all identified endpoints' — only speak to confirmed ones\n"
                f"- Never say 'immediate implementation across all API endpoints' — scope to confirmed only\n"
                f"- Say 'four confirmed endpoints' not 'multiple endpoints' — use the exact count\n"
                f"- SPA shell routes are NOT admin access — never claim admin access from them\n"
                f"- 401 = auth IS enforced — never say auth is missing for those endpoints\n"
                f"- Blast radius: only cite measured numbers (111 records), never estimates\n"
                f"- Scope all remediation language to confirmed findings only — not inferred ones"}])
        return resp.content[0].text.strip()
    except Exception:
        return fallback


def _clean(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("```"):
        parts = raw.split("```")
        raw = parts[1] if len(parts) > 1 else raw
        if raw.startswith("json"): raw = raw[4:]
    return raw.strip()
