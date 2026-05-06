# Sentinel — Architecture and Structure

## Project Layout

```
sentinel/                          ← outer project root
├── run_scan.py                    ← CLI entry point
├── setup.py
├── requirements.txt
├── README.md
├── .env.example
└── sentinel/                      ← inner package
    ├── __init__.py
    │
    ├── core/                      ← shared infrastructure
    │   ├── models.py              ← ScanMode, Finding, ScanResult, enums
    │   ├── validator.py           ← validate_action() — action-level safety gate
    │   ├── pipeline.py            ← formal finding state machine (HYPOTHESIS→CONFIRMED)
    │   ├── scoring.py             ← evidence-based confidence (CVSS-anchored)
    │   ├── evidence.py            ← request/response artifact capture
    │   ├── standards.py           ← OWASP ASVS/WSTG mapping engine
    │   ├── policy.py              ← policy enforcement gates
    │   ├── eval_harness.py        ← benchmarking and eval tracking
    │   ├── attack_chains.py       ← chain analysis (CONFIRMED findings only)
    │   ├── mitre.py               ← MITRE ATT&CK static mappings
    │   ├── threat_intel.py        ← live ATT&CK data (835 techniques, cached)
    │   ├── nvd_lookup.py          ← NVD CVE API v2 lookup
    │   ├── audit.py               ← append-only JSONL audit log
    │   ├── auth_context.py        ← authentication context and JWT analysis
    │   └── delta.py               ← cross-scan diffing and baseline comparison
    │
    ├── agents/                    ← all AI agents
    │   ├── queen_agent.py         ← sovereign commander (PROBE/ACTIVE)
    │   ├── alpha_agent.py         ← autonomous threat investigator
    │   ├── orchestrator.py        ← iterative agent dispatcher
    │   ├── probe_agent.py         ← endpoint/auth/IDOR probing
    │   ├── js_analysis_agent.py   ← JS secrets, source maps, hidden endpoints
    │   ├── api_agent.py           ← GraphQL, Swagger, API auth analysis
    │   ├── disclosure_agent.py    ← sensitive files, stack traces, debug endpoints
    │   ├── injection_agent.py     ← SQL/XSS condition detection (no payloads)
    │   ├── auth_scan_agent.py     ← authenticated IDOR, privilege escalation
    │   ├── config_agent.py        ← security headers, CORS, cookies
    │   ├── recon_agent.py         ← DNS, WHOIS, HTTP headers, port scan
    │   ├── network_agent.py       ← topology, subdomain enum, service exposure
    │   ├── sast_agent.py          ← Bandit, Semgrep, TruffleHog
    │   ├── deps_agent.py          ← pip-audit, npm audit, govulncheck
    │   ├── logic_agent.py         ← Claude-powered business logic analysis
    │   ├── nuclei_agent.py        ← template-based scanning (ACTIVE only)
    │   └── reporter.py            ← JSON + Markdown report generation
    │
    ├── api/                       ← Flask REST API
    │   ├── app.py                 ← /sessions, /scans, /audit endpoints
    │   └── templates/index.html   ← dark terminal web UI
    │
    └── tests/
        └── (no test files currently in repo)
```

## Data Flow

```
1. User runs: py run_scan.py --target URL --mode PROBE --confirm

2. ScanSession created with:
   - target, mode, approved=True
   - approved_targets list

3. PolicyGate initialized for mode:
   - PROBE: 300 max requests, GET/POST/OPTIONS only, no exploit payloads

4. EvalHarness initialized:
   - Loads known vulnerabilities for target app
   - Starts timer

5. Orchestrator dispatches agents based on mode:
   PROBE default: [recon, config, network, probe, js, api, disclosure, injection, auth_scan]

6. Each agent:
   a. Calls validate_action() — safety gate
   b. Executes probes via probe_with_evidence() — captures artifacts
   c. Runs probes through FindingPipeline.test() — enforces state transitions
   d. Returns list[Finding] with evidence attached

7. After agents: Queen takes command
   a. Reviews all findings
   b. Spawns Alpha-1 for strategic investigation
   c. Alpha thinks in cycles:
      - score_alpha_hypothesis() — CVSS-anchored calibration
      - execute_targeted_probe() — evidence capture
      - evaluate_result() — state update, pattern learning
   d. Queen reviews Alpha results
   e. Spawns more Alphas for high-priority objectives
   f. Delivers final verdict

8. Post-processing:
   - enrich_all() — MITRE ATT&CK tagging
   - enrich_finding_with_standards() — ASVS/WSTG mapping
   - _nvd_check() — CVE lookup for detected services
   - analyze_attack_chains() — CONFIRMED findings only
   - compute_delta() — compare to baseline

9. Eval scoring:
   - eval_harness.score(result) — precision/recall/confirmation rate
   - Pipeline summary: confirmed/refuted/hypothesis counts

10. Report generation:
    - JSON report with full evidence
    - Markdown report with pipeline summary + negative validations
    - Eval run saved to reports/eval/
```

## Key Design Principles

### 1. Evidence before claim
No finding is CONFIRMED without:
- Actual HTTP request sent
- Actual HTTP response received
- Response meeting all promotion criteria
- Sanitized proof snippet attached

### 2. Pipeline over convention
State transitions are enforced by code, not by AI judgment.
The AI proposes. The pipeline decides.

### 3. Honest uncertainty
- UNCONFIRMED: max confidence 0.45
- INFERRED: max confidence 0.65
- OBSERVED+CONFIRMED: CVSS-anchored score
- Hallucination: flagged and adjusted down

### 4. Negative validation is explicit
"NOT VULNERABLE" is a first-class result.
The system explicitly records what was tested and found clean.

### 5. Standards-aware output
Findings are enriched with ASVS/WSTG references via best-effort keyword mapping.
Coverage is partial — approximately 10 control families are mapped.
Output includes structured `asvs_refs`, `wstg_refs`, and `control_family` fields
when a match is found. Gaps exist for uncommon or framework-specific findings.

### 6. Policy over convention
Policy gates are architectural, not guidelines.
Violations raise exceptions — they are never silently bypassed.

## Safety Layers

```
Layer 1: Policy Gate (session-level)
  - Initialized per scan via get_policy() in run_orchestrator
  - Rate limits enforced at safe_request/probe_with_evidence via ContextVar
  - PolicyViolation raised when per-endpoint or total budget exceeded

Layer 2: Validator (action-level)
  - validate_action() called before every agent action
  - HARDCODED_BLOCKS cannot be overridden by any mode or session
  - Mode permissions strictly enforced
  - Payload-shape inspector blocks exploit-shaped requests at HTTP chokepoints

Layer 3: Pipeline (finding-level)
  - Only OBSERVED+CONFIRMED findings become real findings
  - SPA fallback classified as REFUTED
  - Evidence required: real EvidenceRef from actual HTTP response

Layer 4: Evidence requirement
  - CONFIRMED requires proof_snippet (real response sample)
  - is_sufficient_for_confirmation() must pass before state write

Layer 5: Consent gate (scan-level)
  - session.approved must be True to proceed
  - ACTIVE mode requires second explicit confirmation
```

## Extending Sentinel

### Adding a new agent
1. Create `agents/your_agent.py` with `run_your_agent(session, target) -> list[Finding]`
2. Add `YOUR_AGENT = "your_agent"` to `AgentName` enum in `core/models.py`
3. Add allowed actions to `core/validator.py` MODE_PERMISSIONS
4. Add dispatch case to `agents/orchestrator.py _dispatch()`
5. Add to `_default_agents()` for appropriate modes
6. Add to `agents/__init__.py`

### Adding a new standards mapping
Add entry to `STANDARDS_DB` in `core/standards.py` following the `ControlMapping` schema.
Add detection logic to `map_finding()`.

### Adding eval targets
Add known vulnerabilities to `KNOWN_VULNS` in `core/eval_harness.py`.
Run scans against the target and track precision/recall over time.
