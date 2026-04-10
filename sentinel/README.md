# 🛡️ Sentinel — AI Security Reasoning Platform

> **Blue team first. Find everything. Exploit nothing. Prove everything.**

Sentinel is not a vulnerability scanner.
It is a **controlled AI security reasoning system** that discovers, verifies, and documents security weaknesses under evidence and policy constraints.

The difference matters:
- A scanner finds things and reports them.
- Sentinel finds things, tests them, confirms them with evidence, maps them to standards, and explains what they mean for defenders.

---

## What Makes Sentinel Different

| Capability | Sentinel | Traditional Scanner |
|---|---|---|
| Findings require evidence | ✅ Enforced | ❌ Often inferred |
| Standards mapping (ASVS/WSTG) | ✅ Every finding | ❌ Rarely |
| Negative validation | ✅ Explicit NOT VULNERABLE records | ❌ Silently skipped |
| Hallucination detection | ✅ Built-in calibration engine | ❌ N/A |
| Policy enforcement | ✅ Architecture-level gates | ❌ Convention only |
| Autonomous reasoning | ✅ Queen → Alpha hierarchy | ❌ Static rule engine |
| Reproducible findings | ✅ Request/response artifacts | ❌ Often not |

---

## Architecture

```
USER
  ↓  run_scan.py --mode PROBE --confirm
SENTINEL
  ↓
POLICY GATE ← enforces allowed methods, payload classes, request budget
  ↓
QUEEN (sovereign commander — PROBE/ACTIVE modes)
  ↓ commands
  ├── ALPHA-1 (autonomous threat investigator)
  │     ├── Hypothesis scoring (CVSS-anchored, not AI assertion)
  │     ├── Attack graph builder
  │     ├── Blast radius calculator (measured, not estimated)
  │     ├── Self-correcting reasoning (learns within session)
  │     ├── Defensive gap analysis
  │     ├── Exploit probability scoring
  │     └── Threat actor profiling
  │
  ↓ directs
ORCHESTRATOR (iterative agent dispatcher)
  ↓
AGENTS
  ├── recon_agent       Passive recon, DNS, HTTP headers
  ├── config_agent      Security headers, CORS, cookies
  ├── network_agent     Port exposure, subdomain enum
  ├── probe_agent       Endpoint discovery, auth weakness, IDOR
  ├── js_agent          JS secrets, source maps, hidden endpoints
  ├── api_agent         GraphQL, Swagger, API auth analysis
  ├── disclosure_agent  Sensitive files, stack traces, debug endpoints
  ├── injection_agent   SQL/XSS condition detection (no payloads)
  ├── auth_scan_agent   Authenticated IDOR, privilege escalation
  ├── sast_agent        Static analysis (Bandit, Semgrep, TruffleHog)
  ├── deps_agent        CVE scanning (pip-audit, npm audit)
  ├── logic_agent       Business logic flaws (Claude-powered)
  └── nuclei_agent      Template-based scanning (ACTIVE mode only)
  ↓
FINDING PIPELINE (formal state machine)
  HYPOTHESIS → TESTED → CONFIRMED | REFUTED
  ↓
STANDARDS ENGINE
  ASVS + WSTG mapping for every finding
  ↓
EVAL HARNESS
  Precision, recall, confirmation rate, evidence coverage
```

---

## Scan Modes

| Mode | Agents | Use Case |
|---|---|---|
| `PASSIVE` | recon, config, network | Initial surface mapping |
| `CODE` | sast, deps, logic | Source code review |
| `PROBE` | All + Queen + Alpha | Active-safe vulnerability discovery |
| `ACTIVE` | Everything + Nuclei | Full scan (double confirmation required) |

---

## The Finding Pipeline

Every finding passes through a formal state machine:

```
HYPOTHESIS
  AI proposes something to investigate
  Confidence: 0.25 max (no evidence)
  ↓
TESTED
  HTTP request sent, response received, metadata captured
  Confidence: context-dependent
  ↓
CONFIRMED                    REFUTED
  All criteria met:            Any of:
  - HTTP 200                   - HTTP 401/403 → AUTH_ENFORCED
  - JSON response              - HTML ~75KB  → SPA_FALLBACK
  - No auth header sent        - HTTP 404    → NOT_FOUND
  - Size > 200 bytes           - HTTP 500    → SERVER_ERROR
  - Not SPA shell              - No response → NO_RESPONSE
  ↓
Evidence bundle attached:
  - Request record (method, url, auth_sent)
  - Response record (status, type, size, records, sensitive fields)
  - Proof snippet (sanitized sample)
  - Promotion reason
```

Nothing advances state without meeting these criteria. No exceptions.

---

## Standards Mapping

Every confirmed finding maps to:

```
Control Family: Authentication
ASVS V2.2.1 (L1) — Anti-Automation Controls
  Requirement: Verify anti-automation controls are effective at
               mitigating breached credential testing.
WSTG-AUTHN-03 — Testing for Weak Lock Out Mechanism
Test Intent:   Validate that the auth endpoint implements rate
               limiting to prevent credential stuffing attacks.
Verification:  Send 6 rapid failed login attempts. Verify HTTP
               429 is returned on the 6th attempt.
Falsification: If HTTP 429 is returned before 10 attempts,
               rate limiting is operational.
Exploitability: Medium — requires automation but no special skill.
Business Impact: Account takeover via credential stuffing.
```

---

## Safety Architecture

```
5 layers of safety:

1. Policy Gate (architecture-level)
   - DELETE/PUT/PATCH permanently blocked in PASSIVE/PROBE
   - Max 300 requests per PROBE scan
   - Max 5 requests per endpoint
   - No exploit payloads in any mode

2. Validator (action-level)
   - Every agent action passes through validate_action()
   - HARDCODED_BLOCKS: exploit, reverse_shell, brute_force, etc.
   - Mode permissions: strict allowlist per mode

3. Pipeline (finding-level)
   - CONFIRMED requires all criteria met
   - Hallucination detection flags AI overconfidence
   - SPA shell always REFUTED

4. Evidence requirement
   - Every CONFIRMED finding has request/response/proof
   - Blast radius is measured, not estimated

5. Consent gate (session-level)
   - session.approved must be True
   - ACTIVE mode requires typed confirmation phrase
```

---

## Evidence Standards

A finding is only as good as its evidence.

### What CONFIRMED means:
```
Request:  GET http://target/api/endpoint
Auth sent: NO
Status:   200 OK
Type:     JSON (59,605 bytes)
Records:  111 returned
Sensitive: password, token, apikey
Proof:    Array[111], keys: ['id','name','solved','password'] | ⚠ Contains: password
State:    CONFIRMED
Reason:   HTTP 200 | JSON | 59605b | No auth | 111 records | Sensitive: password
```

### What NOT VULNERABLE means:
```
NOT VULNERABLE: /admin
  Reason: SPA fallback — HTML shell, no privileged data
  Evidence: HTTP 200 OK | 75,002 bytes | HTML

NOT VULNERABLE: /api/users
  Reason: Authentication enforced — 401/403 returned
  Evidence: HTTP 401 Unauthorized | 972 bytes | HTML
```

---

## Evaluation and Benchmarking

Sentinel tracks its own performance:

```
╔══ Eval Run: EVAL-20260410-085629 ══╗
  Target:  http://localhost:3000
  Mode:    PROBE
  Duration: 95.2s

  Detection Quality:
    True positives:      7
    False positives:     2
    Precision:           78%
    Recall:              70%

  Pipeline Quality:
    Hypotheses tested:   28
    Confirmed findings:  4
    Refuted (NOT vuln):  14
    Confirmation rate:   14%

  Evidence Quality:
    With evidence:       4/4
    With standards map:  4/4
    Hallucinations blkd: 8
    Time to 1st confirm: 12.3s

  Chain Quality:
    Confirmed chains:    2
    Hallucinated chains: 0
╚═══════════════════════════════════╝
```

Lab targets for eval:
- OWASP Juice Shop (Node.js/Angular) — 10 known vulns mapped
- VAmPI (Python, OWASP API Top 10) — coming
- WebGoat (Java/J2EE) — coming
- DVWA (PHP/MySQL) — coming

---

## Core Modules

| Module | Purpose |
|---|---|
| `core/pipeline.py` | Formal finding state machine |
| `core/scoring.py` | Evidence-based confidence (CVSS-anchored) |
| `core/evidence.py` | Request/response artifact capture |
| `core/standards.py` | OWASP ASVS/WSTG mapping engine |
| `core/policy.py` | Policy enforcement gates |
| `core/eval_harness.py` | Benchmarking and eval tracking |
| `core/models.py` | ScanMode, Finding, ScanResult schemas |
| `core/validator.py` | Action-level safety gate |
| `core/attack_chains.py` | Chain analysis (CONFIRMED only) |
| `core/mitre.py` | MITRE ATT&CK mapping |
| `core/threat_intel.py` | Live ATT&CK data (835 techniques) |
| `core/nvd_lookup.py` | NVD CVE lookup |
| `core/audit.py` | Immutable audit log |
| `core/auth_context.py` | Authentication context management |
| `core/delta.py` | Cross-scan diffing |
| `agents/queen_agent.py` | Sovereign commander |
| `agents/alpha_agent.py` | Autonomous threat investigator |
| `agents/orchestrator.py` | Iterative agent dispatcher |
| `agents/probe_agent.py` | Endpoint/auth/IDOR probing |
| `agents/injection_agent.py` | Injection condition detection |
| `agents/auth_scan_agent.py` | Authenticated vulnerability scanning |

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/Leishkychan/Sentinel.git
cd sentinel
pip install -e .
cp .env.example .env
# Add ANTHROPIC_API_KEY to .env

# Run against Juice Shop (Docker)
docker run -d -p 3000:3000 bkimminich/juice-shop

# PASSIVE scan (read-only)
py run_scan.py --target http://localhost:3000 --mode PASSIVE --confirm

# PROBE scan (full Queen + Alpha pipeline)
py run_scan.py --target http://localhost:3000 --mode PROBE --confirm
```

---

## Roadmap

### Phase 2 (current) — Verification Engine
- [x] Finding pipeline with formal state transitions
- [x] Evidence-first: every confirmed finding has request/response/proof
- [x] OWASP ASVS/WSTG standards mapping
- [x] Policy enforcement layer
- [x] Negative validation (explicit NOT VULNERABLE records)
- [x] Queen → Alpha autonomous reasoning hierarchy
- [x] Hallucination detection and calibration
- [x] Evaluation harness and benchmarking
- [ ] Defender modes (gap analysis, regression, drift detection)
- [ ] Multi-run memory and diffing
- [ ] VAmPI, WebGoat, DVWA eval targets

### Phase 3 — APEX (Multi-organizational)
- [ ] APEX: multi-Queen coordination
- [ ] Cross-target correlation
- [ ] Organizational risk posture
- [ ] Remediation tracking
- [ ] Executive threat briefing

---

## Ethics and Boundaries

Sentinel is a **blue team tool**. It is designed to help defenders understand and fix vulnerabilities — not to exploit them.

Hard boundaries that cannot be changed:
- No exploit payloads in any mode
- No credential brute force
- No destructive HTTP methods
- No persistence actions
- No exfiltration of real data
- Targets must be explicitly authorized

**Never run Sentinel against systems you do not own or have explicit written authorization to test.**

---

*Built by Leishka — [github.com/Leishkychan](https://github.com/Leishkychan)*
