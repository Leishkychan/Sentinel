# 🛡️ Sentinel — AI-Powered Vulnerability Intelligence Platform

> **Blue team first. Find everything. Exploit nothing. Prove everything.**

Sentinel is an autonomous multi-agent AI security platform that orchestrates specialized agents to discover and validate vulnerabilities across web applications — and stops there. Every finding is backed by real HTTP evidence. No exploitation. No synthetic results. No action without explicit human authorization.

Built and actively used against live authorized targets as part of the [WiCyS Vulnerability Disclosure Program](https://www.wicys.org).

---

## Architecture

```
User (authorized target + mode + --confirm flag)
        │
   Consent & Scope Gate  ← hard stop if target not in APPROVED_TARGETS
        │
   Orchestrator  ← dispatches agents, replans dynamically, enforces iteration ceiling
        │
   ┌────────────────────────────────────────────────────────────┐
   │                    Agent Suite (PROBE mode)                 │
   ├── recon_agent          DNS, tech stack, header analysis     │
   ├── config_agent         Security misconfigurations           │
   ├── network_agent        Network topology, mail servers       │
   ├── probe_agent          Auth bypass, IDOR, rate limiting     │
   ├── js_agent             JS secrets, hidden endpoints         │
   ├── api_agent            GraphQL, Swagger, API auth           │
   ├── disclosure_agent     Sensitive file exposure              │
   ├── injection_agent      SQL/injection conditions (no payloads)│
   ├── auth_scan_agent      Session and auth weakness            │
   ├── wordpress_enum_agent Author enum, xmlrpc, robots.txt      │
   ├── wordpress_agent      WP REST API, user enum, 429-aware    │
   └── salesforce_agent     Experience Cloud, /services/data/    │
        │
   Queen Agent  ← sovereign commander, strategic review
        │
   Alpha Agent(s)  ← autonomous threat investigator, hypothesis engine
        │
   Finding Pipeline  ← CONFIRMED / REFUTED / INCONCLUSIVE / TESTED
        │
   Session Intelligence  ← authoritative state: confirmed_urls, disproven_urls
        │
   Attack Graph + Chain Analysis  ← MITRE ATT&CK mapping, blast radius
        │
   Reporter  ← structured JSON + Markdown, evidence-backed, no hallucinations
```

---

## Scan Modes

| Mode | Agents Active | Notes |
|---|---|---|
| `PASSIVE` | recon, config, network | Read-only observation |
| `CODE` | sast, deps, logic | Source code only, no network |
| `PROBE` | Full 12-agent suite | Active-safe — finds real vulns, no exploitation |
| `ACTIVE` | All agents + nuclei | Requires double confirmation |

---

## Evidence Model

Every confirmed finding requires a real `EvidenceRef` constructed from an actual HTTP response. No synthetic values. No regex-parsed descriptions. No hallucinated confirmations.

```python
EvidenceRef(
    method="GET",
    url="https://target.com/api/Users",
    status_code=200,
    response_type="JSON",       # classified from real Content-Type
    size_bytes=59605,           # real content length
    auth_sent=False,            # explicit, not assumed
    sensitive_fields=["password", "token"],  # matched in response
    record_count=111,           # counted from actual JSON array
    proof_snippet="Array[111]..." # sanitized sample from response
)
```

A finding is `CONFIRMED` only when `is_sufficient_for_confirmation()` passes:
- HTTP 200
- Response type is JSON (not HTML, not EMPTY)
- `size_bytes >= 200`
- `proof_snippet` is present
- `auth_sent == False`

---

## Finding State Machine

```
CONFIRMED    → HTTP 200 + JSON + real evidence passes all confirmation gates
REFUTED      → HTTP 401/403/404, SPA fallback, empty response
INCONCLUSIVE → HTTP 500, timeout, ambiguous
TESTED       → HTTP 200 but not confirmable (HTML, too small, auth sent)
```

State is held in `SessionIntelligence` — the single source of truth for the Reporter, eval harness, and Alpha's dedup logic. Alpha never re-probes a URL already in `confirmed_urls` or `disproven_urls`.

---

## Safety Guarantees

- Every agent calls `validate_action()` before any HTTP request
- No agent can touch a target not in `APPROVED_TARGETS`
- No agent sends exploit payloads, modifies data, or brute forces credentials
- PROBE mode is read-only by design — observation and confirmation only
- Active mode requires explicit `--confirm` flag and second authorization
- All findings require structured HTTP evidence — hallucinations are blocked by the scoring engine
- `MAX_ALPHA_CYCLES = 6` — Alpha investigations are time-bounded

---

## Core Invariants

The codebase enforces these at all times:

1. URL is in exactly ONE of: `confirmed_urls`, `disproven_urls`, `inconclusive_urls`
2. Settled endpoints are removed from `untested_queue`
3. State precedence: `CONFIRMED > DISPROVEN > INCONCLUSIVE`
4. Reporter reads from `SessionIntelligence` only — never from stale summaries
5. No narrative stronger than evidence — AI confidence scores are calibrated against pipeline state

---

## Stack

- **Agent Reasoning:** Claude (`claude-sonnet-4-20250514`) via Anthropic API
- **Agent Framework:** Custom Python — no LangChain/LangGraph dependency
- **Evidence Layer:** `probe_with_evidence()` / `safe_request()` wrappers with scoped TLS
- **Vulnerability Standards:** OWASP ASVS, WSTG, MITRE ATT&CK (835 techniques loaded)
- **CVSS Scoring:** NVD API integration
- **Backend:** Flask / Python
- **Deployment:** Local (Docker optional for Juice Shop demo target)

---

## Authorized Targets

### Demo (local, no authorization required)
```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
```

### Live targets (require explicit written authorization)
Sentinel has been used against:
- **OWASP Juice Shop** — 4 confirmed unauthenticated API endpoints, TP=3, precision 30% (pre-fix baseline; FP-generating bugs in Queen (#5, #7) and eval harness (#9) have since been patched — rerun pending)
- **WiCyS VDP** (`www.wicys.org`, `womenincybersecuritywicys.my.site.com`) — authorized via Bugcrowd, active VDP researcher

**Never run Sentinel against systems you do not own or have explicit written authorization to test.**

---

## Setup

```bash
git clone https://github.com/Leishkychan/Sentinel.git
cd sentinel

python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
# Add ANTHROPIC_API_KEY to .env
```

### Run a scan

```bash
# Set the Python path
$env:PYTHONPATH = "C:\path\to\sentinel"   # Windows PowerShell
export PYTHONPATH=/path/to/sentinel        # Linux/Mac

# Approve target (required — no target probed without explicit approval)
$env:APPROVED_TARGETS = "localhost,127.0.0.1"

# Run
python sentinel/run_scan.py --target http://localhost:3000 --mode PROBE --confirm
```

### Output
```
reports/sentinel_<session_id>_<timestamp>.json   ← structured findings with evidence
reports/sentinel_<session_id>_<timestamp>.md     ← human-readable report
```

---

## Project Status

- [x] Phase 1 — Core pipeline: Orchestrator, Queen, Alpha, findings pipeline
- [x] Phase 2 — Full agent suite: probe, js, api, disclosure, injection, auth_scan
- [x] Phase 3 — Evidence refactor: real EvidenceRef on all confirmed findings
- [x] Phase 4 — Session Intelligence: authoritative state, dedup, stop conditions
- [x] Phase 5 — Tier 1 specialist agents: wordpress_enum, wordpress, salesforce
- [x] Phase 6 — MITRE ATT&CK mapping, CVSS scoring, eval harness, attack chains
- [x] Phase 7 — Phase 5 evidence fix: probe_agent._check_api_endpoints migration
- [ ] Phase 8 — Tier 2 agents: plugin fingerprinter, header auditor, sensitive file probe
- [x] Phase 9 — Severity accuracy: Queen risk verdict from confirmed findings only
- [ ] Phase 10 — Flask UI + full Azure deployment

---

## Author

Built by Leishka Pagan — Security & Cloud Infrastructure Engineer  
[GitHub](https://github.com/Leishkychan) | [Portfolio](https://leishka-pagan.github.io)

---

*Sentinel is a blue team tool. It surfaces vulnerabilities for human review and remediation — never for exploitation. All scan targets require explicit prior written authorization.*
