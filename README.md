# 🛡️ Sentinel — AI-Powered Vulnerability Intelligence Platform

> **Blue team first. Find everything. Exploit nothing.**

Sentinel is an autonomous multi-agent AI system that orchestrates specialized security sub-agents to discover vulnerabilities across web applications, codebases, and live systems — and stops there. No exploitation. No remediation. No autonomous action without explicit human authorization.

Built as a portfolio demonstration of responsible AI security tooling.

---

## Architecture

```
User (authorized target + mode)
        │
   Consent & Scope Gate  ← hard stop if target not approved
        │
   Orchestrator Agent (Claude)  ← plans, dispatches, never executes
        │
   ┌────┴────────────────────────────────┐
   │         Sub-Agents (scoped)         │
   ├── SAST Agent     (code analysis)    │
   ├── Deps Agent     (CVE matching)     │
   ├── Config Agent   (misconfiguration) │
   └── Recon Agent    (passive recon)    │
        │
   Findings Aggregator  ← dedup, MITRE tag, CVSS score
        │
   Report Agent  ← structured JSON + markdown, no exploit steps
        │
   Audit Log (append-only)
```

## Scan Modes

| Mode | Agents Active | Requires |
|---|---|---|
| `PASSIVE` | Recon, Config | Single authorization |
| `CODE` | SAST, Deps | Single authorization |
| `ACTIVE` | All agents | Double confirmation |

## Safety Guarantees

- Every agent action passes through `validate_action()` before execution
- No agent can touch a target not in the approved scope list
- No agent has tools that write, modify, or exploit
- All actions are logged immutably — nothing is deletable mid-session
- Active mode requires explicit second confirmation before any network probing

## Stack

- **Orchestrator:** Claude (claude-sonnet-4-20250514) via Anthropic API
- **Agent Framework:** LangGraph
- **SAST:** Bandit, Semgrep
- **Dependency Scanning:** pip-audit, osv-scanner
- **Secrets Detection:** TruffleHog
- **Recon:** nmap (passive flags), whatweb
- **Backend:** Flask
- **Audit Storage:** Azure Cosmos DB
- **Deployment:** Azure Container Apps

## Demo Targets (Safe & Legal)

All demo runs use intentionally vulnerable applications:
- [DVWA](https://github.com/digininja/DVWA) — Damn Vulnerable Web App
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)
- [WebGoat](https://github.com/WebGoat/WebGoat)

**Never run Sentinel against systems you do not own or have explicit written authorization to test.**

## Project Status

- [x] Phase 1 — Core pipeline (Orchestrator + SAST + Report + Audit)
- [ ] Phase 2 — Deps, Config agents + MITRE tagging
- [ ] Phase 3 — Active mode + Recon agent
- [ ] Phase 4 — Flask UI + Azure deployment

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/sentinel.git
cd sentinel
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Add your Anthropic API key to .env
python -m sentinel.api.app
```

## Author

Built by Leishka — Software Engineer  
[GitHub](https://github.com/Leishkychan) 

---

*Sentinel is a blue team tool. It is designed to surface vulnerabilities for remediation, not exploitation. All scan targets require explicit prior authorization.*
