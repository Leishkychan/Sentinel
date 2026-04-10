"""
sentinel/agents/alpha_agent.py

ALPHA v2 — Autonomous Strategic Threat Investigator.

Full capability set:
  - Hypothesis Scoring Engine (confidence x impact x cost)
  - Attack Graph Builder (findings as nodes, paths to objective)
  - Blast Radius Calculator (quantify actual damage)
  - Self-Correcting Reasoning (learn patterns within session)
  - Defensive Gap Analysis (missing controls per finding)
  - Exploit Probability Scoring (CVSS + context factors)
  - Threat Actor Profiling (match to known APT patterns)
  - Real-Time Threat Intelligence (CVE feeds, cert transparency)
  - Persistent Threat Model (memory across scans via delta)

Alpha NEVER exploits. Alpha ALWAYS reasons defensively.
Alpha reports to Queen. Queen decides what Alpha does next.
"""

import os
import json
import hashlib
from typing import Optional
from dataclasses import dataclass, field
from anthropic import Anthropic
from sentinel.core.models import (
    ScanMode, AgentName, ScanSession, Finding, Severity,
)
from sentinel.core.evidence import probe_with_evidence, EvidenceArtifact
from sentinel.core.pipeline import FindingPipeline, FindingState, NegativeValidation
from sentinel.core.scoring import (
    score_finding, calibrate_ai_decision,
    FindingStatus, VerificationResult, honest_blast_radius,
    _lookup_cvss_definition,
)

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

ALPHA_MODEL    = os.getenv("ALPHA_MODEL", "claude-opus-4-5-20251001")
FALLBACK_MODEL = os.getenv("ORCHESTRATOR_MODEL", "claude-sonnet-4-20250514")

MAX_ALPHA_CYCLES = 10
MIN_FINDINGS     = 2
BLOCKED_METHODS  = {"DELETE", "PUT", "PATCH"}


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class Hypothesis:
    id:         str
    statement:  str
    confidence: float
    impact:     str
    cost:       int
    score:      float = 0.0
    action:     dict  = field(default_factory=dict)
    tested:     bool  = False
    confirmed:  bool  = False

    def calculate_score(self):
        impact_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        self.score = (self.confidence * impact_map.get(self.impact, 1)) / max(self.cost, 1)
        return self.score


@dataclass
class AttackNode:
    finding_id: str
    title:      str
    severity:   str
    enables:    list[str] = field(default_factory=list)


@dataclass
class LearnedPattern:
    pattern:    str
    confidence: float
    example:    str


@dataclass
class AlphaReport:
    target:            str
    total_findings:    int
    critical_count:    int
    attack_graph:      dict
    blast_radius:      dict
    exploit_probs:     list[dict]
    threat_actors:     list[str]
    defensive_gaps:    list[dict]
    threat_narrative:  str
    risk_score:        str
    immediate_actions: list[str]
    confirmed_paths:   list[dict]


ALPHA_SYSTEM = """You are Sentinel Alpha v2 — elite autonomous threat investigator.

HYPOTHESIS SCORING — evidence-based only, no assertion:
  Your confidence claim will be CALIBRATED against measurable evidence.
  A system will check your score against what was actually observed.
  If you claim 0.9 but evidence only supports 0.4, your score becomes 0.4.

  Confidence MUST be based on observable evidence:
  - HTTP 200 confirmed? +0.35
  - Sensitive fields in response? +0.25
  - No auth header required? +0.30
  - Multiple records returned? +0.20
  - Pattern confirmed on 2+ endpoints? +0.20

  Confidence MUST be reduced by uncertainty:
  - Not yet confirmed by direct probe? -0.20
  - Response could be SPA fallback? -0.25
  - Only one observation? -0.10
  - Could be redirect to login? -0.35

  CVSS anchors (use these as your impact basis):
  - Unauthenticated admin access: CVSS 9.8 = CRITICAL
  - SQL injection condition: CVSS 9.8 = CRITICAL
  - Unauthenticated API: CVSS 7.5 = HIGH
  - IDOR: CVSS 6.5 = HIGH
  - JWT none algorithm: CVSS 9.1 = CRITICAL
  - No rate limiting: CVSS 5.3 = MEDIUM

  score = (calibrated_confidence x impact_value) / cost
  impact_value: CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1
  cost: requests needed (1=single probe, 3=agent run)

ATTACK GRAPH: Every finding enables something.
  Unauthenticated endpoint -> data theft, enumeration, admin access
  No rate limiting -> credential stuffing, brute force
  SQL condition -> auth bypass, data extraction
  Build the graph. Find all paths to maximum impact.

BLAST RADIUS: For every CRITICAL finding, estimate:
  How many records? What data types? Worst-case damage?

SELF-CORRECTION: Learn from every result.
  Track patterns. Apply them forward.
  "lowercase /api/ fails -> try capitalized"

THREAT ACTORS: Match findings to TTPs.
  Unauthenticated admin + no rate limit = ransomware profile
  JWT weakness + API enum = credential theft actor

HARD RULES:
  - Never suggest exploitation
  - Only GET, POST, OPTIONS, HEAD in targeted probes
  - Never retry DELETE/PUT/PATCH — they are permanently blocked
  - Never fabricate findings

OUTPUT FORMAT — valid JSON only:

Investigating:
{
  "cycle": N,
  "status": "investigating",
  "hypothesis": {"id": "H001", "statement": "...", "confidence": 0.85, "impact": "CRITICAL", "cost": 1, "score": 3.4},
  "learned_patterns": ["pattern learned"],
  "primary_path": {"action": "targeted_probe|run_agent", "agent": "name", "probe": {"url": "...", "method": "GET"}, "rationale": "why"},
  "fallback_path": {"action": "targeted_probe", "probe": {"url": "...", "method": "GET"}, "rationale": "why"},
  "fallback_path_2": {"action": "targeted_probe", "probe": {"url": "...", "method": "GET"}, "rationale": "why"},
  "blast_radius_estimate": "X records, Y data types"
}

Concluding:
{
  "cycle": N,
  "status": "complete",
  "threat_narrative": "complete picture",
  "attack_paths": [{"path_id": "PATH-001", "title": "...", "severity": "CRITICAL", "steps": [], "confirmed": true, "blast_radius": "...", "break_point": "...", "exploit_probability": 0.95, "threat_actors": []}],
  "defensive_gaps": [{"finding": "...", "missing_controls": ["control1", "control2"]}],
  "exploit_probability_summary": [{"finding": "...", "probability": 0.95, "rationale": "..."}],
  "threat_actor_profile": "who and how",
  "immediate_actions": ["action1", "action2"],
  "risk_score": "CRITICAL"
}
"""


class AlphaAgent:
    """Alpha v2 — Full autonomous threat investigator."""

    def __init__(self, session: ScanSession, source_path: Optional[str] = None,
                 alpha_id: str = "ALPHA-1"):
        self.session           = session
        self.source_path       = source_path
        self.alpha_id          = alpha_id
        self.cycle             = 0
        self.all_findings:     list[Finding] = []
        self.hypotheses:       list[Hypothesis] = []
        self.attack_graph:     dict[str, AttackNode] = {}
        self.learned_patterns: list[LearnedPattern] = []
        self.failed_paths:     set[str] = set()
        self.completed_paths:  set[str] = set()
        self.confirmed_evidence: list[dict] = []  # Probes that returned confirmed data
        self.refuted_paths:    set[str] = set()   # Endpoints confirmed NOT vulnerable
        self.pipeline:         FindingPipeline = FindingPipeline()  # Formal state machine
        self.defensive_gaps:   list[dict] = []
        self.exploit_probs:    list[dict] = []
        self.threat_actors:    list[str] = []
        self.investigation_log: list[dict] = []
        self.report:           Optional[AlphaReport] = None
        self.model             = self._get_best_model()
        print(f"[{self.alpha_id}] Initialized | Model: {self.model}")

    def _get_best_model(self) -> str:
        try:
            client.messages.create(
                model=ALPHA_MODEL, max_tokens=10,
                messages=[{"role": "user", "content": "test"}]
            )
            return ALPHA_MODEL
        except Exception:
            return FALLBACK_MODEL

    def add_findings(self, findings: list[Finding]):
        self.all_findings.extend(findings)
        self._update_attack_graph(findings)

    def think(self) -> dict:
        self.cycle += 1
        print(f"\n[{self.alpha_id}] === Cycle {self.cycle} ===")

        if self.cycle > MAX_ALPHA_CYCLES:
            return self._force_conclusion()

        if len(self.all_findings) < MIN_FINDINGS:
            return {"status": "need_more_data", "cycle": self.cycle}

        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=2500,
                system=ALPHA_SYSTEM,
                messages=[{"role": "user", "content": self._build_prompt()}],
            )
            decision = _parse_json(response.content[0].text.strip())
            # Calibrate AI scores against measurable evidence
            # This prevents hallucinated confidence values
            # Pass confirmed evidence count to calibration
            # More confirmed findings = higher ceiling for confidence
            n_confirmed = len(self.confirmed_evidence)
            decision = calibrate_ai_decision(decision, confirmed_count=n_confirmed)
            self._process_decision(decision)
            return decision
        except Exception as e:
            print(f"[{self.alpha_id}] Think error: {e}")
            return {"status": "error", "cycle": self.cycle}

    def evaluate_result(self, action_id: str, findings: list[Finding],
                        success: bool) -> str:
        if findings:
            self.add_findings(findings)
        self._learn_from_result(action_id, findings, success)

        critical_new = [f for f in findings
                        if f.severity in (Severity.CRITICAL, Severity.HIGH)]

        if success and critical_new:
            self.completed_paths.add(action_id)
            for f in critical_new:
                self._calculate_blast_radius(f)
                # Store as confirmed evidence for future hypothesis calibration
                self.confirmed_evidence.append({
                    "url":     action_id,
                    "finding": f.title,
                    "severity": str(f.severity).split(".")[-1],
                    "description": (f.description or "")[:200],
                })
            return "confirmed"
        elif not success or not findings:
            # Track 401/protected endpoints so we stop retrying them
            if "auth enforced" in str(findings).lower() or not findings:
                self.refuted_paths.add(action_id)
            self.failed_paths.add(action_id)
            return "pivoting"
        return "new_hypothesis"

    def conclude(self) -> dict:
        print(f"\n[{self.alpha_id}] Writing final threat assessment...")
        self._score_all_exploits()
        self._profile_threat_actors()
        self._analyze_defensive_gaps()

        prompt = f"""Complete investigation of {self.session.target}.
Findings: {len(self.all_findings)} | Severity: {self._severity_breakdown()}
Attack graph: {self._format_attack_graph()}
Learned patterns: {[p.pattern for p in self.learned_patterns]}
Exploit probabilities: {json.dumps(self.exploit_probs[:5], indent=2)}
Threat actors: {self.threat_actors}
Findings:
{self._serialize_findings(self.all_findings)}
Write final complete threat assessment. Return complete status JSON."""

        try:
            response = client.messages.create(
                model=self.model, max_tokens=4000,
                system=ALPHA_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            conclusion = _parse_json(response.content[0].text.strip())
            self._build_final_report(conclusion)
            return conclusion
        except Exception as e:
            print(f"[{self.alpha_id}] Conclusion error: {e}")
            return self._force_conclusion()

    def _process_decision(self, decision: dict):
        hyp = decision.get("hypothesis", {})
        if hyp.get("statement"):
            print(f"[{self.alpha_id}] Hypothesis: {hyp['statement'][:120]}")
            conf     = hyp.get("confidence", "?")
            score    = hyp.get("score", "?")
            impact   = hyp.get("impact", "?")
            status   = hyp.get("status", "UNCONFIRMED")
            verif    = hyp.get("verification", "UNTESTED")
            cvss     = hyp.get("cvss_basis")
            vector   = hyp.get("cvss_vector", "")
            # Only show MEASURED blast radius — not AI narrative
            blast    = hyp.get("blast_radius", "unknown — not yet measured")
            # Override hallucinated blast radius — only measured values allowed
            hallucination_phrases = [
                "complete system", "all user", "thousands", "millions", "entire",
                "all records", "complete database", "complete customer", "all data",
                "potentially", "complete application", "complete exposure",
                "full data", "all order", "complete crud", "all account",
            ]
            if any(x in str(blast).lower() for x in hallucination_phrases):
                if self.confirmed_evidence:
                    blast = f"pending measurement — {len(self.confirmed_evidence)} endpoint(s) confirmed so far"
                else:
                    blast = "not yet measured — no confirmed probes this cycle"
            reliable = hyp.get("score_reliable", True)
            calib    = hyp.get("calibration_note", "")

            cvss_str = f"est. CVSS: {cvss} [{vector}]" if cvss else "CVSS: no NVD match"
            status_icon = "✅" if status == "OBSERVED" else "⚠️" if status == "INFERRED" else "❌"
            print(f"[{self.alpha_id}] {status_icon} {status} | {verif}")
            print(f"[{self.alpha_id}] Score: {score} | Conf: {conf} | Impact: {impact} | {cvss_str}")
            print(f"[{self.alpha_id}] Blast radius: {blast}")
            if not reliable and calib:
                print(f"[{self.alpha_id}] ⚠ {calib}")

        patterns = decision.get("learned_patterns", [])
        for p in patterns:
            self._add_pattern(p, 0.8, "from cycle reasoning")

        if decision.get("primary_path"):
            p = decision["primary_path"]
            action = p.get("agent") or p.get("probe", {}).get("url", "?")
            print(f"[{self.alpha_id}] Primary: {p.get('action','?')} -> {action}")
        if decision.get("blast_radius_estimate"):
            print(f"[{self.alpha_id}] Blast radius: {decision['blast_radius_estimate']}")

        self.investigation_log.append({
            "cycle":      self.cycle,
            "hypothesis": hyp.get("statement", ""),
            "score":      hyp.get("score", 0),
            "status":     decision.get("status", ""),
        })

    # ── Attack Graph ──────────────────────────────────────────────────────────

    def _update_attack_graph(self, new_findings: list[Finding]):
        for f in new_findings:
            node_id = hashlib.md5(f.title.encode()).hexdigest()[:8]
            if node_id not in self.attack_graph:
                self.attack_graph[node_id] = AttackNode(
                    finding_id=node_id,
                    title=f.title,
                    severity=str(f.severity).split(".")[-1],
                    enables=self._compute_enables(f),
                )

    def _compute_enables(self, finding: Finding) -> list[str]:
        title = finding.title.lower()
        desc  = (finding.description or "").lower()
        enables = []
        if "unauthenticated" in title or "no auth" in title:
            enables.extend(["data_theft", "account_enumeration", "admin_access"])
        if "rate limit" in title or "no rate" in desc:
            enables.extend(["credential_stuffing", "brute_force"])
        if "sql" in title or "injection" in title:
            enables.extend(["auth_bypass", "data_extraction", "privilege_escalation"])
        if "jwt" in title or "token" in title:
            enables.extend(["session_hijacking", "privilege_escalation"])
        if "cors" in title:
            enables.extend(["csrf", "data_exfiltration"])
        if "idor" in title:
            enables.extend(["data_theft", "account_takeover"])
        if "admin" in title:
            enables.extend(["full_compromise", "system_control"])
        return enables

    def _format_attack_graph(self) -> str:
        lines = []
        for node in list(self.attack_graph.values())[:10]:
            if node.enables:
                lines.append(f"[{node.severity}] {node.title[:50]} -> {', '.join(node.enables[:3])}")
        return "\n".join(lines) if lines else "Building graph..."

    # ── Blast Radius ──────────────────────────────────────────────────────────

    def _calculate_blast_radius(self, finding: Finding):
        """
        Honest blast radius — only reports what was actually measured.
        Never extrapolates to 'thousands of records' without proof.
        """
        import requests
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        url = finding.file_path
        if not url or not url.startswith("http"):
            finding.description += "\n📊 Blast radius: unknown — no URL to probe"
            return
        try:
            from sentinel.core.evidence import probe_with_evidence
            resp, artifact = probe_with_evidence(url, auth_sent=False)

            if resp and artifact.response.status_code == 200:
                er = artifact.response
                # Build measured blast radius from actual evidence
                parts = []
                if er.record_count is not None:
                    parts.append(f"{er.record_count} records returned")
                if er.sensitive_fields:
                    parts.append(f"sensitive fields: {', '.join(er.sensitive_fields[:4])}")
                if er.size_bytes:
                    parts.append(f"{er.size_bytes} bytes")
                parts.append(f"type: {er.response_type}")

                blast = "MEASURED: " + " | ".join(parts) if parts else f"response received ({er.size_bytes}b)"
                finding.description += f"\n📊 Blast radius (measured): {blast}"
                print(f"[{self.alpha_id}] 📊 Blast radius: {blast}")
            else:
                finding.description += "\n📊 Blast radius: endpoint returned no data"
        except Exception as e:
            finding.description += "\n📊 Blast radius: measurement failed"

    def _detect_data_types(self, text: str) -> list[str]:
        text = text.lower()
        types = []
        if any(k in text for k in ["email", "username"]): types.append("user_accounts")
        if any(k in text for k in ["password", "hash"]):  types.append("credentials")
        if any(k in text for k in ["credit", "payment"]): types.append("payment_data")
        if any(k in text for k in ["address", "phone"]):  types.append("PII")
        if any(k in text for k in ["token", "secret"]):   types.append("secrets")
        return types or ["unknown"]

    # ── Self-Correcting Learning ──────────────────────────────────────────────

    def _learn_from_result(self, action_id: str, findings: list[Finding], success: bool):
        if "/api/" not in action_id:
            return
        resource = action_id.split("/api/")[-1].split("?")[0].split("/")[0]
        if not resource:
            return
        if success and findings and resource[0].isupper():
            self._add_pattern(
                f"Capitalize resource names in /api/ endpoints (e.g. /api/{resource})",
                0.8, f"Worked: {action_id}"
            )
        elif not success and resource[0].islower():
            self._add_pattern(
                f"Lowercase /api/ endpoints fail — try /api/{resource.capitalize()}",
                0.7, f"Failed: {action_id}"
            )

    def _add_pattern(self, pattern: str, confidence: float, example: str):
        if pattern not in [p.pattern for p in self.learned_patterns]:
            self.learned_patterns.append(LearnedPattern(pattern, confidence, example))
            print(f"[{self.alpha_id}] Learned: {pattern}")

    # ── Exploit Probability ───────────────────────────────────────────────────

    def _score_all_exploits(self):
        for f in self.all_findings:
            prob = self._calculate_exploit_probability(f)
            self.exploit_probs.append({
                "finding":     f.title[:60],
                "severity":    str(f.severity).split(".")[-1],
                "probability": prob,
                "rationale":   self._exploit_rationale(prob),
            })
        self.exploit_probs.sort(key=lambda x: x["probability"], reverse=True)

    def _calculate_exploit_probability(self, finding: Finding) -> float:
        """
        Evidence-based exploit probability tied to CVSS and observed status.
        UNCONFIRMED findings never reach CRITICAL probability.
        """
        title = finding.title
        desc  = finding.description or ""

        # CVSS anchor
        cvss_def = _lookup_cvss_definition(title, desc)
        cvss = cvss_def["score"] if cvss_def else None

        if cvss:
            base_prob = 0.10 + (cvss / 10.0) * 0.75  # CVSS 9.8 = max 0.835
        else:
            base_prob = 0.25  # conservative — no CVSS match

        desc_lower = desc.lower()

        # Only add for things ACTUALLY observed
        if "blast radius (measured):" in desc_lower:  base_prob += 0.08
        if "records returned" in desc_lower:          base_prob += 0.07
        if "http 200" in desc_lower:                  base_prob += 0.05

        # Reduce for unconfirmed/inferred
        if "spa shell" in desc_lower or "spa fallback" in desc_lower: base_prob -= 0.20
        if "likely spa" in desc_lower:                base_prob -= 0.15
        if "not yet confirmed" in desc_lower:         base_prob -= 0.10
        if "not confirmed" in desc_lower:             base_prob -= 0.10

        return min(max(round(base_prob, 2), 0.05), 0.95)

    def _exploit_rationale(self, prob: float) -> str:
        if prob >= 0.90: return "Trivially exploitable — no auth, no skill required"
        if prob >= 0.75: return "Easy — well-documented technique, minimal skill"
        if prob >= 0.60: return "Moderate — requires some technical knowledge"
        if prob >= 0.40: return "Requires chaining or specific context"
        return "Difficult — advanced skills needed"

    # ── Threat Actor Profiling ────────────────────────────────────────────────

    def _profile_threat_actors(self):
        scores = {
            "Ransomware Groups (FIN8, REvil)":         0,
            "Financial Crime / Data Brokers (FIN7)":   0,
            "Nation-State / Espionage (APT28, APT41)": 0,
            "Opportunistic Attackers":                 0,
        }
        for f in self.all_findings:
            title = f.title.lower()
            if "unauthenticated" in title or "admin" in title:
                scores["Ransomware Groups (FIN8, REvil)"]       += 3
                scores["Opportunistic Attackers"]               += 2
            if "sql" in title or "injection" in title:
                scores["Financial Crime / Data Brokers (FIN7)"] += 3
                scores["Nation-State / Espionage (APT28, APT41)"] += 2
            if "jwt" in title or "credential" in title:
                scores["Nation-State / Espionage (APT28, APT41)"] += 2
                scores["Financial Crime / Data Brokers (FIN7)"]  += 2
            if "data exposed" in title or "api" in title:
                scores["Financial Crime / Data Brokers (FIN7)"] += 3

        self.threat_actors = [
            a for a, s in sorted(scores.items(), key=lambda x: x[1], reverse=True)
            if s > 0
        ][:2]

    # ── Defensive Gap Analysis ────────────────────────────────────────────────

    def _analyze_defensive_gaps(self):
        control_map = {
            "unauthenticated": [
                "Implement JWT/session authentication middleware",
                "Apply auth guard to all non-public endpoints",
                "Return 401 for unauthenticated requests",
            ],
            "rate limit": [
                "Implement rate limiting: max 5 failed auth attempts/min",
                "Return HTTP 429 with Retry-After header",
                "Add progressive delays after repeated failures",
            ],
            "sql": [
                "Replace string concatenation with parameterized queries",
                "Use ORM parameterization (Sequelize, SQLAlchemy)",
                "Suppress SQL errors in production responses",
            ],
            "jwt": [
                "Set exp claim: 15-60 minute token lifetime",
                "Implement refresh token rotation",
                "Reject 'none' algorithm tokens server-side",
                "Use RS256/ES256 instead of HS256",
            ],
            "cors": [
                "Replace wildcard (*) with specific trusted origins",
                "Never allow credentials with wildcard CORS",
            ],
            "https": [
                "Configure 301 redirect HTTP -> HTTPS",
                "Add HSTS: Strict-Transport-Security: max-age=31536000",
            ],
            "idor": [
                "Verify resource.user_id === requesting_user.id on every request",
                "Use UUIDs instead of sequential IDs",
            ],
            "header": [
                "Add Content-Security-Policy header",
                "Add X-Frame-Options: DENY",
                "Add X-Content-Type-Options: nosniff",
            ],
        }
        for f in self.all_findings:
            title = f.title.lower()
            gaps  = []
            for keyword, controls in control_map.items():
                if keyword in title:
                    gaps.extend(controls)
            if gaps:
                self.defensive_gaps.append({
                    "finding":          f.title[:60],
                    "severity":         str(f.severity).split(".")[-1],
                    "missing_controls": list(dict.fromkeys(gaps))[:4],
                })

    # ── Build Final Report ────────────────────────────────────────────────────

    def _build_final_report(self, conclusion: dict):
        bd = self._severity_breakdown()
        self.report = AlphaReport(
            target=self.session.target,
            total_findings=len(self.all_findings),
            critical_count=bd.get("CRITICAL", 0),
            attack_graph={
                nid: {"title": n.title, "enables": n.enables}
                for nid, n in self.attack_graph.items()
            },
            blast_radius={
                f.title[:40]: {"types": self._detect_data_types(f.description or "")}
                for f in self.all_findings
                if str(f.severity).split(".")[-1] == "CRITICAL"
            },
            exploit_probs=self.exploit_probs[:10],
            threat_actors=self.threat_actors,
            defensive_gaps=self.defensive_gaps,
            threat_narrative=conclusion.get("threat_narrative", ""),
            risk_score=conclusion.get("risk_score", "HIGH"),
            immediate_actions=conclusion.get("immediate_actions", []),
            confirmed_paths=conclusion.get("attack_paths", []),
        )

    def _build_prompt(self) -> str:
        patterns = "\n".join(
            f"  - {p.pattern} ({p.confidence:.0%})"
            for p in self.learned_patterns
        ) or "  None yet"

        blocked = list(getattr(self.session, '_alpha_blocked_methods', set()))
        constraints = f"\nBLOCKED (do not retry): {blocked}\n" if blocked else ""

        # Build confirmed evidence summary
        confirmed_str = ""
        if self.confirmed_evidence:
            confirmed_str = "\nCONFIRMED FINDINGS (use these to elevate hypothesis confidence):\n"
            for ce in self.confirmed_evidence[-5:]:
                confirmed_str += f"  ✅ CONFIRMED: {ce['url']} → {ce['finding'][:60]}\n"

        refuted_str = ""
        if self.refuted_paths:
            refuted_str = f"\nCONFIRMED PROTECTED (stop probing these): {list(self.refuted_paths)[-5:]}\n"

        return f"""Target: {self.session.target}
Mode: {self.session.mode.value} | Cycle: {self.cycle}/{MAX_ALPHA_CYCLES}

Learned patterns:
{patterns}
Completed: {list(self.completed_paths)[-5:]}
Failed: {list(self.failed_paths)[-5:]}
{confirmed_str}{refuted_str}{constraints}
Attack graph ({len(self.attack_graph)} nodes):
{self._format_attack_graph()}

Findings ({len(self.all_findings)} total | {self._severity_breakdown()}):
{self._serialize_findings(self.all_findings)}

Score your hypothesis. Pick the highest-scoring path.
Only use GET, POST, OPTIONS, HEAD. Return JSON only."""

    def _serialize_findings(self, findings: list[Finding]) -> str:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_f = sorted(
            findings,
            key=lambda f: order.get(str(f.severity).split(".")[-1], 5)
        )[:20]
        return "\n".join(
            f"[{str(f.severity).split('.')[-1]}] {f.title}: {(f.description or '')[:100]}"
            for f in sorted_f
        )

    def _severity_breakdown(self) -> dict:
        b = {}
        for f in self.all_findings:
            s = str(f.severity).split(".")[-1]
            b[s] = b.get(s, 0) + 1
        return b

    def _force_conclusion(self) -> dict:
        bd = self._severity_breakdown()
        return {
            "status": "complete", "cycle": self.cycle,
            "threat_narrative": (
                f"Investigation of {self.session.target} — {self.cycle} cycles. "
                f"{len(self.all_findings)} findings: {bd}."
            ),
            "attack_paths": [],
            "defensive_gaps": self.defensive_gaps[:5],
            "exploit_probability_summary": self.exploit_probs[:5],
            "threat_actor_profile": ", ".join(self.threat_actors) or "Unknown",
            "immediate_actions": ["Review CRITICAL findings", "Implement authentication"],
            "risk_score": "CRITICAL" if bd.get("CRITICAL", 0) > 0 else "HIGH",
        }


# ── Targeted Probe Executor ───────────────────────────────────────────────────

def execute_targeted_probe(probe: dict, session: ScanSession) -> list[Finding]:
    """
    Execute a targeted probe with full evidence capture.
    Every probe produces a documented request/response artifact.
    """
    from sentinel.core.validator import validate_action
    from urllib.parse import urlparse

    url    = probe.get("url", "")
    method = probe.get("method", "GET").upper()

    if not url:
        return []

    if method in BLOCKED_METHODS:
        if not hasattr(session, '_alpha_blocked_methods'):
            session._alpha_blocked_methods = set()
        session._alpha_blocked_methods.add(method)
        print(f"[ALPHA/PROBE] {method} blocked — read-only mode")
        return []

    host = urlparse(url).hostname or url
    try:
        validate_action(AgentName.PROBE, "http_probe", host, session)
    except Exception as e:
        print(f"[ALPHA/PROBE] Scope: {e}")
        return []

    # Execute with full evidence capture
    resp, artifact = probe_with_evidence(
        url=url,
        method=method,
        headers=probe.get("headers", {}),
        body=probe.get("body"),
        auth_sent=False,
    )

    # Always show the evidence in console
    print(artifact.format_console())

    if resp is None:
        return []

    # Run through formal pipeline — enforces state transitions
    response_data = {
        "status_code":  resp.status_code,
        "content":      resp.text[:5000],
        "size_bytes":   len(resp.content),
        "content_type": resp.headers.get("Content-Type", ""),
        "auth_sent":    False,
    }

    # Get or create pipeline from session
    if not hasattr(session, '_pipeline'):
        session._pipeline = FindingPipeline()

    state, confirmed_bundle, negative = session._pipeline.test(
        url=url,
        method=method,
        response_data=response_data,
        hypothesis=probe.get("hypothesis", ""),
    )

    # Print pipeline verdict
    if state == FindingState.CONFIRMED:
        print(f"[PIPELINE] ✅ CONFIRMED: {url.split('/')[-1]} → {confirmed_bundle.promotion_reason}")
    elif state == FindingState.REFUTED:
        print(f"[PIPELINE] ❌ REFUTED:   {negative.format().splitlines()[0]}")
    else:
        print(f"[PIPELINE] 🔍 TESTED:    HTTP {resp.status_code} — inconclusive")

    return _analyze_probe_response_with_evidence(
        url, resp, artifact, probe.get("hypothesis", ""), state=state
    )


def _analyze_probe_response_with_evidence(url: str, resp,
                                            artifact: EvidenceArtifact,
                                            hypothesis: str,
                                            state: FindingState = FindingState.TESTED) -> list[Finding]:
    """
    Analyze probe response using pipeline state.
    Only creates findings for CONFIRMED state — pipeline enforces this.
    """
    status = resp.status_code
    er     = artifact.response

    # Pipeline already handled REFUTED cases — just skip
    if state == FindingState.REFUTED:
        return []

    # Only CONFIRMED state produces findings
    if state != FindingState.CONFIRMED:
        return []

    # Real data confirmed
    resource = url.rstrip("/").split("/")[-1].split("?")[0] or "endpoint"

    # Build honest description with evidence
    desc_parts = [
        f"CONFIRMED: Unauthenticated {er.response_type} response from {url}.",
        f"Evidence: HTTP {status} {er.status_text}, {er.size_bytes} bytes, "
        f"Content-Type: {er.content_type[:40]}.",
    ]
    if er.record_count is not None:
        desc_parts.append(f"Records returned: {er.record_count}.")
    if er.sensitive_fields:
        desc_parts.append(f"Sensitive fields detected: {', '.join(er.sensitive_fields)}.")
    if er.sample:
        desc_parts.append(f"Sample (sanitized): {er.sample}")

    severity = Severity.CRITICAL if (er.sensitive_fields and er.record_count) else                Severity.HIGH if (er.sensitive_fields or er.record_count) else                Severity.MEDIUM

    return [Finding(
        agent=AgentName.PROBE,
        title=f"[Alpha] Confirmed Unauthenticated Access: /{resource}",
        description=" ".join(desc_parts),
        severity=severity,
        file_path=url,
        mitre_tactic="Collection",
        mitre_technique="T1213 — Data from Information Repositories",
        remediation=(
            "Implement authentication middleware on this endpoint. "
            "Return 401 Unauthorized for unauthenticated requests. "
            "Verify authorization server-side before returning data."
        ),
    )]


def _analyze_probe_response(url: str, resp, hypothesis: str) -> list[Finding]:
    """Legacy — kept for compatibility. Use _analyze_probe_response_with_evidence."""
    if resp.status_code != 200 or len(resp.content) <= 100:
        return []
    resource = url.rstrip("/").split("/")[-1].split("?")[0] or "endpoint"
    return [Finding(
        agent=AgentName.PROBE,
        title=f"[Alpha] Unauthenticated Access: /{resource}",
        description=f"HTTP 200 from {url} without auth. {len(resp.content)} bytes.",
        severity=Severity.HIGH,
        file_path=url,
        mitre_tactic="Collection",
        mitre_technique="T1213 — Data from Information Repositories",
        remediation="Implement authentication on this endpoint.",
    )]


def _parse_json(raw: str) -> dict:
    raw = raw.strip()
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
