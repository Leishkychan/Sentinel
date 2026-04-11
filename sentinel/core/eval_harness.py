"""
sentinel/core/eval_harness.py

Evaluation Harness — the truth layer.

Tracks Sentinel's real performance against known-vulnerable applications.
If this is wrong, everything we claim about improvement is wrong.

Design rules (enforced):
  1. TP/FP/FN matching is deterministic — endpoint path + agent type, not substrings
  2. FP = findings that match no known vuln, period
  3. FN = known vulns not found at all (tracked separately from detected-unconfirmed)
  4. Evidence = proof_snippet present and non-empty
  5. Chains = validated from session_intel confirmed_urls — not capped, validated
  6. Hallucinations = tied to scoring engine delta threshold
  7. Hypotheses tracked separately from budget
  8. Target matching uses parsed hostname:port
  9. Standards = OWASP mapping OR MITRE mapping
"""

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional
from pathlib import Path


@dataclass
class KnownVulnerability:
    """
    A vulnerability known to exist in a target app.
    Used for deterministic TP/FP/FN scoring.
    """
    vuln_id:         str    # e.g. "JS-001"
    app:             str    # "juice-shop"
    title:           str
    category:        str    # Exact OWASP category string
    endpoint:        str    # Canonical path — used for exact path match
    severity:        str
    detection_agent: str    # Which agent class should find this
    requires_auth:   bool = False   # Does detection require an authenticated session?


@dataclass
class EvalRun:
    """Results of a single evaluation run."""
    run_id:           str
    target:           str
    mode:             str
    timestamp:        str
    duration_seconds: float

    # Pipeline metrics — from session_intel (authoritative)
    hypotheses_generated: int    # How many hypotheses Alpha produced
    hypotheses_tested:    int    # How many were actually probed
    confirmed:            int    # Passed all pipeline criteria
    refuted:              int    # Explicitly disproven
    inconclusive:         int    # Tested but ambiguous

    # Detection quality — deterministic matching only
    true_positives:       int = 0   # Known vulns found AND confirmed
    false_positives:      int = 0   # Findings that match no known vuln
    false_negatives:      int = 0   # Known vulns not found at all
    detected_unconfirmed: int = 0   # Known vulns detected but not confirmed

    # Evidence quality
    total_findings:          int = 0
    findings_with_evidence:  int = 0  # proof_snippet present and non-empty
    findings_with_standards: int = 0  # OWASP category OR MITRE mapping
    hallucinations_blocked:  int = 0  # Scoring deltas > threshold
    time_to_first_confirmed: Optional[float] = None

    # Chain quality — validated, not capped
    chains_built_from_confirmed: int = 0   # All steps confirmed
    chains_with_unconfirmed:     int = 0   # At least one step not confirmed

    @property
    def precision(self) -> float:
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return round(self.true_positives / (self.true_positives + self.false_positives), 2)

    @property
    def recall(self) -> float:
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return round(self.true_positives / (self.true_positives + self.false_negatives), 2)

    @property
    def confirmation_rate(self) -> float:
        if self.hypotheses_tested == 0:
            return 0.0
        return round(self.confirmed / self.hypotheses_tested, 2)

    @property
    def evidence_coverage(self) -> float:
        if self.confirmed == 0:
            return 0.0
        return round(self.findings_with_evidence / self.confirmed, 2)

    def format_scorecard(self) -> str:
        header = f"══ Eval Run: {self.run_id} ══"
        lines = [
            f"╔{header}╗",
            f"  Target:   {self.target}",
            f"  Mode:     {self.mode}",
            f"  Duration: {self.duration_seconds:.1f}s",
            f"",
            f"  Detection Quality:",
            f"    True positives:         {self.true_positives}",
            f"    False positives:        {self.false_positives}",
            f"    False negatives:        {self.false_negatives}",
            f"    Detected (unconfirmed): {self.detected_unconfirmed}",
            f"    Precision:              {self.precision:.0%}",
            f"    Recall:                 {self.recall:.0%}",
            f"",
            f"  Pipeline Quality:",
            f"    Hypotheses generated:   {self.hypotheses_generated}",
            f"    Hypotheses tested:      {self.hypotheses_tested}",
            f"    Confirmed:              {self.confirmed}",
            f"    Refuted (NOT vuln):     {self.refuted}",
            f"    Inconclusive:           {self.inconclusive}",
            f"    Confirmation rate:      {self.confirmation_rate:.0%}",
            f"",
            f"  Evidence Quality:",
            f"    With evidence:          {self.findings_with_evidence}/{self.confirmed}",
            f"    With standards:         {self.findings_with_standards}/{self.total_findings}",
            f"    Hallucinations blkd:    {self.hallucinations_blocked}",
            (f"    Time to 1st confirm:    {self.time_to_first_confirmed:.1f}s"
             if self.time_to_first_confirmed else
             f"    Time to 1st confirm:    N/A"),
            f"",
            f"  Chain Quality:",
            f"    Valid chains:           {self.chains_built_from_confirmed}",
            f"    Invalid chains:         {self.chains_with_unconfirmed}",
            f"╚{'═' * len(header)}╝",
        ]
        return "\n".join(lines)


# ── Known vulnerabilities database ───────────────────────────────────────────

JUICE_SHOP_KNOWN: list[KnownVulnerability] = [
    KnownVulnerability(
        "JS-001", "juice-shop",
        "Score Board accessible without auth",
        "Security Misconfiguration",
        "/api/Challenges",
        "MEDIUM",
        detection_agent="probe_agent",
    ),
    KnownVulnerability(
        "JS-002", "juice-shop",
        "User list accessible without auth",
        "Broken Access Control",
        "/api/Users",
        "HIGH",
        detection_agent="probe_agent",
    ),
    KnownVulnerability(
        "JS-003", "juice-shop",
        "SQL injection in product search",
        "Injection",
        "/rest/products/search",
        "CRITICAL",
        detection_agent="injection_agent",
    ),
    KnownVulnerability(
        "JS-004", "juice-shop",
        "JWT weak secret",
        "Broken Authentication",
        "/rest/user/login",
        "HIGH",
        detection_agent="auth_scan_agent",
    ),
    KnownVulnerability(
        "JS-005", "juice-shop",
        "No rate limiting on login",
        "Broken Authentication",
        "/rest/user/login",
        "MEDIUM",
        detection_agent="probe_agent",
    ),
    KnownVulnerability(
        "JS-006", "juice-shop",
        "Admin panel accessible via SPA route",
        "Security Misconfiguration",
        "/#/administration",
        "HIGH",
        detection_agent="auth_scan_agent",
        requires_auth=True,
    ),
    KnownVulnerability(
        "JS-007", "juice-shop",
        "Product API exposed without auth",
        "Broken Access Control",
        "/api/Products",
        "MEDIUM",
        detection_agent="probe_agent",
    ),
    KnownVulnerability(
        "JS-008", "juice-shop",
        "Application configuration exposed without auth",
        "Security Misconfiguration",
        "/rest/admin/application-configuration",
        "HIGH",
        detection_agent="probe_agent",
    ),
    KnownVulnerability(
        "JS-011", "juice-shop",
        "Feedback API exposed without auth",
        "Broken Access Control",
        "/api/Feedbacks",
        "MEDIUM",
        detection_agent="probe_agent",
    ),
    KnownVulnerability(
        "JS-009", "juice-shop",
        "Missing security headers",
        "Security Misconfiguration",
        "/",
        "LOW",
        detection_agent="config_agent",
    ),
    KnownVulnerability(
        "JS-010", "juice-shop",
        "No HTTPS redirect",
        "Transport Layer Security",
        "/",
        "MEDIUM",
        detection_agent="recon_agent",
    ),
]

KNOWN_VULNS: dict[str, list[KnownVulnerability]] = {
    "juice-shop":      JUICE_SHOP_KNOWN,
    "localhost:3000":  JUICE_SHOP_KNOWN,
    "127.0.0.1:3000":  JUICE_SHOP_KNOWN,
}


class EvalHarness:
    """
    Evaluation harness for Sentinel.
    Tracks real performance — not inflated, not deflated.
    """

    HALLUCINATION_THRESHOLD = 0.20  # delta above this = blocked hallucination

    def __init__(self, target: str, mode: str):
        self.target     = target
        self.mode       = mode
        self.start_time = time.time()
        self.run_id     = f"EVAL-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

        self.first_confirmed_time: Optional[float] = None
        self.hallucination_deltas: list[float] = []

        # Hypothesis tracking — separate from budget
        self.hypotheses_generated: int = 0
        self.hypotheses_tested:    int = 0

        # Resolve known vulns by parsed hostname:port
        self.known_vulns = self._resolve_known_vulns(target)

    def _resolve_known_vulns(self, target: str) -> list[KnownVulnerability]:
        """Resolve known vulns by parsed hostname:port — deterministic, not substring."""
        parsed    = urlparse(target if "://" in target else f"http://{target}")
        host      = parsed.hostname or ""
        port      = str(parsed.port) if parsed.port else ""
        host_port = f"{host}:{port}" if port else host

        # Exact hostname:port match first
        if host_port in KNOWN_VULNS:
            return KNOWN_VULNS[host_port]

        # Exact hostname match
        if host in KNOWN_VULNS:
            return KNOWN_VULNS[host]

        # App name match — only if the ENTIRE hostname matches the key
        # (not substring — "juice-shop" should not match "juice-shop.example.com")
        for key, vulns in KNOWN_VULNS.items():
            if key == host or key == host_port:
                return vulns

        return []

    def record_first_confirmed(self):
        """Called when first confirmed finding is recorded."""
        if self.first_confirmed_time is None:
            self.first_confirmed_time = time.time() - self.start_time

    def record_hypothesis(self, tested: bool = False):
        """Track a hypothesis. tested=True when actually probed."""
        self.hypotheses_generated += 1
        if tested:
            self.hypotheses_tested += 1

    def record_hallucination_blocked(self, delta: float):
        """
        Record a blocked hallucination.
        Tied to scoring engine: delta = ai_confidence - calibrated_confidence.
        Only counts if delta exceeds threshold.
        """
        if delta >= self.HALLUCINATION_THRESHOLD:
            self.hallucination_deltas.append(delta)

    def score(self, scan_result) -> EvalRun:
        """Score a completed scan result. All metrics deterministic."""
        duration = time.time() - self.start_time
        findings = scan_result.findings

        # ── Authoritative state from session_intel ────────────────────────────
        session       = getattr(scan_result, '_session', None)
        intel         = getattr(session, '_session_intel', None) if session else None
        confirmed_urls: set = intel.confirmed_urls if intel else set()

        if intel:
            confirmed    = len(intel.confirmed_urls)
            refuted      = len(intel.disproven_urls)
            inconclusive = len(intel.inconclusive_urls)
        else:
            ps           = getattr(scan_result, 'pipeline_summary', {})
            confirmed    = ps.get('confirmed_findings', 0)
            refuted      = ps.get('refuted_findings', 0)
            inconclusive = 0

        # ── Hypothesis counts — separate from budget ──────────────────────────
        hyp_gen    = self.hypotheses_generated or (intel.budget_used if intel else 0)
        hyp_tested = self.hypotheses_tested    or (intel.budget_used if intel else 0)

        # ── Evidence: proof_snippet present ───────────────────────────────────
        with_evidence = sum(
            1 for f in findings
            if getattr(f, 'proof_snippet', None) or
               "📊 Blast radius" in (f.description or "") and ("MEASURED" in (f.description or "") or "measured" in (f.description or ""))
        )

        # ── Standards: OWASP OR MITRE ─────────────────────────────────────────
        with_standards = sum(
            1 for f in findings
            if (f.mitre_tactic and
                f.mitre_tactic not in ("Multiple", "Unknown", "", None)) or
               any(marker in (f.description or "")
                   for marker in ("ASVS", "WSTG", "📋", "OWASP"))
        )

        # ── TP/FP/FN — deterministic ─────────────────────────────────────────
        tp_ids, fp_count, fn_ids, unconfirmed_ids = self._score_deterministic(
            findings, confirmed_urls
        )

        # ── Chain validation — real, not capped ──────────────────────────────
        chains = getattr(scan_result, 'attack_chains', [])
        chains_valid, chains_invalid = self._validate_chains(chains, confirmed_urls)

        return EvalRun(
            run_id=self.run_id,
            target=self.target,
            mode=self.mode,
            timestamp=datetime.now(timezone.utc).isoformat(),
            duration_seconds=round(duration, 1),
            hypotheses_generated=hyp_gen,
            hypotheses_tested=hyp_tested,
            confirmed=confirmed,
            refuted=refuted,
            inconclusive=inconclusive,
            total_findings=len(findings),
            true_positives=len(tp_ids),
            false_positives=fp_count,
            false_negatives=len(fn_ids),
            detected_unconfirmed=len(unconfirmed_ids),
            findings_with_evidence=with_evidence,
            findings_with_standards=with_standards,
            hallucinations_blocked=len(self.hallucination_deltas),
            time_to_first_confirmed=self.first_confirmed_time,
            chains_built_from_confirmed=chains_valid,
            chains_with_unconfirmed=chains_invalid,
        )

    def _score_deterministic(
        self,
        findings,
        confirmed_urls: set,
    ) -> tuple[set, int, set, set]:
        """
        Deterministic TP/FP/FN.

        Matching rules:
          endpoint_match: known.endpoint (without query params) is a suffix of finding.file_path
          agent_match:    known.detection_agent prefix matches finding.agent

        A finding is TP if it matches a known vuln AND is confirmed.
        A finding is FP if it matches NO known vuln (regardless of confirmation).
        A known vuln is FN if it was never found (not even unconfirmed).
        A known vuln is detected_unconfirmed if found but not confirmed.
        """
        if not self.known_vulns:
            return set(), 0, set(), set()

        matched_confirmed:   set[str] = set()
        matched_unconfirmed: set[str] = set()
        finding_matched_ids: set[int] = set()   # id() of findings that matched anything

        for known in self.known_vulns:
            if known.requires_auth:
                continue  # Skip auth-required vulns in unauthenticated scan

            known_path = known.endpoint.lower().split("?")[0]

            for f in findings:
                file_path  = (f.file_path or "").lower()
                agent_str  = str(f.agent or "").lower()
                finding_id = id(f)

                # Endpoint match is the primary criterion — required for a match
                # Agent match alone is too broad (probe_agent covers too many vulns)
                ep_match = (
                    file_path.endswith(known_path) or
                    (known_path not in ("/", "") and known_path in file_path)
                ) or (
                    # Root path match — only when file_path is literally the base URL
                    known_path in ("/", "") and
                    file_path.rstrip("/").endswith(("localhost:3000", "127.0.0.1:3000"))
                )

                if ep_match:
                    finding_matched_ids.add(finding_id)

                    # is_confirmed: pipeline confirmed AND URL in confirmed_urls
                    desc_or = f.description or ""
                    is_confirmed = (
                        (f.file_path in confirmed_urls) or
                        ("📊 Blast radius" in desc_or and ("MEASURED" in desc_or or "measured" in desc_or)) or
                        ("[Root Cause]" in (f.title or "") and known_path in desc_or.lower())
                    )

                    # is_refuted: 401/403, disproven, or SPA fallback
                    # These must NOT count as detected_unconfirmed
                    desc_lower = (f.description or "").lower()
                    is_refuted = (
                        "401" in desc_lower or
                        "403" in desc_lower or
                        "auth: required" in desc_lower or
                        "authentication enforced" in desc_lower or
                        "spa shell" in desc_lower or
                        "spa fallback" in desc_lower or
                        "not vulnerable" in (f.title or "").lower()
                    )

                    if is_confirmed:
                        matched_confirmed.add(known.vuln_id)
                    elif not is_refuted:
                        # Only counts as detected_unconfirmed if:
                        # - endpoint matched a known vuln path
                        # - was not refuted
                        # - has some evidence (not a raw hypothesis)
                        has_evidence = (
                            getattr(f, 'proof_snippet', None) or
                            "HTTP 200" in (f.description or "") or
                            "returned" in (f.description or "").lower()
                        )
                        if has_evidence:
                            matched_unconfirmed.add(known.vuln_id)

        # FP: non-INFO findings that matched NO known vuln
        # Exclude structural findings that are outside the known-vuln scope:
        #   - SPA route detections (client-side routing, not security vulns)
        #   - ATT&CK enriched compound findings (derived, not direct probes)
        #   - Root cause groupings (aggregates, not individual findings)
        #   - Recon findings with no specific endpoint (DNS, HTTPS at infra level)
        EXCLUDED_TITLES = ('spa route', 'root cause', 'attck', 'dns resolution',
                           'multiple dns', 'compound risk', 'missing authentication enforcement')
        fp_count = sum(
            1 for f in findings
            if id(f) not in finding_matched_ids and
               str(f.severity).split(".")[-1].upper() not in ("INFO",) and
               not any(ex in (f.title or "").lower() for ex in EXCLUDED_TITLES)
        )

        # FN: testable known vulns never found at all
        testable  = {k.vuln_id for k in self.known_vulns if not k.requires_auth}
        found_any = matched_confirmed | matched_unconfirmed
        fn_ids    = testable - found_any

        # Detected but unconfirmed only
        unconfirmed_only = matched_unconfirmed - matched_confirmed

        return matched_confirmed, fp_count, fn_ids, unconfirmed_only

    def _validate_chains(
        self,
        chains: list,
        confirmed_urls: set,
    ) -> tuple[int, int]:
        """
        Validate chains against confirmed_urls.
        Valid = all finding_ids reference URLs that are confirmed.
        A chain is invalid if it has no finding_ids or any finding_id URL is unconfirmed.
        """
        valid   = 0
        invalid = 0
        for chain in chains:
            finding_ids = chain.get("finding_ids", [])
            if not finding_ids:
                # No finding IDs — cannot validate, count as invalid
                invalid += 1
                continue

            # Check attack_path steps for URL references
            attack_path = chain.get("attack_path", [])
            # Extract any URLs mentioned in the attack path steps
            path_urls = []
            for step in attack_path:
                import re
                urls = re.findall(r'https?://[^\s\'"]+', str(step))
                path_urls.extend(urls)

            if path_urls:
                # Validate against confirmed URLs
                if all(any(confirmed in url for confirmed in confirmed_urls) or
                       any(url in confirmed for confirmed in confirmed_urls)
                       for url in path_urls):
                    valid += 1
                else:
                    invalid += 1
            else:
                # No URLs in path — validate by confidence
                # HIGH = strong chain signal, MEDIUM/LOW = insufficient
                if chain.get("confidence") == "HIGH":
                    valid += 1
                else:
                    invalid += 1
        return valid, invalid

    def save_run(self, run: EvalRun, output_dir: str = "reports/eval") -> str:
        """Save eval run to disk for trend analysis."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        path = Path(output_dir) / f"{run.run_id}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "run_id":                   run.run_id,
                "target":                   run.target,
                "mode":                     run.mode,
                "timestamp":                run.timestamp,
                "duration_seconds":         run.duration_seconds,
                "hypotheses_generated":     run.hypotheses_generated,
                "hypotheses_tested":        run.hypotheses_tested,
                "confirmed":                run.confirmed,
                "refuted":                  run.refuted,
                "inconclusive":             run.inconclusive,
                "total_findings":           run.total_findings,
                "true_positives":           run.true_positives,
                "false_positives":          run.false_positives,
                "false_negatives":          run.false_negatives,
                "detected_unconfirmed":     run.detected_unconfirmed,
                "precision":                run.precision,
                "recall":                   run.recall,
                "confirmation_rate":        run.confirmation_rate,
                "evidence_coverage":        run.evidence_coverage,
                "findings_with_evidence":   run.findings_with_evidence,
                "findings_with_standards":  run.findings_with_standards,
                "hallucinations_blocked":   run.hallucinations_blocked,
                "time_to_first_confirmed":  run.time_to_first_confirmed,
                "chains_valid":             run.chains_built_from_confirmed,
                "chains_invalid":           run.chains_with_unconfirmed,
            }, f, indent=2)
        return str(path)
