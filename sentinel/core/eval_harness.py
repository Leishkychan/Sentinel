"""
sentinel/core/eval_harness.py

Evaluation Harness.

Tracks Sentinel's performance against known-vulnerable applications.
Every claim about Sentinel's capability must be measurable.

Metrics tracked per run:
  - True positives (found something real)
  - False positives (flagged something that isn't vulnerable)
  - False negatives (missed something known-vulnerable)
  - Hypothesis-to-confirmation rate
  - Time to first confirmed finding
  - % findings with usable evidence
  - % hallucinated claims blocked
  - % attack paths correctly promoted

Lab matrix:
  - OWASP Juice Shop     (Node.js, Angular SPA)
  - VAmPI               (Python REST API, OWASP API Top 10)
  - WebGoat             (Java, J2EE)
  - DVWA                (PHP, MySQL)
  - NodeGoat            (Node.js, OWASP Top 10)
"""

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path


@dataclass
class KnownVulnerability:
    """A vulnerability known to exist in a target app."""
    vuln_id:      str          # e.g. "JS-001"
    app:          str          # "juice-shop"
    title:        str
    category:     str          # OWASP category
    endpoint:     str          # Where to find it
    severity:     str
    detection_method: str      # What Sentinel should use to find it


@dataclass
class EvalRun:
    """Results of a single evaluation run."""
    run_id:          str
    target:          str
    mode:            str
    timestamp:       str
    duration_seconds: float

    # Core metrics
    total_findings:  int
    confirmed:       int
    refuted:         int
    hypotheses:      int

    # Quality metrics
    true_positives:  int = 0
    false_positives: int = 0
    false_negatives: int = 0

    # Evidence quality
    findings_with_evidence:    int = 0
    findings_with_standards:   int = 0
    hallucinations_blocked:    int = 0
    time_to_first_confirmed:   Optional[float] = None

    # Chain quality
    confirmed_chains:    int = 0
    hallucinated_chains: int = 0

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
        if self.hypotheses == 0:
            return 0.0
        return round(self.confirmed / self.hypotheses, 2)

    @property
    def evidence_coverage(self) -> float:
        if self.confirmed == 0:
            return 0.0
        return round(self.findings_with_evidence / self.confirmed, 2)

    def format_scorecard(self) -> str:
        lines = [
            f"╔══ Eval Run: {self.run_id} ══╗",
            f"  Target:  {self.target}",
            f"  Mode:    {self.mode}",
            f"  Duration: {self.duration_seconds:.1f}s",
            f"",
            f"  Detection Quality:",
            f"    True positives:      {self.true_positives}",
            f"    False positives:     {self.false_positives}",
            f"    False negatives:     {self.false_negatives}",
            f"    Precision:           {self.precision:.0%}",
            f"    Recall:              {self.recall:.0%}",
            f"",
            f"  Pipeline Quality:",
            f"    Hypotheses tested:   {self.hypotheses}",
            f"    Confirmed findings:  {self.confirmed}",
            f"    Refuted (NOT vuln):  {self.refuted}",
            f"    Confirmation rate:   {self.confirmation_rate:.0%}",
            f"",
            f"  Evidence Quality:",
            f"    With evidence:       {self.findings_with_evidence}/{self.confirmed}",
            f"    With standards map:  {self.findings_with_standards}/{self.confirmed}",
            f"    Hallucinations blkd: {self.hallucinations_blocked}",
            f"    Time to 1st confirm: {self.time_to_first_confirmed:.1f}s" if self.time_to_first_confirmed else "    Time to 1st confirm: N/A",
            f"",
            f"  Chain Quality:",
            f"    Confirmed chains:    {self.confirmed_chains}",
            f"    Hallucinated chains: {self.hallucinated_chains}",
            f"╚{'═' * (len('══ Eval Run: ' + self.run_id + ' ══') + 2)}╝",
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
        "probe_agent — GET without auth",
    ),
    KnownVulnerability(
        "JS-002", "juice-shop",
        "User list accessible without auth",
        "Broken Access Control",
        "/api/Users",
        "HIGH",
        "probe_agent — GET without auth",
    ),
    KnownVulnerability(
        "JS-003", "juice-shop",
        "SQL injection in search",
        "Injection",
        "/rest/products/search?q=",
        "CRITICAL",
        "injection_agent — single quote probe",
    ),
    KnownVulnerability(
        "JS-004", "juice-shop",
        "JWT weak secret",
        "Broken Authentication",
        "/rest/user/login",
        "HIGH",
        "auth_scan_agent — JWT analysis",
    ),
    KnownVulnerability(
        "JS-005", "juice-shop",
        "No rate limiting on login",
        "Broken Authentication",
        "/rest/user/login",
        "MEDIUM",
        "probe_agent — rate limit check",
    ),
    KnownVulnerability(
        "JS-006", "juice-shop",
        "Admin panel accessible (SPA route, real admin JS-side)",
        "Security Misconfiguration",
        "/#/administration",
        "HIGH",
        "auth_scan_agent — authenticated scan",
    ),
    KnownVulnerability(
        "JS-007", "juice-shop",
        "Product API exposed without auth",
        "Broken Access Control",
        "/api/Products",
        "MEDIUM",
        "probe_agent — GET without auth",
    ),
    KnownVulnerability(
        "JS-008", "juice-shop",
        "Feedback API exposed without auth",
        "Broken Access Control",
        "/api/Feedbacks",
        "MEDIUM",
        "probe_agent — GET without auth",
    ),
    KnownVulnerability(
        "JS-009", "juice-shop",
        "Missing security headers",
        "Security Misconfiguration",
        "/*",
        "LOW",
        "config_agent — header check",
    ),
    KnownVulnerability(
        "JS-010", "juice-shop",
        "No HTTPS redirect",
        "Transport Layer Security",
        "/",
        "MEDIUM",
        "recon_agent — HTTP check",
    ),
]

KNOWN_VULNS: dict[str, list[KnownVulnerability]] = {
    "juice-shop":  JUICE_SHOP_KNOWN,
    "localhost:3000": JUICE_SHOP_KNOWN,
    "127.0.0.1:3000": JUICE_SHOP_KNOWN,
}


class EvalHarness:
    """
    Evaluation harness for Sentinel.
    Tracks performance against known-vulnerable targets.
    """

    def __init__(self, target: str, mode: str):
        self.target        = target
        self.mode          = mode
        self.start_time    = time.time()
        self.first_confirmed_time: Optional[float] = None
        self.hallucinations_blocked = 0
        self.known_vulns   = self._get_known_vulns(target)
        self.run_id        = f"EVAL-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    def _get_known_vulns(self, target: str) -> list[KnownVulnerability]:
        for key, vulns in KNOWN_VULNS.items():
            if key in target:
                return vulns
        return []

    def record_confirmed(self):
        """Record first confirmed finding time."""
        if self.first_confirmed_time is None:
            self.first_confirmed_time = time.time() - self.start_time

    def record_hallucination_blocked(self):
        """Record a blocked hallucination."""
        self.hallucinations_blocked += 1

    def score(self, scan_result) -> EvalRun:
        """
        Score a completed scan result against known vulnerabilities.
        """
        duration = time.time() - self.start_time
        findings = scan_result.findings

        # Count findings with evidence
        with_evidence = sum(
            1 for f in findings
            if "evidence" in (f.description or "").lower() or
               "confirmed" in (f.title or "").lower() or
               "blast radius" in (f.description or "").lower()
        )

        # Count findings with standards mapping
        with_standards = sum(
            1 for f in findings
            if f.mitre_tactic and f.mitre_tactic != "Multiple"
        )

        # Get pipeline stats
        pipeline_stats = getattr(scan_result, 'pipeline_summary', {})
        confirmed = pipeline_stats.get('confirmed_findings', 0)
        refuted   = pipeline_stats.get('refuted_findings', 0)
        hypotheses = pipeline_stats.get('hypotheses_tested', 0)

        # Score against known vulns
        tp, fp, fn = self._score_against_known(findings)

        # Count chain quality
        chains = getattr(scan_result, 'attack_chains', [])
        confirmed_chains = len([c for c in chains
                                 if c.get('confidence') in ('HIGH', 'CONFIRMED')])
        hallucinated_chains = len([c for c in chains
                                    if c.get('confidence') == 'LOW'])

        run = EvalRun(
            run_id=self.run_id,
            target=self.target,
            mode=self.mode,
            timestamp=datetime.now(timezone.utc).isoformat(),
            duration_seconds=round(duration, 1),
            total_findings=len(findings),
            confirmed=confirmed,
            refuted=refuted,
            hypotheses=hypotheses,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            findings_with_evidence=with_evidence,
            findings_with_standards=with_standards,
            hallucinations_blocked=self.hallucinations_blocked,
            time_to_first_confirmed=self.first_confirmed_time,
            confirmed_chains=confirmed_chains,
            hallucinated_chains=hallucinated_chains,
        )

        return run

    def _score_against_known(self, findings) -> tuple[int, int, int]:
        """
        Match findings against known vulnerabilities.
        Returns (true_positives, false_positives, false_negatives).
        """
        if not self.known_vulns:
            return 0, 0, 0

        found_vuln_ids = set()
        for finding in findings:
            title = (finding.title or "").lower()
            desc  = (finding.description or "").lower()
            for known in self.known_vulns:
                if (known.endpoint.lower() in title or
                    known.endpoint.lower() in desc or
                    known.category.lower() in title or
                    known.title.lower()[:20] in title):
                    found_vuln_ids.add(known.vuln_id)

        tp = len(found_vuln_ids)
        fn = len(self.known_vulns) - tp
        # False positives: findings that don't map to any known vuln
        fp = max(0, len(findings) - tp - len([
            f for f in findings
            if "info" in str(f.severity).lower() or
               "spa" in (f.title or "").lower()
        ]))

        return tp, max(0, fp), max(0, fn)

    def save_run(self, run: EvalRun, output_dir: str = "reports/eval"):
        """Save eval run to disk for trend analysis."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        path = Path(output_dir) / f"{run.run_id}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "run_id":            run.run_id,
                "target":            run.target,
                "mode":              run.mode,
                "timestamp":         run.timestamp,
                "duration_seconds":  run.duration_seconds,
                "total_findings":    run.total_findings,
                "confirmed":         run.confirmed,
                "refuted":           run.refuted,
                "hypotheses":        run.hypotheses,
                "true_positives":    run.true_positives,
                "false_positives":   run.false_positives,
                "false_negatives":   run.false_negatives,
                "precision":         run.precision,
                "recall":            run.recall,
                "confirmation_rate": run.confirmation_rate,
                "evidence_coverage": run.evidence_coverage,
                "hallucinations_blocked": run.hallucinations_blocked,
                "time_to_first_confirmed": run.time_to_first_confirmed,
                "confirmed_chains":   run.confirmed_chains,
                "hallucinated_chains": run.hallucinated_chains,
            }, f, indent=2)
        return str(path)


# For type hints
from typing import Optional
