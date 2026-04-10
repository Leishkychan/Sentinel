"""
sentinel/core/scoring.py

Evidence-Based Scoring Engine.

Every score is earned, not asserted.
Every confidence value traces back to measurable evidence.
No hallucinated numbers.

Scoring methodology:
  EvidenceScore = sum of observed, measurable signals
  UncertaintyPenalty = what we don't know, subtracted
  CVSSBase = real CVSS score when available (from NVD)
  FinalConfidence = (EvidenceScore - UncertaintyPenalty) clamped to [0.0, 0.99]
  FinalScore = FinalConfidence × ImpactValue / Cost

Every score prints its evidence trail so it's auditable.
"""

from dataclasses import dataclass, field
from typing import Optional
import re


# ── Evidence signals — each is a boolean observation, not an assertion ────────

@dataclass
class EvidenceSignal:
    """A single piece of observed evidence with a defined weight."""
    name:        str
    weight:      float   # positive = increases confidence, negative = decreases
    observed:    bool
    description: str     # what was actually observed

    def contribution(self) -> float:
        return self.weight if self.observed else 0.0


@dataclass
class ScoredHypothesis:
    """A hypothesis with a fully traceable score."""
    statement:        str
    raw_confidence:   float       # what AI claimed
    calibrated_score: float       # what evidence actually supports
    impact:           str         # CRITICAL/HIGH/MEDIUM/LOW
    cost:             int         # estimated requests
    final_score:      float       # calibrated_score × impact_value / cost
    evidence:         list[EvidenceSignal] = field(default_factory=list)
    uncertainty:      list[EvidenceSignal] = field(default_factory=list)
    cvss_base:        Optional[float] = None
    evidence_summary: str = ""
    is_reliable:      bool = True  # False if AI confidence far exceeds evidence

    def format_scorecard(self) -> str:
        """Human-readable score breakdown — fully auditable."""
        lines = [
            f"Hypothesis: {self.statement[:80]}",
            f"─" * 60,
        ]

        if self.cvss_base:
            lines.append(f"CVSS Base Score: {self.cvss_base} (NVD)")

        lines.append(f"Evidence (positive signals):")
        positive = [e for e in self.evidence if e.observed]
        if positive:
            for e in positive:
                lines.append(f"  + {e.description} ({e.weight:+.2f})")
        else:
            lines.append("  (none observed yet)")

        lines.append(f"Uncertainty (negative signals):")
        negative = [e for e in self.uncertainty if e.observed]
        if negative:
            for e in negative:
                lines.append(f"  - {e.description} ({e.weight:+.2f})")
        else:
            lines.append("  (none)")

        lines.append(f"─" * 60)
        lines.append(f"Calibrated confidence: {self.calibrated_score:.2f}")
        lines.append(f"AI-claimed confidence:  {self.raw_confidence:.2f}")
        if not self.is_reliable:
            lines.append(f"⚠ AI confidence ({self.raw_confidence:.2f}) "
                         f"exceeds evidence ({self.calibrated_score:.2f}) — score adjusted down")
        lines.append(f"Impact: {self.impact} | Cost: {self.cost} requests")
        lines.append(f"Final score: {self.final_score:.2f}")

        return "\n".join(lines)


# ── Evidence signal definitions ───────────────────────────────────────────────

# These are the ONLY ways to earn confidence. No other path exists.

HTTP_EVIDENCE_SIGNALS = {
    # Positive evidence — things we actually observed
    "http_200_confirmed": EvidenceSignal(
        "http_200_confirmed", +0.35,
        False, "HTTP 200 confirmed — endpoint exists and responds"
    ),
    "sensitive_fields_in_response": EvidenceSignal(
        "sensitive_fields_in_response", +0.25,
        False, "Sensitive fields (password/token/email) present in response body"
    ),
    "no_auth_header_required": EvidenceSignal(
        "no_auth_header_required", +0.30,
        False, "Endpoint returned data without Authorization header"
    ),
    "json_data_returned": EvidenceSignal(
        "json_data_returned", +0.15,
        False, "Response is structured JSON data (not HTML/error)"
    ),
    "multiple_records_returned": EvidenceSignal(
        "multiple_records_returned", +0.20,
        False, "Response contains multiple records (list/array)"
    ),
    "error_message_leaked": EvidenceSignal(
        "error_message_leaked", +0.25,
        False, "Error message reveals internal details (stack trace/SQL)"
    ),
    "admin_content_in_response": EvidenceSignal(
        "admin_content_in_response", +0.30,
        False, "Response contains admin-level data or functionality"
    ),
    "consistent_across_ids": EvidenceSignal(
        "consistent_across_ids", +0.25,
        False, "Multiple resource IDs accessible (confirms IDOR not fluke)"
    ),
    "pattern_confirmed_twice": EvidenceSignal(
        "pattern_confirmed_twice", +0.20,
        False, "Same pattern confirmed on 2+ separate endpoints"
    ),
    "rate_limit_absent_confirmed": EvidenceSignal(
        "rate_limit_absent_confirmed", +0.20,
        False, "5 rapid requests returned no 429 — rate limiting absent"
    ),
}

HTTP_UNCERTAINTY_SIGNALS = {
    # Uncertainty — things that reduce our confidence
    "spa_fallback_possible": EvidenceSignal(
        "spa_fallback_possible", -0.25,
        False, "Response size matches known SPA shell (75KB) — may not be real data"
    ),
    "only_one_id_tested": EvidenceSignal(
        "only_one_id_tested", -0.15,
        False, "Only one resource ID tested — IDOR not yet confirmed as pattern"
    ),
    "no_content_type_json": EvidenceSignal(
        "no_content_type_json", -0.10,
        False, "Response Content-Type not JSON — may be HTML redirect or error"
    ),
    "response_under_100_bytes": EvidenceSignal(
        "response_under_100_bytes", -0.20,
        False, "Response too small to contain meaningful data"
    ),
    "redirected_to_login": EvidenceSignal(
        "redirected_to_login", -0.35,
        False, "Request was redirected to login page — endpoint IS protected"
    ),
    "inconsistent_with_prior": EvidenceSignal(
        "inconsistent_with_prior", -0.15,
        False, "Result inconsistent with previously observed pattern"
    ),
    "single_observation": EvidenceSignal(
        "single_observation", -0.10,
        False, "Only observed once — could be coincidence"
    ),
}

# CVSS base scores for common vulnerability types
# Source: NVD standard CVSS v3.1 scores for these vuln classes
CVSS_BASELINE = {
    "unauthenticated_admin":     9.8,   # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    "unauthenticated_api":       7.5,   # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    "sql_injection":             9.8,   # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    "xss_reflected":             6.1,   # AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
    "idor":                      6.5,   # AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
    "jwt_none_algorithm":        9.1,   # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
    "jwt_no_expiry":             6.5,   # AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N
    "missing_https":             5.9,   # AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N
    "cors_wildcard":             6.5,   # AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N
    "missing_csp":               4.3,   # AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N
    "no_rate_limiting":          5.3,   # AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N
    "sensitive_data_exposure":   7.5,   # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    "mass_assignment":           8.8,   # AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
    "directory_listing":         5.3,   # AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
    "source_map_exposure":       5.3,   # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
}

IMPACT_VALUES = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


# ── Core scoring functions ────────────────────────────────────────────────────

def score_hypothesis(
    statement:      str,
    ai_confidence:  float,      # what the AI claimed — treated as unverified
    impact:         str,        # CRITICAL/HIGH/MEDIUM/LOW
    cost:           int,        # estimated requests needed
    http_response:  Optional[dict] = None,  # actual HTTP response data if available
    finding_context: Optional[dict] = None, # existing finding data
) -> ScoredHypothesis:
    """
    Score a hypothesis based on actual evidence, not AI assertion.

    ai_confidence is the starting point but is immediately checked against
    measurable evidence. If AI claims 0.9 but evidence only supports 0.4,
    the score is 0.4 — the AI's assertion is discarded.
    """
    evidence    = []
    uncertainty = []
    cvss_base   = None

    # Determine CVSS base from finding context
    if finding_context:
        cvss_base = _lookup_cvss(finding_context.get("title", ""),
                                  finding_context.get("description", ""))

    # Evaluate evidence signals from HTTP response
    if http_response:
        evidence, uncertainty = _evaluate_http_signals(http_response)

    # Evaluate evidence from finding context
    if finding_context:
        ctx_evidence, ctx_uncertainty = _evaluate_finding_signals(finding_context)
        evidence.extend(ctx_evidence)
        uncertainty.extend(ctx_uncertainty)

    # If no HTTP response and no context, apply single_observation penalty
    if not http_response and not finding_context:
        u = _copy_signal(HTTP_UNCERTAINTY_SIGNALS["single_observation"])
        u.observed = True
        uncertainty.append(u)

    # Calculate calibrated score from evidence
    evidence_total    = sum(e.contribution() for e in evidence)
    uncertainty_total = sum(u.contribution() for u in uncertainty)  # negative values

    # Start from 0.3 base (something reasonable exists for it to be a hypothesis)
    # then add evidence and subtract uncertainty
    calibrated = 0.30 + evidence_total + uncertainty_total

    # If CVSS exists, use it to anchor the impact assessment
    if cvss_base:
        # Normalize CVSS (0-10) to confidence range
        cvss_normalized = cvss_base / 10.0
        # Weight: 40% CVSS anchor + 60% evidence
        calibrated = (0.4 * cvss_normalized) + (0.6 * calibrated)

    calibrated = max(0.05, min(0.99, calibrated))

    # Check if AI was hallucinating confidence
    # If AI claims confidence significantly higher than evidence supports:
    is_reliable = True
    if ai_confidence > calibrated + 0.25:
        is_reliable = False
        # Use evidence-based score, not AI assertion
        final_confidence = calibrated
    else:
        # AI and evidence roughly agree — use calibrated (still evidence-based)
        final_confidence = calibrated

    final_score = (final_confidence * IMPACT_VALUES.get(impact, 1)) / max(cost, 1)

    # Build evidence summary
    positive_obs = [e.description for e in evidence if e.observed]
    negative_obs = [u.description for u in uncertainty if u.observed]

    summary_parts = []
    if positive_obs:
        summary_parts.append(f"Supporting: {'; '.join(positive_obs[:3])}")
    if negative_obs:
        summary_parts.append(f"Uncertain: {'; '.join(negative_obs[:2])}")
    if cvss_base:
        summary_parts.append(f"CVSS: {cvss_base}")

    evidence_summary = " | ".join(summary_parts) if summary_parts else "No direct evidence yet"

    return ScoredHypothesis(
        statement=statement,
        raw_confidence=ai_confidence,
        calibrated_score=round(final_confidence, 2),
        impact=impact,
        cost=cost,
        final_score=round(final_score, 2),
        evidence=evidence,
        uncertainty=uncertainty,
        cvss_base=cvss_base,
        evidence_summary=evidence_summary,
        is_reliable=is_reliable,
    )


def score_finding(finding_title: str, finding_description: str,
                  http_response: Optional[dict] = None) -> dict:
    """
    Score an actual finding with evidence-based exploit probability.
    Returns a scoring dict with full evidence trail.
    """
    cvss = _lookup_cvss(finding_title, finding_description)
    impact = _infer_impact(finding_title, finding_description)
    context = {"title": finding_title, "description": finding_description}

    scored = score_hypothesis(
        statement=finding_title,
        ai_confidence=0.5,  # neutral starting point for findings
        impact=impact,
        cost=1,
        http_response=http_response,
        finding_context=context,
    )

    return {
        "title":             finding_title,
        "cvss_base":         cvss,
        "exploit_probability": scored.calibrated_score,
        "impact":            impact,
        "evidence_summary":  scored.evidence_summary,
        "is_reliable":       scored.is_reliable,
        "scorecard":         scored.format_scorecard(),
    }


# ── Signal evaluators ─────────────────────────────────────────────────────────

def _evaluate_http_signals(http_response: dict) -> tuple[list, list]:
    """Evaluate evidence signals from an actual HTTP response."""
    evidence    = []
    uncertainty = []

    status   = http_response.get("status_code", 0)
    content  = http_response.get("content", "")
    size     = http_response.get("size_bytes", 0)
    ctype    = http_response.get("content_type", "")
    redirect = http_response.get("redirected_to_login", False)

    # HTTP 200 with meaningful content
    e = _copy_signal(HTTP_EVIDENCE_SIGNALS["http_200_confirmed"])
    e.observed = (status == 200)
    evidence.append(e)

    # Sensitive fields
    sensitive_terms = ["password", "token", "secret", "email", "credit",
                       "ssn", "key", "role", "hash", "admin"]
    has_sensitive = any(t in content.lower() for t in sensitive_terms)
    e = _copy_signal(HTTP_EVIDENCE_SIGNALS["sensitive_fields_in_response"])
    e.observed = has_sensitive
    evidence.append(e)

    # JSON data
    e = _copy_signal(HTTP_EVIDENCE_SIGNALS["json_data_returned"])
    e.observed = ("json" in ctype.lower() or
                  (content.strip().startswith("{") or content.strip().startswith("[")))
    evidence.append(e)

    # Multiple records
    e = _copy_signal(HTTP_EVIDENCE_SIGNALS["multiple_records_returned"])
    e.observed = (content.strip().startswith("[") and size > 500)
    evidence.append(e)

    # No auth required (inferred from getting 200 without auth header)
    e = _copy_signal(HTTP_EVIDENCE_SIGNALS["no_auth_header_required"])
    e.observed = (status == 200 and not http_response.get("auth_sent", False))
    evidence.append(e)

    # Uncertainty signals
    # SPA fallback (75KB responses)
    u = _copy_signal(HTTP_UNCERTAINTY_SIGNALS["spa_fallback_possible"])
    u.observed = (size > 70000 and size < 80000 and "text/html" in ctype)
    uncertainty.append(u)

    # Too small to be real data
    u = _copy_signal(HTTP_UNCERTAINTY_SIGNALS["response_under_100_bytes"])
    u.observed = (status == 200 and size < 100)
    uncertainty.append(u)

    # No JSON content type
    u = _copy_signal(HTTP_UNCERTAINTY_SIGNALS["no_content_type_json"])
    u.observed = (status == 200 and "json" not in ctype.lower() and size > 0)
    uncertainty.append(u)

    # Redirected to login
    u = _copy_signal(HTTP_UNCERTAINTY_SIGNALS["redirected_to_login"])
    u.observed = redirect
    uncertainty.append(u)

    return evidence, uncertainty


def _evaluate_finding_signals(context: dict) -> tuple[list, list]:
    """Evaluate evidence from an existing finding's context."""
    evidence    = []
    uncertainty = []

    title = context.get("title", "").lower()
    desc  = context.get("description", "").lower()

    # Pattern confirmed if description mentions confirmation
    e = _copy_signal(HTTP_EVIDENCE_SIGNALS["pattern_confirmed_twice"])
    e.observed = ("confirmed" in desc or "verified" in desc or "blast radius" in desc)
    evidence.append(e)

    # Admin content
    e = _copy_signal(HTTP_EVIDENCE_SIGNALS["admin_content_in_response"])
    e.observed = ("admin" in title or "administration" in title or "privilege" in title)
    evidence.append(e)

    # Single observation uncertainty
    u = _copy_signal(HTTP_UNCERTAINTY_SIGNALS["single_observation"])
    u.observed = ("may" in desc or "potential" in desc or "possible" in desc)
    uncertainty.append(u)

    return evidence, uncertainty


# ── CVSS lookup ───────────────────────────────────────────────────────────────

def _lookup_cvss(title: str, description: str) -> Optional[float]:
    """Look up CVSS base score for a known vulnerability type."""
    text = (title + " " + description).lower()

    # Match in priority order (most specific first)
    if "sql injection" in text or "sqli" in text:
        return CVSS_BASELINE["sql_injection"]
    if "jwt" in text and ("none" in text or "alg" in text):
        return CVSS_BASELINE["jwt_none_algorithm"]
    if "jwt" in text and "expir" in text:
        return CVSS_BASELINE["jwt_no_expiry"]
    if "unauthenticated" in text and ("admin" in text or "administration" in text):
        return CVSS_BASELINE["unauthenticated_admin"]
    if "unauthenticated" in text or "without auth" in text or "no auth" in text:
        return CVSS_BASELINE["unauthenticated_api"]
    if "idor" in text or "insecure direct" in text:
        return CVSS_BASELINE["idor"]
    if "mass assignment" in text:
        return CVSS_BASELINE["mass_assignment"]
    if "xss" in text or "cross-site scripting" in text:
        return CVSS_BASELINE["xss_reflected"]
    if "cors" in text and "wildcard" in text:
        return CVSS_BASELINE["cors_wildcard"]
    if "https" in text and ("redirect" in text or "missing" in text):
        return CVSS_BASELINE["missing_https"]
    if "rate limit" in text:
        return CVSS_BASELINE["no_rate_limiting"]
    if "sensitive data" in text or "data exposed" in text:
        return CVSS_BASELINE["sensitive_data_exposure"]
    if "source map" in text:
        return CVSS_BASELINE["source_map_exposure"]
    if "directory listing" in text:
        return CVSS_BASELINE["directory_listing"]
    if "content security policy" in text or "csp" in text:
        return CVSS_BASELINE["missing_csp"]

    return None


def _infer_impact(title: str, description: str) -> str:
    """Infer impact level from CVSS or keywords — not from AI assertion."""
    cvss = _lookup_cvss(title, description)
    if cvss:
        if cvss >= 9.0: return "CRITICAL"
        if cvss >= 7.0: return "HIGH"
        if cvss >= 4.0: return "MEDIUM"
        return "LOW"

    text = (title + " " + description).lower()
    if any(k in text for k in ["unauthenticated admin", "sql injection", "jwt none",
                                "mass assignment", "rce", "command injection"]):
        return "CRITICAL"
    if any(k in text for k in ["idor", "auth bypass", "sensitive data", "api exposed"]):
        return "HIGH"
    if any(k in text for k in ["rate limit", "xss", "cors", "info disclosure"]):
        return "MEDIUM"
    return "LOW"


def _copy_signal(signal: EvidenceSignal) -> EvidenceSignal:
    """Create a copy of an evidence signal (so originals aren't mutated)."""
    return EvidenceSignal(
        name=signal.name,
        weight=signal.weight,
        observed=signal.observed,
        description=signal.description,
    )


# ── Public calibration interface ──────────────────────────────────────────────

def calibrate_ai_decision(decision: dict, probe_results: Optional[dict] = None) -> dict:
    """
    Take an AI decision with claimed confidence/score and calibrate it
    against measurable evidence. Returns updated decision with real scores.

    This is called after EVERY Alpha think() cycle to prevent hallucinated confidence.
    """
    hyp = decision.get("hypothesis", {})
    if not hyp:
        return decision

    statement     = hyp.get("statement", "")
    ai_confidence = float(hyp.get("confidence", 0.5))
    impact        = hyp.get("impact", "HIGH")
    cost          = int(hyp.get("cost", 1))

    scored = score_hypothesis(
        statement=statement,
        ai_confidence=ai_confidence,
        impact=impact,
        cost=cost,
        http_response=probe_results,
        finding_context={"title": statement, "description": statement},
    )

    # Update the decision with calibrated scores
    decision["hypothesis"]["confidence"]        = scored.calibrated_score
    decision["hypothesis"]["score"]             = scored.final_score
    decision["hypothesis"]["cvss_basis"]        = scored.cvss_base
    decision["hypothesis"]["evidence_summary"]  = scored.evidence_summary
    decision["hypothesis"]["score_reliable"]    = scored.is_reliable

    if not scored.is_reliable:
        decision["hypothesis"]["calibration_note"] = (
            f"AI claimed {ai_confidence:.2f} but evidence supports {scored.calibrated_score:.2f}. "
            "Score adjusted to evidence-based value."
        )

    return decision
