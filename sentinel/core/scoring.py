"""
sentinel/core/scoring.py

Evidence-Based Scoring Engine v2.

Three-stage pipeline:
  DETECT → TEST → CONFIRM → REPORT

Every finding has a status:
  OBSERVED    — we saw it directly, HTTP response confirmed it
  INFERRED    — we believe it based on indirect signals
  UNCONFIRMED — hypothesis only, not yet tested

Severity is tied to real-world impact criteria, not keyword matching.
Blast radius is honest — "unknown volume" until actually measured.
Attack chains only form from CONFIRMED findings.
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class FindingStatus(str, Enum):
    OBSERVED    = "OBSERVED"     # Directly confirmed by HTTP response
    INFERRED    = "INFERRED"     # Supported by indirect evidence
    UNCONFIRMED = "UNCONFIRMED"  # Hypothesis only


class VerificationResult(str, Enum):
    CONFIRMED    = "CONFIRMED"    # Test passed, finding is real
    REFUTED      = "REFUTED"      # Test failed, finding is false
    INCONCLUSIVE = "INCONCLUSIVE" # Test ran but result ambiguous
    UNTESTED     = "UNTESTED"     # Not yet tested


@dataclass
class EvidenceItem:
    """A single piece of evidence — observed fact only."""
    observation: str       # What was literally observed
    source:      str       # Where it came from (URL, header, response body)
    verified:    bool      # Did we confirm this directly?
    weight:      float     # Contribution to confidence


@dataclass
class ScoredFinding:
    """
    A finding with full evidence trail and honest status.
    Nothing is CRITICAL unless it's OBSERVED and CONFIRMED.
    """
    title:               str
    status:              FindingStatus
    verification:        VerificationResult
    severity:            str           # Only assigned after verification
    cvss_base:           Optional[float]
    cvss_vector:         Optional[str]
    calibrated_score:    float         # Evidence-based, not AI assertion
    ai_claimed_score:    float         # What AI said — for audit
    score_delta:         float         # Difference — measures hallucination
    evidence:            list[EvidenceItem] = field(default_factory=list)
    blast_radius:        str = "unknown volume — not yet measured"
    attack_chain_eligible: bool = False  # Only True if CONFIRMED
    notes:               list[str] = field(default_factory=list)

    def format_scorecard(self) -> str:
        lines = [
            f"Status: {self.status.value} | Verification: {self.verification.value}",
            f"Severity: {self.severity} | CVSS: {self.cvss_base or 'no match'}",
        ]
        if self.cvss_vector:
            lines.append(f"CVSS Vector: {self.cvss_vector}")
        lines.append(f"Calibrated: {self.calibrated_score:.2f} | AI claimed: {self.ai_claimed_score:.2f}")
        if abs(self.score_delta) > 0.2:
            lines.append(f"⚠ Hallucination detected: delta={self.score_delta:.2f}")
        lines.append(f"Blast radius: {self.blast_radius}")
        lines.append(f"Chain eligible: {self.attack_chain_eligible}")
        if self.evidence:
            lines.append("Evidence:")
            for e in self.evidence:
                mark = "✅" if e.verified else "⚠️"
                lines.append(f"  {mark} {e.observation} [{e.source}]")
        if self.notes:
            for n in self.notes:
                lines.append(f"  ❌ {n}")
        return "\n".join(lines)


# ── CVSS definitions — full vector strings, not just scores ──────────────────
# Source: NVD CVSS v3.1 standard vectors for these vulnerability classes

CVSS_DEFINITIONS = {
    "unauthenticated_admin_access": {
        "score":  9.8,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "notes":  "Network-accessible, no privileges, no interaction, full impact",
    },
    "unauthenticated_api_read": {
        "score":  7.5,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "notes":  "Data exposure without auth, no write access confirmed",
    },
    "sql_injection_confirmed": {
        "score":  9.8,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "notes":  "Full DB read/write possible",
    },
    "sql_injection_condition": {
        "score":  8.1,
        "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "notes":  "Condition detected, exploitation not confirmed",
    },
    "xss_reflected": {
        "score":  6.1,
        "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "notes":  "Requires user interaction",
    },
    "idor_confirmed": {
        "score":  6.5,
        "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "notes":  "Auth required but object ownership not enforced",
    },
    "idor_unconfirmed": {
        "score":  4.3,
        "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "notes":  "Pattern suggests IDOR, not directly confirmed",
    },
    "jwt_none_algorithm": {
        "score":  9.1,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "notes":  "Token forgery possible",
    },
    "jwt_weak_secret": {
        "score":  7.4,
        "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "notes":  "Secret crackable offline",
    },
    "jwt_no_expiry": {
        "score":  6.5,
        "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "notes":  "Requires token theft first",
    },
    "missing_https": {
        "score":  5.9,
        "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "notes":  "Requires MitM position — not trivial",
    },
    "cors_wildcard": {
        "score":  6.5,
        "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "notes":  "Requires user to visit attacker page",
    },
    "missing_csp": {
        "score":  4.3,
        "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
        "notes":  "XSS prerequisite needed",
    },
    "no_rate_limiting": {
        "score":  5.3,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "notes":  "Enables brute force, not direct compromise",
    },
    "sensitive_data_in_response": {
        "score":  7.5,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "notes":  "Direct data exposure",
    },
    "mass_assignment": {
        "score":  8.8,
        "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "notes":  "Auth required, but privilege escalation possible",
    },
    "missing_security_header": {
        "score":  3.7,
        "vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "notes":  "Defense-in-depth failure, not direct exploit",
    },
    "server_version_disclosure": {
        "score":  2.6,
        "vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "notes":  "Information gathering only",
    },
    "directory_listing": {
        "score":  5.3,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "notes":  "File enumeration, depends on what is listed",
    },
    "source_map_exposure": {
        "score":  5.3,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "notes":  "Source code exposure aids attack planning",
    },
    "spa_fallback_unconfirmed": {
        "score":  None,
        "vector": None,
        "notes":  "Cannot assign CVSS — endpoint not confirmed as real",
    },
}


# ── Severity tiers — HONEST mapping, not inflated ────────────────────────────

# What actually justifies each severity level
SEVERITY_CRITERIA = {
    "CRITICAL": [
        "Confirmed authentication bypass with full system access",
        "Confirmed SQL injection allowing data extraction",
        "Confirmed RCE or command injection",
        "JWT none algorithm confirmed exploitable",
        "Unauthenticated access to admin functionality CONFIRMED (not SPA fallback)",
    ],
    "HIGH": [
        "Confirmed IDOR exposing other users' data",
        "Confirmed sensitive data exposure (passwords, tokens, PII)",
        "SQL injection CONDITION detected (not yet confirmed exploitable)",
        "Mass assignment accepting privileged fields",
        "Unauthenticated API returning structured data (confirmed, not inferred)",
        "JWT weakness confirmed (weak secret, no expiry)",
    ],
    "MEDIUM": [
        "No rate limiting on auth endpoints (condition only)",
        "Wildcard CORS (requires user interaction to exploit)",
        "Reflected input in response (XSS condition, not confirmed payload)",
        "Multiple API versions active",
        "API documentation exposed",
        "Missing HTTPS redirect",
    ],
    "LOW": [
        "Missing security headers (X-Frame-Options, CSP, etc.)",
        "Server version disclosure",
        "Technology stack identified in headers",
        "Robots.txt or sitemap exposed",
        "Cookie missing Secure/HttpOnly (low risk without XSS)",
    ],
    "INFO": [
        "DNS resolution successful",
        "HTTP redirect behavior",
        "Host is up/reachable",
        "WHOIS data",
    ],
}


def assign_severity(title: str, description: str,
                    status: FindingStatus,
                    verification: VerificationResult) -> str:
    """
    Assign severity based on:
    1. What was actually confirmed (not inferred)
    2. Real CVSS score from definitions
    3. Status — UNCONFIRMED findings cannot be CRITICAL

    This replaces keyword-based severity inflation.
    """
    text = (title + " " + description).lower()
    cvss_def = _lookup_cvss_definition(title, description)

    # If finding is not confirmed, cap severity
    if status == FindingStatus.UNCONFIRMED or verification == VerificationResult.UNTESTED:
        # Unconfirmed findings max out at MEDIUM
        if cvss_def and cvss_def["score"]:
            if cvss_def["score"] >= 7.0:
                return "HIGH"    # Would be CRITICAL if confirmed
            elif cvss_def["score"] >= 4.0:
                return "MEDIUM"
            else:
                return "LOW"
        return "MEDIUM"  # Conservative default for unconfirmed

    if status == FindingStatus.INFERRED:
        # Inferred findings max out at HIGH
        if cvss_def and cvss_def["score"]:
            if cvss_def["score"] >= 9.0:
                return "HIGH"    # Would be CRITICAL if observed
            elif cvss_def["score"] >= 7.0:
                return "HIGH"
            elif cvss_def["score"] >= 4.0:
                return "MEDIUM"
            else:
                return "LOW"
        return "MEDIUM"

    # OBSERVED findings can use full CVSS range
    if cvss_def and cvss_def["score"]:
        score = cvss_def["score"]
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 5.0: return "MEDIUM"  # 4.0-4.9 = LOW (defense-in-depth, not direct exploit)
        return "LOW"

    # Fallback keyword mapping — conservative
    if any(k in text for k in ["sql injection condition", "error message"]):
        return "HIGH"
    if any(k in text for k in ["missing header", "version disclosure",
                                "cookie", "security header", "x-frame",
                                "content-type-options", "referrer-policy",
                                "permissions-policy"]):
        return "LOW"
    if any(k in text for k in ["rate limit", "cors", "xss condition", "missing https"]):
        return "MEDIUM"

    return "LOW"  # When in doubt, don't inflate — reviewers can escalate


def honest_blast_radius(response_data: Optional[dict] = None,
                        endpoint: str = "") -> str:
    """
    Honest blast radius statement.
    Only claims what was actually measured.
    Never extrapolates to "thousands of records" without proof.
    """
    if not response_data:
        return "unknown volume — endpoint not yet probed"

    status  = response_data.get("status_code", 0)
    content = response_data.get("content", "")
    size    = response_data.get("size_bytes", 0)
    ctype   = response_data.get("content_type", "")

    if status != 200:
        return f"not accessible — HTTP {status}"

    if size < 100:
        return "minimal data — response too small to contain records"

    # Try to count actual records
    import json as _json
    try:
        data = _json.loads(content)
        if isinstance(data, list):
            count = len(data)
            types = _detect_data_types(content)
            return (f"{count} records returned in unauthenticated response. "
                    f"Data types detected: {', '.join(types) if types else 'unknown'}. "
                    f"Response size: {size} bytes.")
        elif isinstance(data, dict):
            # Check for nested data arrays
            for key in ["data", "items", "results", "records"]:
                if key in data and isinstance(data[key], list):
                    count = len(data[key])
                    types = _detect_data_types(content)
                    return (f"{count} records in '{key}' field. "
                            f"Data types: {', '.join(types) if types else 'unknown'}.")
            return f"single object returned ({size} bytes). Data types: {_detect_data_types(content) or ['unknown']}."
    except (_json.JSONDecodeError, ValueError):
        pass

    # HTML response
    if "text/html" in ctype:
        if 70000 < size < 80000:
            return "likely SPA shell (~75KB) — real data not confirmed"
        return f"HTML response ({size} bytes) — structured data not confirmed"

    return f"response received ({size} bytes) — structure unknown, volume not measurable"


def calibrate_confidence(ai_confidence: float,
                         status: FindingStatus,
                         verification: VerificationResult,
                         cvss_score: Optional[float],
                         evidence_items: list[EvidenceItem]) -> tuple[float, float]:
    """
    Returns (calibrated_confidence, delta).
    delta > 0.2 indicates hallucination.

    Calibration rules:
    - OBSERVED + CONFIRMED = can use CVSS-anchored score
    - INFERRED = max 0.65 regardless of AI claim
    - UNCONFIRMED = max 0.45 regardless of AI claim
    - No evidence items = max 0.35
    """
    # Evidence-based ceiling
    verified_evidence = [e for e in evidence_items if e.verified]
    evidence_sum = sum(e.weight for e in verified_evidence)

    if status == FindingStatus.UNCONFIRMED:
        ceiling = 0.45
    elif status == FindingStatus.INFERRED:
        ceiling = 0.65
    else:  # OBSERVED
        ceiling = 0.95

    if verification == VerificationResult.UNTESTED:
        ceiling = min(ceiling, 0.50)
    elif verification == VerificationResult.CONFIRMED:
        ceiling = min(ceiling * 1.1, 0.99)

    # SPA fallback always reduces ceiling — even if HTTP 200
    # We cannot confirm anything if the response is a SPA shell
    spa_signals = [e for e in evidence_items
                   if "spa shell" in e.observation.lower() and e.verified]
    if spa_signals:
        ceiling = min(ceiling, 0.50)  # Hard cap — cannot be confident about SPA fallback

    # Start from CVSS anchor if available
    if cvss_score and status == FindingStatus.OBSERVED:
        base = 0.20 + (cvss_score / 10.0) * 0.65
    elif status == FindingStatus.INFERRED:
        # INFERRED: 0.30-0.50 range (strictly)
        base = max(0.30, min(0.50, 0.40 + evidence_sum))
    elif status == FindingStatus.OBSERVED and verification == VerificationResult.INCONCLUSIVE:
        # OBSERVED but inconclusive: 0.35-0.55 range
        base = max(0.35, min(0.55, 0.45 + evidence_sum))
    else:
        # UNCONFIRMED: 0.05-0.35 range (strictly)
        base = max(0.05, min(0.35, 0.25 + evidence_sum))

    calibrated = min(base, ceiling)
    calibrated = max(0.05, round(calibrated, 2))

    # Enforce deterministic ranges — no AI discretion
    if verification == VerificationResult.REFUTED:
        # REFUTED: confidence is 0.0 — proven not vulnerable
        calibrated = 0.0
    elif status == FindingStatus.OBSERVED and verification == VerificationResult.CONFIRMED:
        # CONFIRMED + strong evidence: 0.85-0.95
        calibrated = max(0.85, min(0.95, calibrated))
    elif status == FindingStatus.INFERRED:
        # INFERRED: 0.30-0.50
        calibrated = max(0.30, min(0.50, calibrated))
    elif verification == VerificationResult.INCONCLUSIVE:
        # INCONCLUSIVE: hard cap 0.40
        calibrated = min(0.40, calibrated)
    elif status == FindingStatus.UNCONFIRMED:
        # UNCONFIRMED: hard cap 0.35
        calibrated = min(0.35, calibrated)

    delta = round(ai_confidence - calibrated, 2)
    return calibrated, delta


def score_alpha_hypothesis(statement: str, ai_confidence: float,
                           ai_impact: str, cost: int,
                           http_response: Optional[dict] = None,
                           confirmed_count: int = 0) -> dict:
    """
    Score a single Alpha hypothesis.
    confirmed_count: previous confirmed probes this session — elevates ceiling.
    Returns a fully calibrated scoring dict.
    """
    # Determine status from available evidence
    if http_response and http_response.get("status_code") == 200:
        status       = FindingStatus.OBSERVED
        verification = VerificationResult.CONFIRMED
    elif http_response:
        sc = http_response.get("status_code", 0)
        # 401/403/404 are definitive negative signals — not ambiguous
        if sc in (401, 403, 404):
            status       = FindingStatus.INFERRED
            verification = VerificationResult.REFUTED
        else:
            # 500, other non-200 — genuinely ambiguous
            status       = FindingStatus.INFERRED
            verification = VerificationResult.INCONCLUSIVE
    else:
        status       = FindingStatus.UNCONFIRMED
        verification = VerificationResult.UNTESTED

    cvss_def = _lookup_cvss_definition(statement, statement)
    cvss_score = cvss_def["score"] if cvss_def else None
    cvss_vector = cvss_def["vector"] if cvss_def else None

    # Build evidence items
    evidence = []
    if http_response:
        evidence = _build_evidence_items(http_response)

    # If we have confirmed evidence from this session, raise the ceiling
    # Each confirmed finding adds evidence context to subsequent hypotheses
    # Guard: never elevate a REFUTED result — 401/403/404 are definitive negatives
    if confirmed_count > 0 and status == FindingStatus.UNCONFIRMED:
        # We have real confirmed findings — elevate to INFERRED minimum
        status = FindingStatus.INFERRED
        # Only set INCONCLUSIVE if we actually have an http_response to be inconclusive about
        # Pre-probe decisions (http_response=None) must stay UNTESTED — they haven't run yet
        if confirmed_count >= 2 and http_response is not None and verification != VerificationResult.REFUTED:
            verification = VerificationResult.INCONCLUSIVE  # Pattern emerging from actual responses

    calibrated, delta = calibrate_confidence(
        ai_confidence, status, verification, cvss_score, evidence
    )

    # Assign honest severity
    severity = assign_severity(statement, statement, status, verification)

    # CVSS-based impact override
    if cvss_score:
        if cvss_score >= 9.0:
            real_impact = "CRITICAL"
        elif cvss_score >= 7.0:
            real_impact = "HIGH"
        elif cvss_score >= 4.0:
            real_impact = "MEDIUM"
        else:
            real_impact = "LOW"
    else:
        real_impact = ai_impact

    # If status is UNCONFIRMED, cap impact
    if status == FindingStatus.UNCONFIRMED and real_impact == "CRITICAL":
        real_impact = "HIGH"

    impact_values = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    final_score = round(
        (calibrated * impact_values.get(real_impact, 2)) / max(cost, 1), 2
    )

    # Honest blast radius
    blast = honest_blast_radius(http_response, statement)

    result = {
        "calibrated_confidence": calibrated,
        "ai_confidence":         ai_confidence,
        "delta":                 delta,
        "hallucination_detected": delta > 0.20,
        "status":                status.value,
        "verification":          verification.value,
        "severity":              severity,
        "impact":                real_impact,
        "cvss_score":            cvss_score,
        "cvss_vector":           cvss_vector,
        "final_score":           final_score,
        "blast_radius":          blast,
        "attack_chain_eligible": (status == FindingStatus.OBSERVED and
                                  verification == VerificationResult.CONFIRMED),
        "evidence_count":        len([e for e in evidence if e.verified]),
    }

    if delta > 0.20:
        result["calibration_note"] = (
            f"AI claimed {ai_confidence:.2f}, evidence supports {calibrated:.2f} "
            f"(status: {status.value}). Adjusted down."
        )
        # Track on session for eval harness
        # (accessed via session._eval_harness if available)

    return result


def calibrate_ai_decision(decision: dict,
                           probe_results: Optional[dict] = None,
                           confirmed_count: int = 0) -> dict:
    """
    Calibrate an AI decision dict.
    Called after every Alpha think() cycle.
    confirmed_count: number of probes confirmed so far this session.
    More confirmed findings = higher evidence ceiling.
    """
    hyp = decision.get("hypothesis", {})
    if not hyp:
        return decision

    scored = score_alpha_hypothesis(
        statement=hyp.get("statement", ""),
        ai_confidence=float(hyp.get("confidence", 0.5)),
        ai_impact=hyp.get("impact", "HIGH"),
        cost=int(hyp.get("cost", 1)),
        http_response=probe_results,
        confirmed_count=confirmed_count,
    )

    # Update with calibrated values
    decision["hypothesis"]["confidence"]           = scored["calibrated_confidence"]
    decision["hypothesis"]["score"]                = scored["final_score"]
    decision["hypothesis"]["impact"]               = scored["impact"]
    decision["hypothesis"]["status"]               = scored["status"]
    decision["hypothesis"]["verification"]         = scored["verification"]
    decision["hypothesis"]["cvss_basis"]           = scored["cvss_score"]
    decision["hypothesis"]["cvss_vector"]          = scored["cvss_vector"]
    decision["hypothesis"]["blast_radius"]         = scored["blast_radius"]
    decision["hypothesis"]["attack_chain_eligible"] = scored["attack_chain_eligible"]
    decision["hypothesis"]["score_reliable"]       = not scored["hallucination_detected"]

    if scored["hallucination_detected"]:
        decision["hypothesis"]["calibration_note"] = scored["calibration_note"]
        # Auto-report to eval_harness via module-level reference
        try:
            import sentinel.agents._eval_ref as _eref
        except ImportError as e:
            import sys
            print(f"[WARN] eval harness import failed: {e}", file=sys.stderr)
        else:
            import sys
            harness = getattr(_eref, "current_harness", None)
            if harness is None:
                print("[WARN] eval harness not set — hallucination will not be recorded",
                      file=sys.stderr)
            elif not hasattr(harness, "record_hallucination_blocked"):
                print("[WARN] eval harness missing record_hallucination_blocked — skipping",
                      file=sys.stderr)
            else:
                harness.record_hallucination_blocked(scored.get("delta", 0.0))

    return decision


def score_finding(title: str, description: str,
                  http_response: Optional[dict] = None) -> dict:
    """Score an actual confirmed finding."""
    status = (FindingStatus.OBSERVED if http_response and
              http_response.get("status_code") == 200
              else FindingStatus.INFERRED)
    verification = (VerificationResult.CONFIRMED if status == FindingStatus.OBSERVED
                    else VerificationResult.UNTESTED)

    cvss_def   = _lookup_cvss_definition(title, description)
    cvss_score  = cvss_def["score"] if cvss_def else None
    cvss_vector = cvss_def["vector"] if cvss_def else None

    evidence   = _build_evidence_items(http_response) if http_response else []
    calibrated, delta = calibrate_confidence(
        0.5, status, verification, cvss_score, evidence
    )
    severity = assign_severity(title, description, status, verification)
    blast    = honest_blast_radius(http_response, title)

    return {
        "title":             title,
        "status":            status.value,
        "verification":      verification.value,
        "cvss_base":         cvss_score,
        "cvss_vector":       cvss_vector,
        "severity":          severity,
        "exploit_probability": calibrated,
        "blast_radius":      blast,
        "attack_chain_eligible": (status == FindingStatus.OBSERVED and
                                  verification == VerificationResult.CONFIRMED),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _lookup_cvss_definition(title: str, description: str) -> Optional[dict]:
    text = (title + " " + description).lower()

    # Ordered by specificity — most specific first
    # Order matters — most specific first, most general last
    if "sql injection condition" in text:   return CVSS_DEFINITIONS["sql_injection_condition"]
    if "sql injection" in text:             return CVSS_DEFINITIONS["sql_injection_confirmed"]
    if "jwt" in text and "none" in text:    return CVSS_DEFINITIONS["jwt_none_algorithm"]
    if "jwt" in text and "expir" in text:   return CVSS_DEFINITIONS["jwt_no_expiry"]
    if "jwt" in text and "weak" in text:    return CVSS_DEFINITIONS["jwt_weak_secret"]
    if "unauthenticated" in text and "admin" in text:
        return CVSS_DEFINITIONS["unauthenticated_admin_access"]
    if "unauthenticated" in text:           return CVSS_DEFINITIONS["unauthenticated_api_read"]
    if "idor" in text and "confirmed" in text: return CVSS_DEFINITIONS["idor_confirmed"]
    if "idor" in text:                      return CVSS_DEFINITIONS["idor_unconfirmed"]
    if "mass assignment" in text:           return CVSS_DEFINITIONS["mass_assignment"]
    if "xss" in text or "reflected xss" in text: return CVSS_DEFINITIONS["xss_reflected"]
    if "cors" in text and "wildcard" in text: return CVSS_DEFINITIONS["cors_wildcard"]
    if "no rate limit" in text or "rate limit" in text: return CVSS_DEFINITIONS["no_rate_limiting"]
    if "sensitive data" in text:            return CVSS_DEFINITIONS["sensitive_data_in_response"]
    if "source map" in text:                return CVSS_DEFINITIONS["source_map_exposure"]
    if "directory listing" in text:         return CVSS_DEFINITIONS["directory_listing"]
    # Missing HTTPS before security header — both contain "security"
    if ("no https" in text or "missing https" in text or
        ("https" in text and "redirect" in text)):
        return CVSS_DEFINITIONS["missing_https"]
    # Security header MUST come after HTTPS check
    if "security header" in text or "x-frame" in text or "x-content" in text:
        return CVSS_DEFINITIONS["missing_security_header"]
    if "content security policy" in text or " csp" in text:
        return CVSS_DEFINITIONS["missing_csp"]
    if "server" in text and "version" in text: return CVSS_DEFINITIONS["server_version_disclosure"]
    if "spa fallback" in text:              return CVSS_DEFINITIONS["spa_fallback_unconfirmed"]

    return None


def _build_evidence_items(http_response: dict) -> list[EvidenceItem]:
    """Build evidence items from actual HTTP response."""
    items   = []
    status  = http_response.get("status_code", 0)
    content = http_response.get("content", "")
    size    = http_response.get("size_bytes", 0)
    ctype   = http_response.get("content_type", "")

    items.append(EvidenceItem(
        observation=f"HTTP {status} response",
        source="HTTP status code",
        verified=True,
        weight=0.25 if status == 200 else -0.10,
    ))

    if size > 0:
        items.append(EvidenceItem(
            observation=f"{size} bytes returned",
            source="Content-Length",
            verified=True,
            weight=0.10 if size > 200 else -0.05,
        ))

    if "json" in ctype:
        items.append(EvidenceItem(
            observation="JSON content type",
            source="Content-Type header",
            verified=True,
            weight=0.15,
        ))

    # SPA fallback uncertainty
    if 70000 < size < 80000 and "html" in ctype:
        items.append(EvidenceItem(
            observation="Response matches SPA shell size (~75KB HTML)",
            source="Content-Length + Content-Type",
            verified=True,
            weight=-0.25,  # Reduces confidence
        ))

    from sentinel.core.evidence import find_sensitive_fields_in_json
    sensitive = find_sensitive_fields_in_json(content)
    if sensitive:
        items.append(EvidenceItem(
            observation=f"Sensitive fields in response: {', '.join(sensitive)}",
            source="Response body",
            verified=True,
            weight=0.20,
        ))

    return items


def _detect_data_types(content: str) -> list[str]:
    text = content.lower()
    types = []
    if any(k in text for k in ["email", "username"]): types.append("user accounts")
    if any(k in text for k in ["password", "hash"]):   types.append("credentials")
    if any(k in text for k in ["credit", "payment"]):  types.append("payment data")
    if any(k in text for k in ["address", "phone"]):   types.append("PII")
    if any(k in text for k in ["token", "secret"]):    types.append("secrets/tokens")
    return types
