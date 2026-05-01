"""
sentinel/core/pipeline.py

Formal Finding Pipeline.

A finding cannot advance state without meeting explicit criteria.
No exceptions. No AI discretion on promotion.

State machine:
  HYPOTHESIS → TESTED → CONFIRMED | REFUTED

First-class TESTED sub-outcomes (stored in promotion_reason, not separate states):
  TESTED / INPUT_REQUIRED:
    - HTTP 400 returned
    - Endpoint exists and works — it rejected malformed input
    - NOT a security finding — retry only with valid input
    - Never retried without providing required parameters
    - Not stored as disproven (endpoint may still be vulnerable with valid input)

  TESTED / INCONCLUSIVE:
    - HTTP 500 returned
    - Server is broken/misconfigured — cannot determine safe or unsafe
    - Not promoted to CONFIRMED (no proof of access)
    - Not promoted to REFUTED (no proof of protection)
    - After 2 INCONCLUSIVE results on same URL: permanently skip

These are intentionally NOT separate FindingState enum values because:
  - Both transition from HYPOTHESIS → TESTED (the state is correct)
  - The distinction is encoded in promotion_reason for reporting
  - Adding enum values would require updating all state machine consumers

Promotion rules (enforced, not advisory):
  HYPOTHESIS → TESTED:
    - Request was sent
    - Response was received
    - Response metadata captured (status, type, size)

  TESTED → CONFIRMED:
    - HTTP 200 returned
    - Response is NOT a SPA shell
    - Response type is JSON OR contains meaningful content
    - Auth was NOT sent (proving no-auth bypass)
    - Content size > threshold

  TESTED → REFUTED:
    - HTTP 401 or 403 returned (AUTH_ENFORCED)
    - Response is a SPA shell (SPA_FALLBACK)
    - HTTP 404 returned (NOT_FOUND)
    - Request failed (NO_RESPONSE)
    - Response is empty (EMPTY_RESPONSE)

Every CONFIRMED finding includes:
  - Request artifact (method, url, headers sent)
  - Response artifact (status, type, size, sample)
  - Proof snippet (sanitized)
  - Promotion timestamp

Every REFUTED finding includes:
  - Why it was refuted
  - What was tested
  - What was expected vs what happened
"""

import json
import hashlib
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


# ── State definitions ─────────────────────────────────────────────────────────

class FindingState(str, Enum):
    HYPOTHESIS  = "HYPOTHESIS"   # AI proposed this, nothing tested yet
    TESTED      = "TESTED"       # Request sent, response received
    CONFIRMED   = "CONFIRMED"    # All promotion criteria met
    REFUTED     = "REFUTED"      # Proven NOT vulnerable


class RefutedReason(str, Enum):
    AUTH_ENFORCED    = "AUTH_ENFORCED"       # 401/403 returned
    SPA_FALLBACK     = "SPA_FALLBACK"        # HTML SPA shell, no real data
    NO_RESPONSE      = "NO_RESPONSE"         # Connection failed / timeout
    EMPTY_RESPONSE   = "EMPTY_RESPONSE"      # 200 but no meaningful content
    NOT_FOUND        = "NOT_FOUND"           # 404 — endpoint doesn't exist
    SERVER_ERROR     = "SERVER_ERROR"        # 500 — broken but not vulnerable
    ASSUMPTION_FAILS = "ASSUMPTION_FAILS"    # A required assumption was false


# ── Evidence requirement ──────────────────────────────────────────────────────

@dataclass
class RequestRecord:
    """What was sent."""
    method:      str
    url:         str
    auth_sent:   bool
    timestamp:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ResponseRecord:
    """What was received."""
    status_code:    int
    status_text:    str
    content_type:   str
    size_bytes:     int
    response_type:  str           # JSON | HTML | TEXT | EMPTY
    record_count:   Optional[int]  # If JSON array
    sensitive_fields: list[str]
    proof_snippet:  Optional[str]  # Sanitized sample — REQUIRED for CONFIRMED


@dataclass
class EvidenceBundle:
    """
    Complete evidence for a finding.
    CONFIRMED findings MUST have this populated.
    """
    request:       RequestRecord
    response:      ResponseRecord
    finding_state: FindingState
    promotion_reason: str         # Why this was confirmed/refuted
    refuted_reason: Optional[RefutedReason] = None

    def format(self) -> str:
        lines = [
            f"{'─'*50}",
            f"Request:  {self.request.method} {self.request.url}",
            f"Auth sent: {'YES' if self.request.auth_sent else 'NO'}",
            f"Status:   {self.response.status_code} {self.response.status_text}",
            f"Type:     {self.response.response_type} ({self.response.size_bytes} bytes)",
        ]
        if self.response.record_count is not None:
            lines.append(f"Records:  {self.response.record_count} returned")
        if self.response.sensitive_fields:
            lines.append(f"Sensitive: {', '.join(self.response.sensitive_fields)}")
        if self.response.proof_snippet:
            lines.append(f"Proof:    {self.response.proof_snippet}")
        lines.append(f"State:    {self.finding_state.value}")
        lines.append(f"Reason:   {self.promotion_reason}")
        if self.refuted_reason:
            lines.append(f"Refuted:  {self.refuted_reason.value}")
        lines.append(f"{'─'*50}")
        return "\n".join(lines)


# ── Potential path structure ──────────────────────────────────────────────────

@dataclass
class PathStep:
    """A single step in a potential attack path."""
    step_number:  int
    endpoint:     str
    method:       str
    state:        FindingState
    assumption:   str            # What must be true for this step
    next_test:    str            # What to probe to advance
    evidence:     Optional[EvidenceBundle] = None


@dataclass
class PotentialPath:
    """
    A structured potential attack path.
    Entry point → steps → outcome.
    Path only becomes an attack chain when ALL steps are CONFIRMED.
    """
    path_id:      str
    title:        str
    entry_point:  str            # First confirmed finding
    steps:        list[PathStep]
    risk_level:   str            # CRITICAL|HIGH|MEDIUM|LOW
    required_assumptions: list[str]
    state:        FindingState   # Path state = min(step states)
    confirmed_steps: int = 0
    total_steps:  int = 0

    def advance_state(self):
        """Recalculate path state from step states."""
        self.confirmed_steps = sum(1 for s in self.steps
                                   if s.state == FindingState.CONFIRMED)
        self.total_steps = len(self.steps)

        if all(s.state == FindingState.CONFIRMED for s in self.steps):
            self.state = FindingState.CONFIRMED
        elif any(s.state == FindingState.REFUTED for s in self.steps):
            self.state = FindingState.REFUTED
        elif any(s.state == FindingState.TESTED for s in self.steps):
            self.state = FindingState.TESTED
        else:
            self.state = FindingState.HYPOTHESIS

    def format(self) -> str:
        lines = [
            f"Path: {self.title} [{self.state.value}]",
            f"Risk: {self.risk_level} | Steps: {self.confirmed_steps}/{self.total_steps} confirmed",
            f"Entry: {self.entry_point}",
        ]
        for step in self.steps:
            icon = "✅" if step.state == FindingState.CONFIRMED else \
                   "❌" if step.state == FindingState.REFUTED else \
                   "🔍" if step.state == FindingState.TESTED else "❓"
            lines.append(f"  {icon} Step {step.step_number}: {step.endpoint}")
            lines.append(f"     Assumption: {step.assumption}")
            if step.state not in (FindingState.CONFIRMED, FindingState.REFUTED):
                lines.append(f"     Next test:  {step.next_test}")
        return "\n".join(lines)


# ── Negative validation record ────────────────────────────────────────────────

@dataclass
class NegativeValidation:
    """
    Explicit record of what was tested and proven NOT vulnerable.
    Critical for credibility — shows the system doesn't just find everything.
    """
    endpoint:     str
    method:       str
    reason:       RefutedReason
    evidence:     EvidenceBundle
    tested_at:    str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def format(self) -> str:
        reason_map = {
            RefutedReason.AUTH_ENFORCED:    "Authentication enforced — 401/403 returned",
            RefutedReason.SPA_FALLBACK:     "SPA fallback — HTML shell, no privileged data",
            RefutedReason.NOT_FOUND:        "Endpoint does not exist — 404 returned",
            RefutedReason.NO_RESPONSE:      "No response — connection refused or timed out",
            RefutedReason.EMPTY_RESPONSE:   "Empty response — no meaningful content",
            RefutedReason.SERVER_ERROR:     "Server error — 500 returned, endpoint broken",
            RefutedReason.ASSUMPTION_FAILS: "Required assumption not met",
        }
        return (
            f"NOT VULNERABLE: {self.endpoint}\n"
            f"  Method tested: {self.method}\n"
            f"  Reason: {reason_map.get(self.reason, self.reason.value)}\n"
            f"  Evidence: HTTP {self.evidence.response.status_code} "
            f"{self.evidence.response.status_text} | "
            f"{self.evidence.response.size_bytes} bytes | "
            f"{self.evidence.response.response_type}"
        )


# ── Promotion engine ──────────────────────────────────────────────────────────

class FindingPipeline:
    """
    Enforces state transitions for findings.
    Nothing advances without meeting explicit criteria.
    """

    SPA_SIZE_MIN = 70000
    SPA_SIZE_MAX = 82000
    MIN_CONTENT_SIZE = 200  # Minimum bytes to count as meaningful content

    def __init__(self):
        self.confirmed:          list[EvidenceBundle]       = []
        self.refuted:            list[NegativeValidation]   = []
        self.potential_paths:    list[PotentialPath]        = []
        self.hypothesis_count:   int = 0
        self.tested_count:       int = 0

    def test(self, url: str, method: str, response_data: dict,
             hypothesis: str) -> tuple[FindingState, Optional[EvidenceBundle],
                                       Optional[NegativeValidation]]:
        """
        Test a hypothesis against actual response data.
        Returns (state, confirmed_bundle | None, negative_validation | None)

        This is the ONLY way to advance a finding's state.
        """
        self.hypothesis_count += 1

        status    = response_data.get("status_code", 0)
        content   = response_data.get("content", "")
        size      = response_data.get("size_bytes", 0)
        ctype     = response_data.get("content_type", "")
        auth_sent = response_data.get("auth_sent", False)

        # Build request record
        req = RequestRecord(method=method, url=url, auth_sent=auth_sent)

        # Determine response type
        rtype = self._classify_response(content, ctype, size)

        # Count records — prefer pre-computed count from artifact (full response)
        # over re-parsing truncated content (which fails on large responses)
        record_count = (
            response_data.get("record_count")       # pre-computed from full response
            or self._count_records(content, rtype)  # fallback: parse truncated content
        )
        sensitive     = self._find_sensitive_fields(content)
        proof_snippet = self._build_proof(content, rtype, status, sensitive)

        # Build response record
        resp = ResponseRecord(
            status_code=status,
            status_text=self._status_text(status),
            content_type=ctype[:60],
            size_bytes=size,
            response_type=rtype,
            record_count=record_count,
            sensitive_fields=sensitive,
            proof_snippet=proof_snippet,
        )

        self.tested_count += 1

        # ── Apply promotion rules (enforced) ──────────────────────────────────

        # REFUTED: 401/403
        if status in (401, 403):
            neg = NegativeValidation(
                endpoint=url, method=method,
                reason=RefutedReason.AUTH_ENFORCED,
                evidence=EvidenceBundle(req, resp, FindingState.REFUTED,
                                        f"HTTP {status} — authentication enforced",
                                        RefutedReason.AUTH_ENFORCED),
            )
            self.refuted.append(neg)
            return FindingState.REFUTED, None, neg

        # REFUTED: 404
        if status == 404:
            neg = NegativeValidation(
                endpoint=url, method=method,
                reason=RefutedReason.NOT_FOUND,
                evidence=EvidenceBundle(req, resp, FindingState.REFUTED,
                                        "Endpoint does not exist",
                                        RefutedReason.NOT_FOUND),
            )
            self.refuted.append(neg)
            return FindingState.REFUTED, None, neg

        # REFUTED: no response
        if status == 0:
            neg = NegativeValidation(
                endpoint=url, method=method,
                reason=RefutedReason.NO_RESPONSE,
                evidence=EvidenceBundle(req, resp, FindingState.REFUTED,
                                        "No response received",
                                        RefutedReason.NO_RESPONSE),
            )
            self.refuted.append(neg)
            return FindingState.REFUTED, None, neg

        # REFUTED: SPA shell
        if self._is_spa_shell(size, ctype):
            neg = NegativeValidation(
                endpoint=url, method=method,
                reason=RefutedReason.SPA_FALLBACK,
                evidence=EvidenceBundle(req, resp, FindingState.REFUTED,
                                        f"SPA shell detected (~{size}b HTML) — no privileged data",
                                        RefutedReason.SPA_FALLBACK),
            )
            self.refuted.append(neg)
            return FindingState.REFUTED, None, neg

        # INPUT_REQUIRED: 400 Bad Request — endpoint exists but needs valid input
        # This is NOT a security finding and NOT inconclusive in the security sense.
        # The endpoint is rejecting a malformed request — it's working as designed.
        # Record as TESTED with INPUT_REQUIRED reason — do NOT retry without valid params.
        if status == 400:
            bundle = EvidenceBundle(
                request=req,
                response=resp,
                finding_state=FindingState.TESTED,
                promotion_reason=f"HTTP 400 — input required, not a security finding",
            )
            return FindingState.TESTED, bundle, None

        # 500 handling: distinguish "route doesn't exist" from "server broken"
        if status >= 500:
            # "Unexpected path: /api/X" in body = route not registered = equivalent to 404
            # This is a strong negative signal — the endpoint doesn't exist on this server
            if "unexpected path" in content.lower() or "cannot get" in content.lower():
                neg = NegativeValidation(
                    endpoint=url, method=method,
                    reason=RefutedReason.NOT_FOUND,
                    evidence=EvidenceBundle(req, resp, FindingState.REFUTED,
                                            f"HTTP 500 with route-not-found body — endpoint does not exist",
                                            RefutedReason.NOT_FOUND),
                )
                self.refuted.append(neg)
                return FindingState.REFUTED, None, neg

            # Genuine server error — inconclusive, not proven safe
            bundle = EvidenceBundle(
                request=req,
                response=resp,
                finding_state=FindingState.TESTED,
                promotion_reason=f"HTTP {status} server error — inconclusive, not proven safe",
            )
            return FindingState.TESTED, bundle, None

        # REFUTED: empty or too-small response
        if status == 200 and size < self.MIN_CONTENT_SIZE:
            neg = NegativeValidation(
                endpoint=url, method=method,
                reason=RefutedReason.EMPTY_RESPONSE,
                evidence=EvidenceBundle(req, resp, FindingState.REFUTED,
                                        f"Response too small ({size}b) — no meaningful content",
                                        RefutedReason.EMPTY_RESPONSE),
            )
            self.refuted.append(neg)
            return FindingState.REFUTED, None, neg

        # CONFIRMED: 200 + JSON + no auth sent + meaningful size
        if (status == 200 and
                rtype == "JSON" and
                not auth_sent and
                size >= self.MIN_CONTENT_SIZE):

            # Proof snippet is REQUIRED for confirmation — no fabrication allowed
            if not proof_snippet:
                bundle = EvidenceBundle(
                    request=req,
                    response=resp,
                    finding_state=FindingState.TESTED,
                    promotion_reason=(
                        f"HTTP 200 | JSON | {size}b | No auth sent — "
                        "INCONCLUSIVE: proof_snippet absent, cannot confirm"
                    ),
                )
                return FindingState.TESTED, bundle, None

            bundle = EvidenceBundle(
                request=req,
                response=resp,
                finding_state=FindingState.CONFIRMED,
                promotion_reason=(
                    f"HTTP 200 | JSON | {size}b | No auth sent | "
                    f"{record_count or 'unknown'} records"
                    + (f" | Sensitive: {', '.join(sensitive[:3])}" if sensitive else "")
                ),
            )
            self.confirmed.append(bundle)
            return FindingState.CONFIRMED, bundle, None

        # TESTED but not confirmed or refuted — needs more investigation
        bundle = EvidenceBundle(
            request=req,
            response=resp,
            finding_state=FindingState.TESTED,
            promotion_reason=f"HTTP {status} | {rtype} | {size}b — inconclusive",
        )
        return FindingState.TESTED, bundle, None

    def build_potential_path(self, title: str, entry_point: str,
                              steps_data: list[dict],
                              risk_level: str = "HIGH") -> PotentialPath:
        """
        Build a structured potential path from hypothesis data.
        """
        path_id = f"PATH-{hashlib.md5(title.encode()).hexdigest()[:6].upper()}"

        steps = []
        for i, step in enumerate(steps_data, 1):
            steps.append(PathStep(
                step_number=i,
                endpoint=step.get("endpoint", "unknown"),
                method=step.get("method", "GET"),
                state=FindingState(step.get("state", "HYPOTHESIS")),
                assumption=step.get("assumption", "Unknown assumption"),
                next_test=step.get("next_test", "Probe this endpoint"),
                evidence=step.get("evidence"),
            ))

        path = PotentialPath(
            path_id=path_id,
            title=title,
            entry_point=entry_point,
            steps=steps,
            risk_level=risk_level,
            required_assumptions=[s.assumption for s in steps],
            state=FindingState.HYPOTHESIS,
        )
        path.advance_state()
        self.potential_paths.append(path)
        return path

    def update_path_step(self, path_id: str, step_number: int,
                         new_state: FindingState,
                         evidence: Optional[EvidenceBundle] = None):
        """Update a path step when a probe returns evidence."""
        for path in self.potential_paths:
            if path.path_id == path_id:
                for step in path.steps:
                    if step.step_number == step_number:
                        step.state = new_state
                        step.evidence = evidence
                path.advance_state()
                return

    def get_summary(self) -> dict:
        """Summary of pipeline state."""
        confirmed_paths = [p for p in self.potential_paths
                           if p.state == FindingState.CONFIRMED]
        return {
            "hypotheses_tested":  self.tested_count,
            "confirmed_findings": len(self.confirmed),
            "refuted_findings":   len(self.refuted),
            "potential_paths":    len(self.potential_paths),
            "confirmed_paths":    len(confirmed_paths),
            "confirmation_rate":  round(
                len(self.confirmed) / max(self.tested_count, 1), 2
            ),
        }

    def format_refuted(self) -> str:
        """Format all negative validations for report."""
        if not self.refuted:
            return "No endpoints refuted this session."
        lines = ["## Negative Validations (Tested — NOT Vulnerable)\n"]
        for neg in self.refuted:
            lines.append(neg.format())
            lines.append("")
        return "\n".join(lines)

    def format_confirmed(self) -> str:
        """Format all confirmed findings with full evidence."""
        if not self.confirmed:
            return "No confirmed vulnerabilities this session."
        lines = ["## Confirmed Vulnerabilities (With Evidence)\n"]
        for bundle in self.confirmed:
            lines.append(bundle.format())
            lines.append("")
        return "\n".join(lines)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _classify_response(self, content: str, ctype: str, size: int) -> str:
        if "json" in ctype.lower() or (
            content.strip().startswith(("{", "[")) and size > 0
        ):
            return "JSON"
        if "html" in ctype.lower():
            return "HTML"
        if content.strip():
            return "TEXT"
        return "EMPTY"

    def _count_records(self, content: str, rtype: str) -> Optional[int]:
        if rtype != "JSON":
            return None
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return len(data)
            if isinstance(data, dict):
                for key in ["data", "items", "results"]:
                    if key in data and isinstance(data[key], list):
                        return len(data[key])
        except (json.JSONDecodeError, ValueError):
            pass
        return None

    def _find_sensitive_fields(self, content: str) -> list[str]:
        from sentinel.core.evidence import find_sensitive_fields_in_json
        return find_sensitive_fields_in_json(content)[:5]

    def _build_proof(self, content: str, rtype: str, status: int,
                     sensitive: list[str]) -> Optional[str]:
        """Build a sanitized proof snippet."""
        if status != 200 or not content:
            return None
        if rtype == "JSON":
            try:
                data = json.loads(content)
                if isinstance(data, list) and data:
                    first = data[0] if isinstance(data[0], dict) else {}
                    keys  = list(first.keys())[:6]
                    snippet = f"Array[{len(data)}], first record keys: {keys}"
                    if sensitive:
                        snippet += f" | ⚠ Contains: {', '.join(sensitive[:3])}"
                    return snippet
                elif isinstance(data, dict):
                    for key in ["data", "items"]:
                        if key in data and isinstance(data[key], list):
                            inner = data[key]
                            keys  = list(inner[0].keys())[:6] if inner and isinstance(inner[0], dict) else []
                            return f"{{'{key}': Array[{len(inner)}]}}, record keys: {keys}"
                    return f"Object keys: {list(data.keys())[:6]}"
            except (json.JSONDecodeError, ValueError):
                return content[:100]
        if rtype == "HTML":
            return "[HTML response — not structured data]"
        return content[:100]

    def _is_spa_shell(self, size: int, ctype: str) -> bool:
        return self.SPA_SIZE_MIN < size < self.SPA_SIZE_MAX and "html" in ctype.lower()

    def _status_text(self, status: int) -> str:
        return {
            200: "OK", 201: "Created", 204: "No Content",
            301: "Moved", 302: "Found",
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
            404: "Not Found", 405: "Method Not Allowed",
            429: "Too Many Requests", 500: "Internal Server Error",
            503: "Service Unavailable",
        }.get(status, str(status))


# ── Hard promotion rule enforcer ──────────────────────────────────────────────
# These are the non-bypassable rules referenced in the architecture.
# Called BEFORE any state transition. Raises if criteria not met.

class PromotionRules:
    """
    Non-bypassable promotion rules.
    No state transition happens without passing these checks.
    """

    @staticmethod
    def can_promote_to_tested(request_sent: bool, response_received: bool) -> tuple[bool, str]:
        if not request_sent:
            return False, "Cannot promote to TESTED: no request was sent"
        if not response_received:
            return False, "Cannot promote to TESTED: no response received"
        return True, "OK"

    @staticmethod
    def can_promote_to_confirmed(response: ResponseRecord,
                                  auth_sent: bool = False) -> tuple[bool, str]:
        """
        TESTED → CONFIRMED requires ALL of:
          - HTTP 200
          - Response type is JSON (not HTML/EMPTY)
          - proof_snippet is non-empty
          - size > 200 bytes
          - auth was NOT sent (auth_sent must be False)
          - NOT a SPA shell

        Fails IMMEDIATELY if any criterion is missing.
        auth_sent defaults to False for backwards compatibility with validate_evidence_bundle.
        """
        if response.status_code != 200:
            return False, f"Status {response.status_code} — only HTTP 200 can be CONFIRMED"

        if response.response_type == "HTML":
            return False, "HTML response — not structured data, cannot CONFIRM"

        if response.response_type == "EMPTY":
            return False, "Empty response — no evidence, cannot CONFIRM"

        if response.size_bytes < 200:
            return False, f"Response too small ({response.size_bytes}b) — insufficient evidence"

        if not response.proof_snippet:
            return False, "No proof snippet — evidence required for CONFIRMED state"

        if auth_sent:
            return False, "Auth was sent — cannot confirm auth bypass"

        return True, "OK"

    @staticmethod
    def must_be_inconclusive(status_code: int, response_type: str,
                              timed_out: bool = False) -> tuple[bool, str]:
        """
        Cases that MUST be INCONCLUSIVE — cannot be promoted or chained.
        """
        if timed_out:
            return True, "Request timed out — INCONCLUSIVE"
        if status_code >= 500:
            return True, f"HTTP {status_code} server error — INCONCLUSIVE"
        if response_type == "EMPTY" and status_code == 200:
            return True, "HTTP 200 but empty body — INCONCLUSIVE"
        return False, "Not inconclusive"

    @staticmethod
    def can_use_in_chain(state: FindingState) -> tuple[bool, str]:
        """
        Hard rule: only CONFIRMED findings can be used in attack chains.
        INFERRED, UNCONFIRMED, INCONCLUSIVE cannot anchor chains.
        """
        if state == FindingState.CONFIRMED:
            return True, "OK"
        return False, f"State is {state.value} — only CONFIRMED can be used in chains"

    @staticmethod
    def validate_evidence_bundle(bundle: 'EvidenceBundle') -> tuple[bool, str]:
        """
        Validate that a bundle meets minimum evidence requirements.
        Auto-downgrade to TESTED if it doesn't.
        """
        if not bundle.request.url:
            return False, "Missing request URL"
        if bundle.response.status_code == 0:
            return False, "Missing response status code"
        if bundle.finding_state == FindingState.CONFIRMED:
            ok, reason = PromotionRules.can_promote_to_confirmed(bundle.response)
            if not ok:
                return False, f"CONFIRMED requires: {reason}"
        return True, "OK"
