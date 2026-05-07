"""
sentinel/core/session_intelligence.py

SessionIntelligence — The authoritative source of truth for a scan session.

This is not a notes bucket. It is a structured, enforcement-capable memory layer.

Roles:
  1. Memory layer        — everything observed, confirmed, refuted, learned
  2. Deduplication layer — no URL probed twice, no finding created twice
  3. Coordination layer  — Queen and Alpha share this, see same state
  4. Promotion context   — scoring engine reads this to calibrate confidence
  5. Budget enforcer     — tracks and enforces request limits
  6. Stop condition mgr  — defines when investigation is genuinely complete

Every endpoint record contains:
  - What was tested (method, URL, timestamp)
  - What happened (status, type, size, auth behavior)
  - What it means (CONFIRMED / DISPROVEN / INCONCLUSIVE)
  - Why it was classified that way (specific reason)
  - What to do next (retest policy)
  - Full evidence object reference
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
from sentinel.core.models import EvidenceRef, DataSurfaceType  # defined in models.py — shared with Finding


# ── State definitions ─────────────────────────────────────────────────────────

class ProbeOutcome(str, Enum):
    CONFIRMED    = "CONFIRMED"     # Vulnerable — full evidence attached
    DISPROVEN    = "DISPROVEN"     # NOT vulnerable — reason documented
    INCONCLUSIVE = "INCONCLUSIVE"  # Tested but ambiguous
    UNTESTED     = "UNTESTED"      # Not yet probed


class DisproveReason(str, Enum):
    AUTH_ENFORCED    = "AUTH_ENFORCED"    # 401/403 — access control working
    SPA_FALLBACK     = "SPA_FALLBACK"     # HTML SPA shell, no server data
    NOT_FOUND        = "NOT_FOUND"        # 404 — endpoint doesn't exist
    EMPTY_RESPONSE   = "EMPTY_RESPONSE"   # 200 but < 200 bytes
    SERVER_ERROR     = "SERVER_ERROR"     # 500 — broken but not vulnerable
    NO_RESPONSE      = "NO_RESPONSE"      # Timeout or connection refused
    WRONG_FORMAT     = "WRONG_FORMAT"     # Response format unexpected


class RetestPolicy(str, Enum):
    NEVER          = "NEVER"           # Do not probe again under any condition
    IF_AUTH_ADDED  = "IF_AUTH_ADDED"   # Only retry if auth token available
    IF_DIFFERENT_METHOD = "IF_DIFFERENT_METHOD"  # Try a different HTTP method
    AFTER_N_CYCLES = "AFTER_N_CYCLES"  # Can retry after 3+ cycles
    ALWAYS_SKIP    = "ALWAYS_SKIP"     # SPA fallback — skip completely


class AuthBehavior(str, Enum):
    REQUIRES_AUTH   = "REQUIRES_AUTH"    # Returns 401/403 without token
    NO_AUTH_NEEDED  = "NO_AUTH_NEEDED"   # Returns data without auth
    AUTH_IRRELEVANT = "AUTH_IRRELEVANT"  # SPA / static content
    UNKNOWN         = "UNKNOWN"          # Not yet determined


class StopCondition(str, Enum):
    BUDGET_EXHAUSTED      = "BUDGET_EXHAUSTED"
    ALL_PATHS_SETTLED     = "ALL_PATHS_SETTLED"   # Every path confirmed or disproven
    MAX_CYCLES_REACHED    = "MAX_CYCLES_REACHED"
    MANUAL_STOP           = "MANUAL_STOP"
    SUFFICIENT_EVIDENCE   = "SUFFICIENT_EVIDENCE"  # Enough to write report


# ── Core data structures ──────────────────────────────────────────────────────

@dataclass
class EndpointRecord:
    """
    Complete record for a single endpoint.
    This is the unit of session intelligence — not a string, a structured object.
    """
    url:             str
    outcome:         ProbeOutcome
    auth_behavior:   AuthBehavior
    evidence:        Optional[EvidenceRef]
    disprove_reason: Optional[DisproveReason]
    retest_policy:   RetestPolicy
    classification_reason: str        # Why it was classified this way
    cycle_discovered: int
    confidence:      float = 0.0      # Confidence in the outcome
    chain_candidate: bool = False     # Could this be part of an attack chain?
    related_endpoints: list[str] = field(default_factory=list)

    def format_short(self) -> str:
        icon = "[OK]"      if self.outcome == ProbeOutcome.CONFIRMED    else \
               "[FAIL]"    if self.outcome == ProbeOutcome.DISPROVEN    else \
               "[INFO]"    if self.outcome == ProbeOutcome.INCONCLUSIVE else \
               "[UNKNOWN]"
        return (f"{icon} {self.url} [{self.outcome.value}] "
                f"-- {self.classification_reason[:60]}")

    def format_full(self) -> str:
        lines = [
            f"Endpoint:     {self.url}",
            f"Outcome:      {self.outcome.value}",
            f"Auth:         {self.auth_behavior.value}",
            f"Reason:       {self.classification_reason}",
            f"Retest:       {self.retest_policy.value}",
            f"Confidence:   {self.confidence:.2f}",
            f"Chain cand:   {self.chain_candidate}",
        ]
        if self.disprove_reason:
            lines.append(f"Disproved:    {self.disprove_reason.value}")
        if self.evidence:
            lines.append(f"\nEvidence:\n{self.evidence.format()}")
        return "\n".join(lines)


@dataclass
class ChainCandidate:
    """
    A potential attack chain — confirmed findings that could link together.
    Only built from CONFIRMED endpoints.
    """
    candidate_id: str
    title:        str
    endpoints:    list[str]         # CONFIRMED endpoints in this path
    confidence:   float
    severity:     str
    evidence_count: int = 0
    promoted:     bool = False      # Has this been promoted to a full chain?


@dataclass
class LearnedBehavior:
    """Structured behavioral knowledge — not free text."""
    namespace:   str       # e.g. "/api/", "/rest/admin/"
    auth_pattern: AuthBehavior
    url_pattern: str       # e.g. "Capitalize resource names"
    examples:    list[str] = field(default_factory=list)
    confidence:  float = 0.5
    discovered_at: int = 0


@dataclass
class RootCause:
    """Multiple endpoints with the same underlying vulnerability."""
    root_id:     str
    title:       str
    category:    str
    pattern:     str
    severity:    str
    endpoints:   list[str] = field(default_factory=list)
    evidence_count: int = 0
    next_action: str = ""
    verified:    bool = False
    # ── Phase 8: blast radius dedup fields ────────────────────────────────────
    aggregate_record_count:  Optional[int]  = None   # sum of PRIMARY endpoints only
    aggregate_bytes:         Optional[int]  = None   # sum of PRIMARY endpoints only
    response_signatures:     list[str]      = field(default_factory=list)  # sha256 of proof_snippets seen
    data_surface_breakdown:  dict           = field(default_factory=dict)  # url → "PRIMARY"|"DERIVATIVE"


# ── Session Intelligence ──────────────────────────────────────────────────────

class SessionIntelligence:
    """
    The authoritative source of truth for the entire scan session.

    Roles:
      1. Memory layer         — everything observed, confirmed, refuted
      2. Deduplication layer  — no URL probed twice
      3. Coordination layer   — Queen and Alpha share this
      4. Promotion context    — calibrates confidence scoring
      5. Budget enforcer      — tracks and limits request counts
      6. Stop condition mgr   — knows when to stop
    """

    # Budget defaults per mode
    BUDGETS = {
        "PASSIVE": 50,
        "PROBE":   300,
        "ACTIVE":  600,
        "AUDIT":   400,
    }

    def __init__(self, target: str, mode: str = "PROBE"):
        self.target       = target
        self.mode         = mode
        self.session_id   = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        self.started_at   = datetime.now(timezone.utc).isoformat()
        self.current_cycle = 0

        # ── Core memory stores ────────────────────────────────────────────────
        # Keyed by URL for O(1) lookup
        self.endpoints:  dict[str, EndpointRecord] = {}

        # Indexed views for fast access
        self.confirmed_urls:    set[str] = set()
        self.disproven_urls:    set[str] = set()
        self.inconclusive_urls: set[str] = set()

        # ── Behavioral intelligence ───────────────────────────────────────────
        self.behaviors:  list[LearnedBehavior] = []
        self.root_causes: list[RootCause] = []
        self.chain_candidates: list[ChainCandidate] = []

        # ── Coordination ──────────────────────────────────────────────────────
        self.queen_objectives_completed: list[str] = []
        self.queen_objectives_failed:    list[str] = []
        self.alpha_cycles_used:          int = 0

        # ── Budget tracking ───────────────────────────────────────────────────
        self.budget_total:     int = self.BUDGETS.get(mode, 300)
        self.budget_used:      int = 0
        self.budget_by_domain: dict[str, int] = {}

        # ── Stop conditions ───────────────────────────────────────────────────
        self.stop_condition:   Optional[StopCondition] = None
        self.stop_triggered:   bool = False

        # ── Statistics ────────────────────────────────────────────────────────
        self.probes_prevented: int = 0   # Reprobe attempts blocked
        self.hallucinations_blocked: int = 0
        self.duplicates_removed: int = 0
        self.untested_queue:   list[str] = []  # Endpoints discovered by agents, queued for Alpha
        self.inconclusive_counts: dict[str, int] = {}  # How many times each URL returned inconclusive

        # Request failure tracking — keyed by (agent_name, failure_class)
        # failure_class: timeout | dns | tls | connection_refused | other
        # Updated by SessionIntelligence.record_request_failure()
        self.request_failures:  dict[tuple, int] = {}

        # Last known failure reason per URL — preserves debugging detail
        # without storing full event history.
        # Keyed by url → {"failure_class": str, "failure_reason": str, "agent": str}
        self.recent_failure_detail: dict[str, dict] = {}

        # Attack graph — drives chain-based investigation
        from sentinel.core.attack_graph import AttackGraph
        self.attack_graph: AttackGraph = AttackGraph()

    # ── Core probe lifecycle ──────────────────────────────────────────────────

    def should_probe(self, url: str) -> tuple[bool, str]:
        """
        The central guard. Called before EVERY probe.
        Returns (should_probe, reason_if_not).

        This makes loops structurally impossible.
        """
        # Budget check first
        if self.budget_used >= self.budget_total:
            self.stop_triggered = True
            self.stop_condition = StopCondition.BUDGET_EXHAUSTED
            return False, f"Budget exhausted ({self.budget_used}/{self.budget_total})"

        # Stop condition check
        if self.stop_triggered:
            return False, f"Stop condition: {self.stop_condition.value}"

        # Known outcome checks
        if url in self.confirmed_urls:
            self.probes_prevented += 1
            ep = self.endpoints.get(url)
            return False, f"CONFIRMED — skip (evidence: {ep.evidence.proof_snippet[:40] if ep and ep.evidence else 'captured'})"

        if url in self.disproven_urls:
            self.probes_prevented += 1
            ep = self.endpoints.get(url)
            reason = ep.disprove_reason.value if ep and ep.disprove_reason else "disproven"
            retest = ep.retest_policy.value if ep else "NEVER"
            if retest == RetestPolicy.NEVER.value or retest == RetestPolicy.ALWAYS_SKIP.value:
                return False, f"DISPROVEN ({reason}) — retest policy: {retest}"
            # Some policies allow retry
            if retest == RetestPolicy.IF_AUTH_ADDED.value:
                return False, f"DISPROVEN ({reason}) — retry only with auth token"

        if url in self.inconclusive_urls:
            count = self.inconclusive_counts.get(url, 0)
            if count >= 2:
                # Hard stop — probed twice, both inconclusive, not worth retrying
                self.probes_prevented += 1
                return False, f"INCONCLUSIVE x{count} — hard stop after 2 attempts"
            ep = self.endpoints.get(url)
            if ep and ep.cycle_discovered >= self.current_cycle - 1:
                self.probes_prevented += 1
                return False, f"INCONCLUSIVE — too recent to retry (cycle {ep.cycle_discovered})"

        return True, "Proceed"

    def record_confirmed(self, url: str, evidence: EvidenceRef,
                         confidence: float = 0.85) -> EndpointRecord:
        """
        Register a confirmed finding with full evidence.

        Precedence rules (explicit):
          CONFIRMED > DISPROVEN > INCONCLUSIVE
          - If already CONFIRMED: no-op (idempotent)
          - If previously DISPROVEN: allowed only with HTTP 200 + JSON evidence
            (authentication was added, or endpoint was re-classified correctly)
          - If previously INCONCLUSIVE: allowed — CONFIRMED outranks it
        """
        # Idempotent: already confirmed
        if url in self.confirmed_urls:
            return self.endpoints.get(url)

        # Validate evidence before accepting CONFIRMED state
        ok, reason = evidence.is_sufficient_for_confirmation()
        if not ok:
            print(f"[INTEL] [WARN] Cannot CONFIRM {url}: {reason} -- downgrading to INCONCLUSIVE")
            return self.record_inconclusive(url, evidence, f"Evidence insufficient: {reason}")

        ep = EndpointRecord(
            url=url,
            outcome=ProbeOutcome.CONFIRMED,
            auth_behavior=AuthBehavior.NO_AUTH_NEEDED,
            evidence=evidence,
            disprove_reason=None,
            retest_policy=RetestPolicy.NEVER,
            classification_reason=(
                f"HTTP {evidence.status_code} | {evidence.response_type} | "
                f"{evidence.size_bytes}b | no auth sent"
                + (f" | {evidence.record_count} records" if evidence.record_count else "")
                + (f" | sensitive: {','.join(evidence.sensitive_fields[:2])}" if evidence.sensitive_fields else "")
            ),
            cycle_discovered=self.current_cycle,
            confidence=confidence,
            chain_candidate=True,  # Confirmed findings are chain candidates
        )
        self.endpoints[url] = ep
        self.confirmed_urls.add(url)
        # Enforce mutual exclusivity — URL must be in exactly one outcome set
        # CONFIRMED outranks all weaker states: remove from both
        self.disproven_urls.discard(url)
        self.inconclusive_urls.discard(url)
        # budget_used tracks unique endpoint classification outcomes, not raw HTTP requests.
        # One URL may require zero or many HTTP requests before it reaches CONFIRMED state.
        self.budget_used += 1
        # Remove from untested queue if present
        if url in self.untested_queue:
            self.untested_queue.remove(url)
        self._update_root_cause(url, evidence)
        self._evaluate_chain_candidates()
        self._check_stop_conditions()

        # Fire attack graph — chain-based next steps go to FRONT of queue
        next_steps = self.attack_graph.record_confirmed(
            url=url,
            evidence_summary=evidence.proof_snippet or evidence.format()[:100],
            session_intel=self,
        )
        if next_steps:
            for step_url in reversed(next_steps):
                if (step_url not in self.confirmed_urls and
                        step_url not in self.disproven_urls and
                        self.inconclusive_counts.get(step_url, 0) < 2 and
                        step_url not in self.untested_queue):
                    self.untested_queue.insert(0, step_url)
            print(f"[CHAIN] Queued {len(next_steps)} chain-driven next steps at queue front")

        # Notify eval harness of first confirmed finding (for time-to-confirm metric)
        try:
            import sentinel.agents._eval_ref as _eref
        except ImportError as e:
            import sys
            print(f"[WARN] eval harness import failed: {e}", file=sys.stderr)
        else:
            import sys
            harness = getattr(_eref, "current_harness", None)
            if harness is None:
                print("[WARN] eval harness not set -- time-to-confirm will not be recorded",
                      file=sys.stderr)
            elif not hasattr(harness, "record_first_confirmed"):
                print("[WARN] eval harness missing record_first_confirmed -- skipping",
                      file=sys.stderr)
            else:
                harness.record_first_confirmed()

        return ep

    def record_disproven(self, url: str, reason: DisproveReason,
                         evidence: Optional[EvidenceRef] = None,
                         status_code: int = 0) -> EndpointRecord:
        """
        Register a disproven endpoint.

        Precedence rules (explicit):
          - CONFIRMED outranks DISPROVEN — never overwrite a confirmed finding
          - DISPROVEN is idempotent — already disproven returns existing record
          - INCONCLUSIVE → DISPROVEN allowed (stronger negative signal)
        """
        # CONFIRMED outranks DISPROVEN — this endpoint has real data, don't overwrite
        if url in self.confirmed_urls:
            return self.endpoints.get(url)

        # Idempotent: already disproven
        if url in self.disproven_urls:
            ep = self.endpoints.get(url)
            if ep is None:
                # State integrity issue: in disproven_urls but not in endpoints
                # Log and return None — do NOT fall through and create a new record.
                # Falling through would re-increment budget_used and re-add to disproven_urls.
                print(f"[INTEL] [WARN] State integrity: {url} in disproven_urls but missing from endpoints")
                return None
            return ep

        retest = self._get_retest_policy(reason)
        auth_behavior = AuthBehavior.REQUIRES_AUTH if reason == DisproveReason.AUTH_ENFORCED else \
                        AuthBehavior.AUTH_IRRELEVANT if reason == DisproveReason.SPA_FALLBACK else \
                        AuthBehavior.UNKNOWN

        reason_text = {
            DisproveReason.AUTH_ENFORCED:  "HTTP 401/403 — authentication enforced, access control working",
            DisproveReason.SPA_FALLBACK:   "SPA shell (~75KB HTML) — client-side route, no server data",
            DisproveReason.NOT_FOUND:      "HTTP 404 — endpoint does not exist",
            DisproveReason.EMPTY_RESPONSE: "Response too small — no meaningful content",
            DisproveReason.SERVER_ERROR:   "HTTP 5xx — server error, endpoint broken not vulnerable",
            DisproveReason.NO_RESPONSE:    "Connection failed — endpoint unreachable",
        }.get(reason, reason.value)

        ep = EndpointRecord(
            url=url,
            outcome=ProbeOutcome.DISPROVEN,
            auth_behavior=auth_behavior,
            evidence=evidence,
            disprove_reason=reason,
            retest_policy=retest,
            classification_reason=reason_text,
            cycle_discovered=self.current_cycle,
            confidence=0.90,
            chain_candidate=False,
        )
        self.endpoints[url] = ep
        self.disproven_urls.add(url)
        # Remove from inconclusive tracking if promoted to disproven
        self.inconclusive_urls.discard(url)
        # Remove from queue — settled endpoints must not linger as pending work
        if url in self.untested_queue:
            self.untested_queue.remove(url)
        # budget_used tracks unique endpoint classification outcomes, not raw HTTP requests.
        # One URL may require zero or many HTTP requests before it reaches DISPROVEN state.
        self.budget_used += 1
        return ep

    def record_inconclusive(self, url: str,
                             evidence: Optional[EvidenceRef] = None,
                             reason: str = "HTTP 500 or ambiguous") -> EndpointRecord:
        """
        Register an inconclusive probe.

        Precedence rules (explicit):
          INCONCLUSIVE is the weakest state — never overwrites settled state
          - CONFIRMED → stays CONFIRMED (INCONCLUSIVE is ignored)
          - DISPROVEN  → stays DISPROVEN (INCONCLUSIVE is ignored)
          - INCONCLUSIVE → count incremented, retry policy applied
        """
        # Remove from queue immediately — no longer pending regardless of outcome
        if url in self.untested_queue:
            self.untested_queue.remove(url)

        # CONFIRMED outranks INCONCLUSIVE — don't overwrite
        if url in self.confirmed_urls:
            return self.endpoints.get(url)

        # DISPROVEN outranks INCONCLUSIVE — don't overwrite
        if url in self.disproven_urls:
            return self.endpoints.get(url)

        ep = EndpointRecord(
            url=url,
            outcome=ProbeOutcome.INCONCLUSIVE,
            auth_behavior=AuthBehavior.UNKNOWN,
            evidence=evidence,
            disprove_reason=None,
            retest_policy=RetestPolicy.AFTER_N_CYCLES,
            classification_reason=reason,
            cycle_discovered=self.current_cycle,
            confidence=0.30,
            chain_candidate=False,
        )
        self.endpoints[url] = ep
        self.inconclusive_urls.add(url)
        self.inconclusive_counts[url] = self.inconclusive_counts.get(url, 0) + 1
        # budget_used tracks unique endpoint classification outcomes, not raw HTTP requests.
        # One URL may require zero or many HTTP requests before it reaches INCONCLUSIVE state.
        self.budget_used += 1
        return ep

    # ── Behavioral learning ───────────────────────────────────────────────────

    def learn_auth_behavior(self, namespace: str, behavior: AuthBehavior,
                             example_url: str):
        """Learn how a namespace handles authentication."""
        existing = [b for b in self.behaviors if b.namespace == namespace]
        if existing:
            existing[0].examples.append(example_url)
            existing[0].confidence = min(0.99, existing[0].confidence + 0.1)
        else:
            self.behaviors.append(LearnedBehavior(
                namespace=namespace,
                auth_pattern=behavior,
                url_pattern="",
                examples=[example_url],
                confidence=0.7,
                discovered_at=self.current_cycle,
            ))

    def learn_url_pattern(self, pattern: str, namespace: str,
                          example: str, confidence: float = 0.7):
        """Learn a URL pattern (e.g. 'capitalize resource names in /api/')."""
        existing = [b for b in self.behaviors
                    if b.namespace == namespace and b.url_pattern == pattern]
        if existing:
            existing[0].confidence = min(0.99, existing[0].confidence + 0.05)
            existing[0].examples.append(example)
        else:
            self.behaviors.append(LearnedBehavior(
                namespace=namespace,
                auth_pattern=AuthBehavior.UNKNOWN,
                url_pattern=pattern,
                examples=[example],
                confidence=confidence,
                discovered_at=self.current_cycle,
            ))

    def get_auth_expectation(self, url: str) -> AuthBehavior:
        """What do we expect for auth at this URL based on learned patterns?"""
        for behavior in sorted(self.behaviors,
                                key=lambda b: b.confidence, reverse=True):
            if behavior.namespace and behavior.namespace in url:
                return behavior.auth_pattern
        return AuthBehavior.UNKNOWN

    # ── Root cause grouping ───────────────────────────────────────────────────

    def _update_root_cause(self, url: str, evidence: EvidenceRef):
        """
        Authoritative root cause grouping — Phase 8.

        Dedup key: (normalize_url(url), vulnerability_class_pattern)
        DataSurfaceType classification:
          1. Canonical dataset key match (explicit map) — PRIMARY/DERIVATIVE
          2. Response signature hash fallback (sha256 of proof_snippet[:200])
        Blast radius dedup: aggregate record_count from PRIMARY endpoints only.
        Severity elevation: admin/config context → CRITICAL unconditionally.
        """
        import hashlib

        # Infer pattern from evidence
        if evidence.sensitive_fields:
            pattern  = "sensitive_data_exposure"
            category = "Sensitive Data Protection"
            severity = "HIGH"
        elif not evidence.auth_sent and evidence.status_code == 200:
            pattern  = "unauthenticated_api"
            category = "Authorization / Access Control"
            severity = "HIGH"
        else:
            return

        # ── normalize: admin/config context always elevates to CRITICAL ───────
        _admin_signals = ("admin", "config", "management", "internal", "system", "setup")
        if any(s in url.lower() for s in _admin_signals):
            severity = "CRITICAL"

        # ── canonical dataset map ─────────────────────────────────────────────
        # Maps URL path substrings → canonical dataset key.
        # First endpoint matching a key = PRIMARY; subsequent = DERIVATIVE.
        # Extend this map as new targets are scanned.
        CANONICAL_DATASETS: dict[str, str] = {
            "/api/products":          "products",
            "/rest/products/search":  "products",
            "/rest/products/":        "products",
            "/api/feedbacks":         "feedbacks",
            "/rest/feedbacks":        "feedbacks",
            "/api/users":             "users",
            "/rest/users":            "users",
            "/api/challenges":        "challenges",
            "/api/quantitys":         "quantities",
            "/api/quantities":        "quantities",
            "/api/orders":            "orders",
            "/rest/orders":           "orders",
            "/api/complaints":        "complaints",
            "/api/baskets":           "baskets",
        }

        def _norm(u: str) -> str:
            try:
                from urllib.parse import urlparse, urlunparse
                p = urlparse(u.strip().lower())
                return urlunparse((p.scheme, p.netloc, p.path.rstrip("/"), "", "", ""))
            except Exception:
                return u.strip().lower()

        url_lower = url.lower()
        dataset_key = next(
            (dk for path_fragment, dk in CANONICAL_DATASETS.items()
             if path_fragment in url_lower),
            None
        )

        # ── dedup key: (normalized_url, pattern) ─────────────────────────────
        dedup_key = (_norm(url), pattern)

        # Reject if this exact (url, pattern) pair is already registered
        for rc in self.root_causes:
            if rc.pattern == pattern:
                for ep_url in rc.endpoints:
                    if (_norm(ep_url), pattern) == dedup_key:
                        return  # already grouped — idempotent

        # ── response signature fallback (hash-based) ──────────────────────────
        proof = getattr(evidence, "proof_snippet", None) or ""
        sig   = hashlib.sha256(proof[:200].encode("utf-8", errors="replace")).hexdigest()[:16]
        if not proof:
            sig = hashlib.sha256(
                f"{url}:{evidence.record_count}:{evidence.size_bytes}".encode()
            ).hexdigest()[:16]

        # ── group: find existing root cause for this pattern ──────────────────
        for rc in self.root_causes:
            if rc.pattern == pattern:
                # Determine surface type:
                # 1. Canonical key match → DERIVATIVE if key already seen
                # 2. Hash match → DERIVATIVE
                # 3. Otherwise → PRIMARY
                rc_dataset_keys = set(
                    rc.data_surface_breakdown.get("_dataset_keys_seen", "").split(",")
                )
                rc_dataset_keys.discard("")

                if dataset_key and dataset_key in rc_dataset_keys:
                    surface = DataSurfaceType.DERIVATIVE.value
                elif dataset_key is None and sig in rc.response_signatures:
                    surface = DataSurfaceType.DERIVATIVE.value
                else:
                    surface = DataSurfaceType.PRIMARY.value
                    rc.response_signatures.append(sig)
                    if dataset_key:
                        rc_dataset_keys.add(dataset_key)
                        rc.data_surface_breakdown["_dataset_keys_seen"] = ",".join(rc_dataset_keys)
                    # Aggregate only PRIMARY endpoints
                    if evidence.record_count is not None:
                        rc.aggregate_record_count = (rc.aggregate_record_count or 0) + evidence.record_count
                    if evidence.size_bytes:
                        rc.aggregate_bytes = (rc.aggregate_bytes or 0) + evidence.size_bytes

                rc.endpoints.append(url)
                rc.evidence_count += 1
                rc.verified = True
                rc.data_surface_breakdown[url] = surface
                # Elevate severity if this endpoint is admin context
                if severity == "CRITICAL":
                    rc.severity = "CRITICAL"
                return

        # ── group: create new root cause ──────────────────────────────────────
        rc_id = f"RC-{len(self.root_causes)+1:03d}"
        initial_dataset_keys = dataset_key or ""
        new_rc = RootCause(
            root_id=rc_id,
            title=self._pattern_to_title(pattern),
            category=category,
            pattern=pattern,
            severity=severity,
            endpoints=[url],
            evidence_count=1,
            next_action=self._get_next_action(pattern),
            verified=True,
            aggregate_record_count=evidence.record_count if evidence.record_count is not None else None,
            aggregate_bytes=evidence.size_bytes or None,
            response_signatures=[sig],
            data_surface_breakdown={
                url: DataSurfaceType.PRIMARY.value,
                "_dataset_keys_seen": initial_dataset_keys,
            },
        )
        self.root_causes.append(new_rc)

    def _pattern_to_title(self, pattern: str) -> str:
        return {
            "unauthenticated_api":   "Missing Authentication Enforcement",
            "unauthenticated_admin": "Unauthenticated Administrative Access",
            "no_rate_limiting":      "Missing Rate Limiting on Auth Endpoints",
            "dangerous_methods":     "Dangerous HTTP Methods Allowed",
            "sql_injection":         "SQL Injection Condition Detected",
            "sensitive_data_exposure": "Sensitive Data Exposure in API Response",
        }.get(pattern, f"Security Issue: {pattern}")

    def _get_next_action(self, pattern: str) -> str:
        return {
            "unauthenticated_api":   "Verify with authenticated session — same data returned?",
            "unauthenticated_admin": "Test admin functions with auth token for real impact scope",
            "no_rate_limiting":      "Send 10 rapid requests — verify no HTTP 429",
            "dangerous_methods":     "Test OPTIONS — confirm DELETE/PUT in Allow header",
            "sql_injection":         "WSTG-INPV-05: Test boolean-based detection — compare server responses to logically equivalent vs inequivalent conditions",
            "sensitive_data_exposure": "Document all sensitive fields returned without auth",
        }.get(pattern, "Manual review required")

    # ── Chain candidates ──────────────────────────────────────────────────────

    def _evaluate_chain_candidates(self):
        """Evaluate if confirmed findings can form attack chains."""
        confirmed_list = [
            self.endpoints[url]
            for url in self.confirmed_urls
            if url in self.endpoints
        ]

        if len(confirmed_list) < 2:
            return

        # Check for classic chains
        has_config = any("config" in ep.url.lower() for ep in confirmed_list)
        has_api    = any("/api/" in ep.url for ep in confirmed_list)
        has_admin  = any("admin" in ep.url.lower() for ep in confirmed_list)

        if has_config and has_api:
            self._add_chain_candidate(
                "Configuration + API Exposure",
                [ep.url for ep in confirmed_list
                 if "config" in ep.url.lower() or "/api/" in ep.url],
                "CRITICAL", 0.80,
            )

        if has_admin and has_api:
            self._add_chain_candidate(
                "Admin + API Access Chain",
                [ep.url for ep in confirmed_list
                 if "admin" in ep.url.lower() or "/api/" in ep.url],
                "CRITICAL", 0.75,
            )

    def _add_chain_candidate(self, title: str, endpoints: list[str],
                              severity: str, confidence: float):
        """Add or update a chain candidate."""
        for cc in self.chain_candidates:
            if cc.title == title:
                cc.confidence = max(cc.confidence, confidence)
                cc.evidence_count = len(endpoints)
                return
        self.chain_candidates.append(ChainCandidate(
            candidate_id=f"CC-{len(self.chain_candidates)+1:03d}",
            title=title,
            endpoints=endpoints,
            confidence=confidence,
            severity=severity,
            evidence_count=len(endpoints),
        ))

    # ── Stop conditions ───────────────────────────────────────────────────────

    def _check_stop_conditions(self):
        """Evaluate whether investigation should stop."""
        if self.budget_used >= self.budget_total:
            self.stop_triggered = True
            self.stop_condition = StopCondition.BUDGET_EXHAUSTED
            return

        # Sufficient evidence — based on confirmed finding count and severity
        # Rules (code matches comment exactly):
        #   2+ confirmed with HIGH/CRITICAL severity → sufficient
        #   5+ confirmed (any severity) with 2+ chain candidates → sufficient
        confirmed_high_or_critical = sum(
            1 for rc in self.root_causes
            if getattr(rc, 'severity', '') == 'CRITICAL'
            or getattr(rc, 'severity', '') == 'HIGH'
        )
        if confirmed_high_or_critical >= 2 and len(self.chain_candidates) >= 1:
            self.stop_condition = StopCondition.SUFFICIENT_EVIDENCE
        elif len(self.confirmed_urls) >= 5 and len(self.chain_candidates) >= 2:
            self.stop_condition = StopCondition.SUFFICIENT_EVIDENCE
        # Don't stop execution — signal Queen to consider concluding

    def should_stop(self) -> tuple[bool, str]:
        """Should the investigation end?"""
        if self.stop_triggered:
            return True, f"Stop condition: {self.stop_condition.value if self.stop_condition else 'triggered'}"
        if self.budget_used >= int(self.budget_total * 0.9):
            return True, f"Budget nearly exhausted ({self.budget_used}/{self.budget_total})"
        return False, "Continue"

    # ── Queen coordination ────────────────────────────────────────────────────

    def queen_should_investigate(self, objective: str) -> tuple[bool, str]:
        """
        Queen checks if an objective is worth pursuing.
        Prevents Queen from repeating settled territory or generating invalid objectives.
        """
        obj_lower = objective.lower()

        # Hard blocks — these objective types are never valid
        BLOCKED_PATTERNS = [
            ("credential stuffing", "Credential stuffing requires confirmed rate limit absence"),
            ("brute force", "Brute force requires confirmed rate limit absence"),
            ("rapid credential", "Credential attacks require confirmed rate limit absence"),
            ("credential enumeration", "Credential enumeration requires confirmed rate limit absence"),
            ("credential harvest", "Credential harvesting is offensive — not in PROBE scope"),
            ("password spray", "Password spraying requires confirmed rate limit absence"),
            ("rate limit absence", "Rate limit absence objective — cannot exploit in PROBE mode"),
            ("version-specific", "Version endpoint speculation — not confirmed in JS discovery"),
            ("version specific", "Version endpoint speculation — not confirmed in JS discovery"),
            ("api version", "Version endpoint speculation — not confirmed in JS discovery"),
            ("older api", "Version endpoint speculation — not confirmed in JS discovery"),
            ("legacy endpoint", "Version endpoint speculation — not confirmed in JS discovery"),
        ]
        for pattern, reason in BLOCKED_PATTERNS:
            if pattern in obj_lower:
                return False, f"BLOCKED: {reason}"

        # Version path block — only when combined with speculation language.
        # Bare version paths (v1/, /api/v1) are NOT blocked because a target's
        # real confirmed API may live at those paths. Only block when the objective
        # uses guessing language ("try", "older", "legacy", "alternate", "previous")
        # alongside a version path, which signals speculation rather than confirmed investigation.
        _VERSION_PATHS = ("v1/", "v2/", "v3/", "/api/v1", "/api/v2", "/api/v3", "/rest/v1")
        _SPECULATION   = ("try ", "try/", "older", "legacy", "alternate", "previous", "instead")
        if (any(v in obj_lower for v in _VERSION_PATHS) and
                any(s in obj_lower for s in _SPECULATION)):
            return False, "BLOCKED: Version endpoint speculation — version path with guessing language"

        def _norm_url(url: str) -> str:
            """Strip query, fragment, trailing slash, lowercase — for exact URL comparison."""
            try:
                from urllib.parse import urlparse, urlunparse
                p = urlparse(url.strip().lower())
                return urlunparse((p.scheme, p.netloc, p.path.rstrip("/"), "", "", ""))
            except Exception:
                return url.strip().lower()

        # Don't investigate endpoints that were already refuted as SPA.
        # Block only when the full normalized URL appears in the objective text —
        # not on path fragment like "users" or "login".
        for url in self.disproven_urls:
            ep = self.endpoints.get(url)
            if (ep and hasattr(ep, 'disprove_reason') and
                    ep.disprove_reason and 'SPA' in str(ep.disprove_reason)):
                norm = _norm_url(url)
                if norm and norm in obj_lower:
                    return False, f"BLOCKED: {url} was SPA — no server-side data"

        # Don't investigate confirmed territory.
        # Block only when the full normalized URL appears in the objective text.
        for url in self.confirmed_urls:
            norm = _norm_url(url)
            if norm and norm in obj_lower:
                return False, f"Already CONFIRMED: {url} — no need to reinvestigate"

        # Don't repeat completed objectives
        for completed in self.queen_objectives_completed:
            if self._objectives_similar(obj_lower, completed.lower()):
                return False, f"Similar objective already done: {completed[:60]}"

        return True, "New territory — proceed"

    def record_queen_objective(self, objective: str, success: bool):
        if success:
            self.queen_objectives_completed.append(objective[:120])
        else:
            self.queen_objectives_failed.append(objective[:120])

    def _objectives_similar(self, obj1: str, obj2: str) -> bool:
        # Objectives covering different explicit namespaces are never similar
        # /rest/admin/ and /api/ are different attack surfaces
        NAMESPACES = ['/api/', '/rest/admin/', '/rest/products/',
                      '/rest/user/', '/graphql', '/admin/']
        ns1 = {ns for ns in NAMESPACES if ns in obj1}
        ns2 = {ns for ns in NAMESPACES if ns in obj2}
        if ns1 and ns2 and ns1 != ns2:
            return False  # Different namespaces — always allow both

        skip = {"test", "exploit", "enumerate", "attempt", "analyze",
                "probe", "check", "verify", "confirm", "investigate"}
        def key_terms(obj: str) -> set:
            return {w for w in obj.split() if len(w) > 4 and w not in skip}
        t1, t2 = key_terms(obj1), key_terms(obj2)
        if not t1 or not t2:
            return False
        return len(t1 & t2) / max(len(t1), len(t2)) > 0.55

    # ── Confidence promotion context ──────────────────────────────────────────

    def get_confidence_context(self) -> dict:
        """
        Context for the scoring engine.
        More confirmed findings = higher ceiling for similar hypotheses.
        """
        return {
            "confirmed_count":    len(self.confirmed_urls),
            "disproven_count":    len(self.disproven_urls),
            "chain_candidates":   len(self.chain_candidates),
            "patterns_learned":   len([b for b in self.behaviors if b.url_pattern]),
            "auth_namespaces":    {b.namespace: b.auth_pattern.value
                                   for b in self.behaviors if b.auth_pattern != AuthBehavior.UNKNOWN},
        }

    # ── Context strings for agent prompts ─────────────────────────────────────

    def get_alpha_context(self) -> str:
        """
        Injected into every Alpha reasoning prompt.
        Alpha reads this and knows exactly what's settled.
        """
        lines = []

        if self.confirmed_urls:
            lines.append(f"CONFIRMED VULNERABLE — DO NOT REPROBE ({len(self.confirmed_urls)}):")
            for url in list(self.confirmed_urls)[-6:]:
                ep = self.endpoints.get(url)
                lines.append(f"  ✅ {url}")
                if ep:
                    lines.append(f"     Evidence: {ep.classification_reason[:80]}")
                    lines.append(f"     Retest: {ep.retest_policy.value}")

        if self.disproven_urls:
            lines.append(f"\nDISPROVEN — DO NOT REPROBE ({len(self.disproven_urls)}):")
            for url in list(self.disproven_urls)[-10:]:
                ep = self.endpoints.get(url)
                reason = ep.disprove_reason.value if ep and ep.disprove_reason else "disproven"
                lines.append(f"  ❌ {url} ({reason})")

        if self.inconclusive_urls:
            lines.append(f"\nINCONCLUSIVE ({len(self.inconclusive_urls)}) — retry with new angle only:")
            for url in list(self.inconclusive_urls)[-5:]:
                lines.append(f"  🔍 {url}")

        auth_known = {b.namespace: b.auth_pattern.value
                      for b in self.behaviors
                      if b.auth_pattern != AuthBehavior.UNKNOWN and b.namespace}
        if auth_known:
            lines.append(f"\nLEARNED AUTH BEHAVIOR:")
            for ns, behavior in auth_known.items():
                lines.append(f"  {ns} → {behavior}")

        patterns = [b for b in self.behaviors if b.url_pattern]
        if patterns:
            lines.append(f"\nLEARNED URL PATTERNS:")
            for p in patterns[-4:]:
                lines.append(f"  • {p.url_pattern} (confidence: {p.confidence:.0%})")

        stop, reason = self.should_stop()
        if stop:
            lines.append(f"\n⛔ STOP CONDITION: {reason}")

        budget_pct = self.budget_used / self.budget_total
        lines.append(f"\nBudget: {self.budget_used}/{self.budget_total} ({budget_pct:.0%} used)")

        return "\n".join(lines) if lines else "No prior intelligence — first cycle"

    def get_queen_context(self) -> str:
        """Injected into every Queen strategic review."""
        lines = [
            f"Session: {self.budget_used}/{self.budget_total} requests used",
            f"Confirmed: {len(self.confirmed_urls)} | "
            f"Disproven: {len(self.disproven_urls)} | "
            f"Inconclusive: {len(self.inconclusive_urls)}",
        ]

        if self.confirmed_urls:
            lines.append(f"\nCONFIRMED (do not reinvestigate):")
            for url in self.confirmed_urls:
                lines.append(f"  ✅ {url}")

        if self.queen_objectives_completed:
            lines.append(f"\nCOMPLETED OBJECTIVES (do not repeat):")
            for obj in self.queen_objectives_completed[-6:]:
                lines.append(f"  ✓ {obj[:90]}")

        # Show untested endpoints grouped by namespace — Queen uses this to
        # generate targeted objectives instead of repeating generic ones
        if self.untested_queue:
            # Group by namespace prefix
            from collections import defaultdict
            by_ns: dict = defaultdict(list)
            for url in self.untested_queue:
                from urllib.parse import urlparse
                path = urlparse(url).path
                parts = [p for p in path.split('/') if p]
                ns = '/' + parts[0] + '/' if parts else '/'
                by_ns[ns].append(url)

            lines.append(f"\nUNTESTED ENDPOINTS REMAINING ({len(self.untested_queue)} total):")
            for ns, urls in sorted(by_ns.items()):
                sample = [u.split('/')[-1] for u in urls[:4]]
                lines.append(f"  {ns} — {len(urls)} remaining: {', '.join(sample)}"
                             + ('...' if len(urls) > 4 else ''))

        if self.root_causes:
            lines.append(f"\nROOT CAUSES IDENTIFIED:")
            for rc in self.root_causes:
                lines.append(f"  [{rc.severity}] {rc.title}: {len(rc.endpoints)} endpoints confirmed")

        if self.chain_candidates:
            lines.append(f"\nCHAIN CANDIDATES (CONFIRMED endpoints only):")
            for cc in self.chain_candidates:
                lines.append(f"  {cc.title} ({cc.confidence:.0%} confidence)")

        stop, reason = self.should_stop()
        if stop:
            lines.append(f"\n⛔ STOP CONDITION: {reason}")
        elif self.stop_condition == StopCondition.SUFFICIENT_EVIDENCE:
            lines.append(f"\n✅ Sufficient evidence gathered — consider concluding")

        lines.append(f"\nWasted probes prevented: {self.probes_prevented}")

        return "\n".join(lines)

    # ── Retest policy ─────────────────────────────────────────────────────────

    # ── Request failure tracking ──────────────────────────────────────────────

    def record_request_failure(self, agent_name: str, url: str,
                                failure_class: str,
                                failure_reason: str = "") -> None:
        """
        Record a failed outbound request from any agent.

        Called when safe_request returns a FailedResponse.
        failure_class comes from FailedResponse.failure_class — classified at
        the catch site in safe_request from the real exception, not a synthetic
        string. failure_reason is the original exception message, preserved.

        Matches the direct attribute mutation pattern of this class.

        Args:
            agent_name:     Name of the calling agent (e.g. 'disclosure_agent')
            url:            The URL that failed
            failure_class:  One of: timeout | dns | tls | connection_refused | other
            failure_reason: Original exception message — for logs and debugging
        """
        import sys
        detail = f"{failure_class}" + (f": {failure_reason[:80]}" if failure_reason else "")
        print(f"[WARN] [{agent_name}] Request failed: {url} -- {detail}",
              file=sys.stderr)

        # Aggregate counter — (agent, failure_class) → count
        key = (agent_name, failure_class)
        self.request_failures[key] = self.request_failures.get(key, 0) + 1

        # URL-level detail — last known failure per URL, overwrites on repeat
        # Preserves debugging detail without growing unbounded history
        self.recent_failure_detail[url] = {
            "agent":          agent_name,
            "failure_class":  failure_class,
            "failure_reason": failure_reason[:200] if failure_reason else "",
        }

    def get_request_failure_summary(self) -> dict:
        """
        Return request failures grouped by agent and failure class.
        Includes total count and recent URL-level detail.
        Used in scan summary and report output.
        """
        by_agent: dict[str, dict[str, int]] = {}
        for (agent, failure_class), count in self.request_failures.items():
            if agent not in by_agent:
                by_agent[agent] = {}
            by_agent[agent][failure_class] = count

        total = sum(self.request_failures.values())

        return {
            "total_failures":      total,
            "by_agent":            by_agent,
            "recent_url_failures": self.recent_failure_detail,
        }

    def _get_retest_policy(self, reason: DisproveReason) -> RetestPolicy:
        return {
            DisproveReason.AUTH_ENFORCED:  RetestPolicy.IF_AUTH_ADDED,
            DisproveReason.SPA_FALLBACK:   RetestPolicy.ALWAYS_SKIP,
            DisproveReason.NOT_FOUND:      RetestPolicy.NEVER,
            DisproveReason.EMPTY_RESPONSE: RetestPolicy.AFTER_N_CYCLES,
            DisproveReason.SERVER_ERROR:   RetestPolicy.AFTER_N_CYCLES,
            DisproveReason.NO_RESPONSE:    RetestPolicy.AFTER_N_CYCLES,
        }.get(reason, RetestPolicy.NEVER)

    # ── Summary ───────────────────────────────────────────────────────────────

    def get_summary(self) -> dict:
        return {
            "session_id":            self.session_id,
            "total_requests":        self.budget_used,   # classified endpoint outcomes, not raw HTTP count
            "budget_semantics":      "classified_endpoint_outcomes",
            "budget_remaining":      self.budget_total - self.budget_used,
            "confirmed":             len(self.confirmed_urls),
            "disproven":             len(self.disproven_urls),
            "inconclusive":          len(self.inconclusive_urls),
            "root_causes":           len(self.root_causes),
            "chain_candidates":      len(self.chain_candidates),
            "behaviors_learned":     len(self.behaviors),
            "probes_prevented":      self.probes_prevented,
            "queen_objectives_done": len(self.queen_objectives_completed),
            "stop_condition":        self.stop_condition.value if self.stop_condition else None,
            "confidence_context":    self.get_confidence_context(),
            "request_failures":      self.get_request_failure_summary(),
        }
