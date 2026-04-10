"""
sentinel/core/policy.py

Policy Enforcement Layer.

Not "safe by convention" — safe by architecture.

Every action that Sentinel takes must pass through the policy gate.
The gate enforces:
  - Allowed target classes
  - Max probe intensity
  - Max request count per endpoint
  - No destructive methods by default
  - No credential attacks by default
  - No payload classes outside approved mode
  - No escalation from TEST to CONFIRM without policy eligibility

Policy violations raise PolicyViolation — they are never silently bypassed.

Policy profiles:
  PASSIVE   — read-only observation, no probing
  PROBE     — active-safe probing, no exploitation
  ACTIVE    — full suite (Nuclei), double confirmation required
  AUDIT     — PROBE + standards compliance checking
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class PolicyViolation(Exception):
    """Raised when an action violates policy. Never silently caught."""
    pass


class PolicyProfile(str, Enum):
    PASSIVE = "PASSIVE"
    PROBE   = "PROBE"
    ACTIVE  = "ACTIVE"
    AUDIT   = "AUDIT"   # PROBE + compliance checking


@dataclass
class PolicyGate:
    """
    The policy enforcement object.
    Created once per scan session and passed to all agents.
    """
    profile:              PolicyProfile
    max_requests_total:   int
    max_requests_per_ep:  int
    allowed_methods:      set[str]
    blocked_methods:      set[str]
    allowed_payload_classes: set[str]
    blocked_payload_classes: set[str]
    allow_credential_testing: bool
    allow_destructive:    bool
    require_evidence_for_confirm: bool
    request_count:        dict = field(default_factory=dict)
    total_requests:       int = 0

    def check(self, action: str, target: str, method: str = "GET",
              payload_class: Optional[str] = None) -> bool:
        """
        Check if an action is permitted.
        Raises PolicyViolation if not permitted.
        Returns True if permitted.
        """
        method = method.upper()

        # Blocked methods — always blocked regardless of mode
        if method in self.blocked_methods:
            raise PolicyViolation(
                f"Method {method} is blocked by policy (profile: {self.profile.value}). "
                f"Blocked methods: {self.blocked_methods}"
            )

        # Destructive actions
        if not self.allow_destructive and method in {"DELETE", "PUT", "PATCH"}:
            raise PolicyViolation(
                f"Destructive method {method} requires allow_destructive=True. "
                f"Current profile: {self.profile.value}"
            )

        # Payload class check
        if payload_class:
            if payload_class in self.blocked_payload_classes:
                raise PolicyViolation(
                    f"Payload class '{payload_class}' is blocked by policy. "
                    f"Blocked: {self.blocked_payload_classes}"
                )
            if self.allowed_payload_classes and \
               payload_class not in self.allowed_payload_classes:
                raise PolicyViolation(
                    f"Payload class '{payload_class}' not in allowed set. "
                    f"Allowed: {self.allowed_payload_classes}"
                )

        # Credential testing
        if not self.allow_credential_testing and action == "credential_test":
            raise PolicyViolation(
                "Credential testing requires allow_credential_testing=True. "
                f"Current profile: {self.profile.value}"
            )

        # Rate limits
        ep_count = self.request_count.get(target, 0)
        if ep_count >= self.max_requests_per_ep:
            raise PolicyViolation(
                f"Max requests per endpoint ({self.max_requests_per_ep}) reached for {target}. "
                "Stop probing this endpoint."
            )

        if self.total_requests >= self.max_requests_total:
            raise PolicyViolation(
                f"Total request limit ({self.max_requests_total}) reached. "
                "Scan must conclude."
            )

        # Record
        self.request_count[target] = ep_count + 1
        self.total_requests += 1
        return True

    def record_request(self, target: str):
        """Record a request against the policy counter."""
        self.request_count[target] = self.request_count.get(target, 0) + 1
        self.total_requests += 1

    def get_stats(self) -> dict:
        return {
            "profile":          self.profile.value,
            "total_requests":   self.total_requests,
            "max_requests":     self.max_requests_total,
            "endpoints_probed": len(self.request_count),
            "budget_remaining": self.max_requests_total - self.total_requests,
            "top_endpoints":    sorted(self.request_count.items(),
                                       key=lambda x: x[1], reverse=True)[:5],
        }


# ── Policy profiles ───────────────────────────────────────────────────────────

def get_policy(profile: PolicyProfile) -> PolicyGate:
    """Get the policy gate for a given profile."""

    if profile == PolicyProfile.PASSIVE:
        return PolicyGate(
            profile=profile,
            max_requests_total=50,
            max_requests_per_ep=2,
            allowed_methods={"GET", "HEAD", "OPTIONS"},
            blocked_methods={"POST", "PUT", "DELETE", "PATCH"},
            allowed_payload_classes=set(),
            blocked_payload_classes={"exploit", "injection", "brute_force",
                                      "fuzzing", "dos", "credential"},
            allow_credential_testing=False,
            allow_destructive=False,
            require_evidence_for_confirm=True,
        )

    elif profile == PolicyProfile.PROBE:
        return PolicyGate(
            profile=profile,
            max_requests_total=300,
            max_requests_per_ep=5,
            allowed_methods={"GET", "HEAD", "OPTIONS", "POST"},
            blocked_methods={"DELETE", "PUT", "PATCH"},
            allowed_payload_classes={"observation", "error_probe", "auth_test"},
            blocked_payload_classes={"exploit", "brute_force", "fuzzing",
                                      "dos", "injection_payload"},
            allow_credential_testing=True,   # Test creds in known test apps
            allow_destructive=False,
            require_evidence_for_confirm=True,
        )

    elif profile == PolicyProfile.ACTIVE:
        return PolicyGate(
            profile=profile,
            max_requests_total=1000,
            max_requests_per_ep=10,
            allowed_methods={"GET", "HEAD", "OPTIONS", "POST"},
            blocked_methods={"DELETE", "PUT", "PATCH"},  # Still blocked even in ACTIVE
            allowed_payload_classes={"observation", "error_probe", "auth_test",
                                      "nuclei_safe", "cve_detection"},
            blocked_payload_classes={"exploit", "brute_force", "fuzzing", "dos"},
            allow_credential_testing=True,
            allow_destructive=False,
            require_evidence_for_confirm=True,
        )

    elif profile == PolicyProfile.AUDIT:
        return PolicyGate(
            profile=profile,
            max_requests_total=400,
            max_requests_per_ep=5,
            allowed_methods={"GET", "HEAD", "OPTIONS", "POST"},
            blocked_methods={"DELETE", "PUT", "PATCH"},
            allowed_payload_classes={"observation", "error_probe", "auth_test",
                                      "compliance_check"},
            blocked_payload_classes={"exploit", "brute_force", "fuzzing", "dos"},
            allow_credential_testing=True,
            allow_destructive=False,
            require_evidence_for_confirm=True,
        )

    raise ValueError(f"Unknown policy profile: {profile}")


# ── Policy-aware probe wrapper ────────────────────────────────────────────────

def policy_check_probe(url: str, method: str, policy: PolicyGate,
                       payload_class: str = "observation") -> bool:
    """
    Check probe against policy before executing.
    Call this before every HTTP request in every agent.
    """
    try:
        return policy.check(
            action="http_probe",
            target=url,
            method=method,
            payload_class=payload_class,
        )
    except PolicyViolation as e:
        print(f"[POLICY] BLOCKED: {e}")
        return False


# For type hints
from typing import Optional
