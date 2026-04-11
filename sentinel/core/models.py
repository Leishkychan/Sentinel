"""
sentinel/core/models.py
Shared data models, enums, and types used across all agents.
"""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid


# ── Scan Modes ────────────────────────────────────────────────────────────────

class ScanMode(str, Enum):
    PASSIVE = "PASSIVE"   # Recon + Config only. Read-only observation.
    CODE    = "CODE"      # SAST + Deps only. No network activity.
    PROBE   = "PROBE"     # Active-safe probing. Finds real vulns. No exploitation.
    ACTIVE  = "ACTIVE"    # All agents. Requires double confirmation.


# ── Severity ──────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# ── Agent Names ───────────────────────────────────────────────────────────────

class AgentName(str, Enum):
    ORCHESTRATOR = "orchestrator"
    SAST         = "sast_agent"
    DEPS         = "deps_agent"
    CONFIG       = "config_agent"
    RECON        = "recon_agent"
    NUCLEI       = "nuclei_agent"
    LOGIC        = "logic_agent"
    NETWORK      = "network_agent"
    PROBE        = "probe_agent"
    JS           = "js_agent"
    API          = "api_agent"
    DISCLOSURE   = "disclosure_agent"
    ALPHA        = "alpha_agent"
    QUEEN        = "queen_agent"
    INJECTION    = "injection_agent"
    AUTH_SCAN    = "auth_scan_agent"
    AGGREGATOR   = "aggregator"
    REPORTER     = "reporter"


# ── Session ───────────────────────────────────────────────────────────────────

class ScanSession(BaseModel):
    session_id:       str      = Field(default_factory=lambda: str(uuid.uuid4()))
    target:           str
    mode:             ScanMode
    approved:         bool     = False
    active_confirmed: bool     = False
    created_at:       datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    approved_targets: list[str] = Field(default_factory=list)

    # Authenticated scanning support
    auth_token:       Optional[str] = None   # Bearer token
    auth_cookie:      Optional[str] = None   # Session cookie (name=value)
    auth_headers:     dict          = Field(default_factory=dict)  # Custom headers


# ── Evidence Reference ────────────────────────────────────────────────────────
#
# Structured evidence from a real HTTP probe.
# Defined here (not in session_intelligence.py) so Finding can carry it
# without a circular import. session_intelligence.py imports it from here.
#
# This is a Pydantic model so Finding serialises cleanly to JSON.
# Field names and semantics are identical to the original dataclass.

class EvidenceRef(BaseModel):
    """Structured evidence from a real HTTP probe — not a summary string."""
    method:           str
    url:              str
    status_code:      int
    response_type:    str               # JSON | HTML | TEXT | EMPTY
    size_bytes:       int
    auth_sent:        bool
    sensitive_fields: list[str]         = Field(default_factory=list)
    record_count:     Optional[int]     = None
    proof_snippet:    Optional[str]     = None  # Sanitized sample — required for CONFIRMED
    timestamp:        str               = Field(
                          default_factory=lambda: datetime.now(timezone.utc).isoformat()
                      )

    def is_sufficient_for_confirmation(self) -> tuple[bool, str]:
        """Hard check — is this evidence good enough to CONFIRM a finding?"""
        if self.status_code != 200:
            return False, f"HTTP {self.status_code} — only 200 confirms"
        if self.response_type == "HTML":
            return False, "HTML response — not structured data"
        if self.response_type == "EMPTY":
            return False, "Empty response — no evidence"
        if self.size_bytes < 200:
            return False, f"Too small ({self.size_bytes}b)"
        if not self.proof_snippet:
            return False, "No proof snippet — required"
        if self.auth_sent:
            return False, "Auth was sent — cannot confirm auth bypass"
        return True, "OK"

    def format(self) -> str:
        auth_str = "YES — 401/403" if self.status_code in (401, 403) else \
                   "NOT required" if not self.auth_sent and self.status_code == 200 else \
                   "unknown"
        parts = [
            f"Request:  {self.method} {self.url}",
            f"Status:   {self.status_code}",
            f"Type:     {self.response_type} ({self.size_bytes}b)",
            f"Auth req: {auth_str}",
        ]
        if self.record_count is not None:
            parts.append(f"Records:  {self.record_count}")
        if self.sensitive_fields:
            parts.append(f"Sensitive: {', '.join(self.sensitive_fields[:4])}")
        if self.proof_snippet:
            parts.append(f"Proof:    {self.proof_snippet[:150]}")
        return "\n".join(parts)


# ── Individual Finding ────────────────────────────────────────────────────────

class Finding(BaseModel):
    finding_id:   str      = Field(default_factory=lambda: str(uuid.uuid4()))
    agent:        AgentName
    title:        str
    description:  str
    severity:     Severity
    file_path:    Optional[str]      = None
    line_number:  Optional[int]      = None
    cve_id:       Optional[str]      = None
    mitre_tactic: Optional[str]      = None
    mitre_technique: Optional[str]   = None
    remediation:  Optional[str]      = None
    metadata:     dict               = Field(default_factory=dict)
    raw_output:   Optional[str]      = None
    evidence:     Optional[EvidenceRef] = None  # Structured HTTP probe evidence — set by alpha_agent Phase 2+
    timestamp:    datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Scan Result (final output) ────────────────────────────────────────────────

class ScanResult(BaseModel):
    session_id:     str
    target:         str
    mode:           ScanMode
    findings:       list[Finding] = Field(default_factory=list)
    summary:        Optional[str] = None
    total:          int = 0
    by_severity:    dict = Field(default_factory=dict)
    completed_at:   datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agents_run:     list[AgentName] = Field(default_factory=list)

    # Phase 3 additions
    attack_chains:  list[dict] = Field(default_factory=list)
    delta_summary:  Optional[str] = None
    delta_markdown: Optional[str] = None

    # Phase 4 — pipeline + eval
    pipeline_summary:      dict  = Field(default_factory=dict)
    negative_validations:  int   = 0
    eval_run:              Optional[dict] = None


# ── Audit Log Entry ───────────────────────────────────────────────────────────

class AuditEntry(BaseModel):
    entry_id:   str      = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    agent:      AgentName
    action:     str
    target:     str
    mode:       ScanMode
    allowed:    bool
    reason:     Optional[str] = None  # populated on block
    timestamp:  datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
