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
    PASSIVE = "PASSIVE"   # Recon + Config only. Read-only, no probing.
    CODE    = "CODE"      # SAST + Deps only. No network activity.
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


# ── Individual Finding ────────────────────────────────────────────────────────

class Finding(BaseModel):
    finding_id:   str      = Field(default_factory=lambda: str(uuid.uuid4()))
    agent:        AgentName
    title:        str
    description:  str
    severity:     Severity
    file_path:    Optional[str] = None
    line_number:  Optional[int] = None
    cve_id:       Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    remediation:  Optional[str] = None
    raw_output:   Optional[str] = None
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
