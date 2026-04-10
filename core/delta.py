"""
sentinel/core/delta.py

Delta Report — Compare current scan to previous scan.
Surfaces:
  - NEW findings (weren't in last scan)
  - RESOLVED findings (were in last scan, gone now)
  - PERSISTING findings (still present, severity unchanged)
  - ESCALATED findings (severity increased since last scan)

This is what turns Sentinel from a one-shot scanner into
a continuous security monitoring tool.

Storage: local JSON files in reports/deltas/
Future: Cosmos DB for multi-user, multi-target history
"""

import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional

from .models import Finding, ScanResult, Severity

DELTA_DIR = Path("reports/deltas")


@dataclass
class DeltaReport:
    target:           str
    current_scan_id:  str
    previous_scan_id: Optional[str]
    scanned_at:       datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    new_findings:        list[Finding] = field(default_factory=list)
    resolved_findings:   list[Finding] = field(default_factory=list)
    persisting_findings: list[Finding] = field(default_factory=list)
    escalated_findings:  list[dict]    = field(default_factory=list)  # {finding, old_severity, new_severity}

    @property
    def has_new_criticals(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.new_findings)

    @property
    def summary(self) -> str:
        parts = []
        if self.new_findings:
            parts.append(f"{len(self.new_findings)} new")
        if self.resolved_findings:
            parts.append(f"{len(self.resolved_findings)} resolved")
        if self.escalated_findings:
            parts.append(f"{len(self.escalated_findings)} escalated")
        if self.persisting_findings:
            parts.append(f"{len(self.persisting_findings)} persisting")
        return ", ".join(parts) if parts else "No changes detected"


def compute_delta(current: ScanResult, target: str) -> DeltaReport:
    """
    Compare current scan to the most recent previous scan for this target.
    Saves the current scan for future delta comparisons.
    """
    DELTA_DIR.mkdir(parents=True, exist_ok=True)

    previous = _load_previous_scan(target)
    delta    = _build_delta(current, previous, target)

    # Save current scan as the new baseline
    _save_scan(current, target)

    return delta


def _build_delta(current: ScanResult, previous: Optional[dict], target: str) -> DeltaReport:
    """Core delta computation."""
    delta = DeltaReport(
        target=target,
        current_scan_id=current.session_id,
        previous_scan_id=previous.get("session_id") if previous else None,
    )

    if not previous:
        # No previous scan — everything is "new"
        delta.new_findings = current.findings
        return delta

    prev_findings = {_finding_fingerprint(f): f for f in _deserialize_findings(previous.get("findings", []))}
    curr_findings = {_finding_fingerprint(f): f for f in current.findings}

    prev_keys = set(prev_findings.keys())
    curr_keys = set(curr_findings.keys())

    # New: in current but not previous
    for key in curr_keys - prev_keys:
        delta.new_findings.append(curr_findings[key])

    # Resolved: in previous but not current
    for key in prev_keys - curr_keys:
        delta.resolved_findings.append(prev_findings[key])

    # Persisting: in both — check for severity escalation
    for key in curr_keys & prev_keys:
        curr_f = curr_findings[key]
        prev_f = prev_findings[key]
        if _severity_rank(curr_f.severity) > _severity_rank(prev_f.severity):
            delta.escalated_findings.append({
                "finding":      curr_f,
                "old_severity": prev_f.severity,
                "new_severity": curr_f.severity,
            })
        else:
            delta.persisting_findings.append(curr_f)

    return delta


def _finding_fingerprint(f: Finding) -> str:
    """
    Stable fingerprint for a finding across scans.
    Uses title + file + line (not finding_id which changes each scan).
    """
    raw = f"{f.title}|{f.file_path}|{f.line_number}|{f.agent}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _severity_rank(severity) -> int:
    order = {
        Severity.INFO:     0,
        Severity.LOW:      1,
        Severity.MEDIUM:   2,
        Severity.HIGH:     3,
        Severity.CRITICAL: 4,
    }
    return order.get(severity, 0)


# ── Storage ───────────────────────────────────────────────────────────────────

def _scan_file(target: str) -> Path:
    """Get the path for the stored baseline scan for a target."""
    safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
    return DELTA_DIR / f"baseline_{safe}.json"


def _save_scan(result: ScanResult, target: str) -> None:
    """Save current scan as the new baseline for this target."""
    path = _scan_file(target)
    data = {
        "session_id": result.session_id,
        "target":     target,
        "saved_at":   datetime.now(timezone.utc).isoformat(),
        "findings":   [f.model_dump(mode="json") for f in result.findings],
    }
    with open(path, "w") as fp:
        json.dump(data, fp, indent=2, default=str)


def _load_previous_scan(target: str) -> Optional[dict]:
    """Load the most recent baseline scan for this target."""
    path = _scan_file(target)
    if not path.exists():
        return None
    try:
        with open(path) as fp:
            return json.load(fp)
    except (json.JSONDecodeError, IOError):
        return None


def _deserialize_findings(raw_findings: list[dict]) -> list[Finding]:
    """Deserialize stored findings back to Finding objects."""
    findings = []
    for f in raw_findings:
        try:
            findings.append(Finding(**f))
        except Exception:
            continue
    return findings


# ── Report ────────────────────────────────────────────────────────────────────

def delta_to_markdown(delta: DeltaReport) -> str:
    """Generate a markdown delta report."""
    lines = [
        "# 📊 Sentinel Delta Report",
        f"\n**Target:** `{delta.target}`",
        f"**Compared:** `{delta.previous_scan_id[:8] if delta.previous_scan_id else 'N/A (first scan)'}` → `{delta.current_scan_id[:8]}`",
        f"**Summary:** {delta.summary}",
        "\n---\n",
    ]

    if not delta.previous_scan_id:
        lines.append("*First scan for this target — no previous baseline to compare against.*")
        return "\n".join(lines)

    if delta.new_findings:
        lines.append(f"## 🆕 New Findings ({len(delta.new_findings)})\n")
        for f in sorted(delta.new_findings, key=lambda x: _severity_rank(x.severity), reverse=True):
            lines.append(f"- **[{f.severity}]** {f.title}")
            if f.file_path:
                lines.append(f"  - Location: `{f.file_path}`")
            lines.append(f"  - {f.description[:150]}")
        lines.append("")

    if delta.escalated_findings:
        lines.append(f"## ⬆️ Escalated Findings ({len(delta.escalated_findings)})\n")
        for item in delta.escalated_findings:
            f = item["finding"]
            lines.append(f"- **{item['old_severity']} → {item['new_severity']}** {f.title}")
        lines.append("")

    if delta.resolved_findings:
        lines.append(f"## ✅ Resolved Findings ({len(delta.resolved_findings)})\n")
        for f in delta.resolved_findings:
            lines.append(f"- ~~[{f.severity}] {f.title}~~")
        lines.append("")

    if delta.persisting_findings:
        lines.append(f"## ⚠️ Persisting Findings ({len(delta.persisting_findings)})\n")
        for f in sorted(delta.persisting_findings, key=lambda x: _severity_rank(x.severity), reverse=True):
            lines.append(f"- **[{f.severity}]** {f.title}")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by Sentinel. Fix new and escalated findings first.*")
    return "\n".join(lines)
