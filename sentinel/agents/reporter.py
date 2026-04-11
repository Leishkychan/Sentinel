"""
sentinel/agents/reporter.py

Report Agent.
Source of truth: SessionIntelligence, not result.findings.

Structure:
  1. Factual header        — session-intel counts, no LLM narrative
  2. Root Causes           — grouped patterns behind confirmed vulns
  3. Confirmed Vulns       — evidence-proven findings only
  4. Unverified Security   — HIGH/MEDIUM/CRIT not confirmed by pipeline
  5. Informational         — INFO, structural observations
  6. Pipeline Metrics      — recomputed from session_intel

NEVER: exploitation steps, working payloads, attack code
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from sentinel.core.models import ScanResult, Finding, Severity

REPORTS_DIR = Path("reports")

def _now() -> datetime:
    return datetime.now(timezone.utc)


def generate_report(result: ScanResult) -> dict:
    REPORTS_DIR.mkdir(exist_ok=True)
    timestamp = _now().strftime("%Y%m%d_%H%M%S")
    base_name = f"sentinel_{result.session_id[:8]}_{timestamp}"
    json_path = REPORTS_DIR / f"{base_name}.json"
    md_path   = REPORTS_DIR / f"{base_name}.md"

    ctx = _build_context(result)

    json_report = _build_json_report(result, ctx)
    with open(json_path, "w") as f:
        json.dump(json_report, f, indent=2, default=str)

    md_content = _build_markdown_report(result, ctx)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    print(f"[REPORTER] Reports saved: {json_path}, {md_path}")
    return {"json_path": str(json_path), "md_path": str(md_path),
            "json": json_report, "markdown": md_content}


# ── Context ───────────────────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    """Normalize URL for comparison: strip trailing slash and query string."""
    if not url:
        return url
    url = url.rstrip("/")
    # Strip query string for matching purposes
    url = url.split("?")[0]
    return url


def _url_matches_confirmed(file_path: str, confirmed_urls: set) -> bool:
    """
    Fuzzy URL match — handles trailing slash, query string, and path-only variants.
    Confirmed URLs are full URLs; finding file_path may be full or path-only.
    """
    if not file_path:
        return False
    norm = _normalize_url(file_path)
    if norm in confirmed_urls:
        return True
    # Check normalized confirmed URLs
    for cu in confirmed_urls:
        if _normalize_url(cu) == norm:
            return True
        # Path suffix match: confirmed is http://host/api/X, finding is /api/X
        if file_path.startswith("/") and _normalize_url(cu).endswith(file_path.rstrip("/")):
            return True
    return False


def _build_context(result: ScanResult) -> dict:
    """
    Build reconciled context from session_intel (authoritative).
    result.findings are supporting detail — not source of truth.
    """
    session = getattr(result, '_session', None)
    intel   = getattr(session, '_session_intel', None) if session else None

    all_findings  = result.findings or []
    confirmed_urls = intel.confirmed_urls  if intel else set()
    disproven_urls = intel.disproven_urls  if intel else set()
    inconclusive_u = intel.inconclusive_urls if intel else set()

    # Partition findings using fuzzy URL matching
    confirmed_vulns    = []
    unverified_security = []
    info_findings      = []
    supporting_other   = []

    for f in all_findings:
        sev = _sev(f)
        if sev == 'INFO':
            info_findings.append(f)
        elif _url_matches_confirmed(f.file_path or '', confirmed_urls):
            confirmed_vulns.append(f)
        elif sev in ('CRITICAL', 'HIGH', 'MEDIUM'):
            unverified_security.append(f)
        else:
            supporting_other.append(f)

    # Pipeline metrics — session_intel is authoritative for core counts
    confirmed_count    = len(confirmed_urls)  if intel else len(confirmed_vulns)
    disproven_count    = len(disproven_urls)  if intel else 0
    inconclusive_count = len(inconclusive_u)  if intel else 0
    total_probed       = confirmed_count + disproven_count + inconclusive_count
    confirmation_rate  = round(confirmed_count / max(total_probed, 1), 2)

    # hypotheses_tested: approximated from session_intel.budget_used
    # This is a proxy (classification events), not true request count — see session_intelligence.py
    hypotheses_tested  = getattr(intel, 'budget_used', total_probed) if intel else total_probed

    upstream = getattr(result, 'pipeline_summary', {}) or {}
    pipeline = {
        'hypotheses_tested':  hypotheses_tested,
        'confirmed_findings': confirmed_count,
        'refuted_findings':   disproven_count,
        'inconclusive':       inconclusive_count,
        'confirmation_rate':  confirmation_rate,
        'probes_prevented':   getattr(intel, 'probes_prevented', 0) if intel else upstream.get('probes_prevented', 0),
        'attack_graph':       upstream.get('attack_graph', {}),
    }

    # Severity breakdown of confirmed vulns only
    by_sev: dict = {}
    for f in confirmed_vulns:
        s = _sev(f)
        by_sev[s] = by_sev.get(s, 0) + 1

    # Factual summary — from session_intel, not LLM narrative
    factual_summary = _build_factual_summary(confirmed_urls, confirmed_vulns, intel)

    # Integrity warnings
    warnings = []
    upstream_confirmed = upstream.get('confirmed_findings', 0)
    if upstream_confirmed and upstream_confirmed != confirmed_count:
        warnings.append(
            f"Pipeline summary claimed {upstream_confirmed} confirmed, "
            f"session_intel has {confirmed_count}"
        )
    unmapped = confirmed_count - len(confirmed_vulns)
    if unmapped > 0:
        warnings.append(
            f"{unmapped} confirmed URL(s) have no matching finding object — "
            "endpoint confirmed by pipeline but no agent finding linked"
        )

    return {
        'confirmed_vulns':      _sorted_findings(confirmed_vulns),
        'unverified_security':  _sorted_findings(unverified_security),
        'info_findings':        _sorted_findings(info_findings),
        'supporting_other':     _sorted_findings(supporting_other),
        'all_findings':         all_findings,
        'confirmed_count':      confirmed_count,
        'disproven_count':      disproven_count,
        'inconclusive_count':   inconclusive_count,
        'total_probed':         total_probed,
        'confirmation_rate':    confirmation_rate,
        'by_sev':               by_sev,
        'pipeline':             pipeline,
        'root_causes':          intel.root_causes if intel else [],
        'warnings':             warnings,
        'has_intel':            intel is not None,
        'factual_summary':      factual_summary,
        'llm_narrative':        result.summary or '',  # clearly labelled, not authoritative
    }


def _build_factual_summary(confirmed_urls: set, confirmed_vulns: list,
                            intel) -> str:
    """
    Generate a factual summary from session_intel.
    Blast radius read from session_intel endpoint evidence records — not regex on descriptions.
    This is authoritative — not LLM-generated.
    """
    if not confirmed_urls:
        return "No confirmed vulnerabilities detected in this scan."

    count = len(confirmed_urls)
    endpoints = sorted(confirmed_urls)

    # Read blast radius from session_intel endpoint evidence records (authoritative)
    blast_parts = []
    if intel and hasattr(intel, 'endpoints'):
        for url in confirmed_urls:
            ep = intel.endpoints.get(url)
            if ep and ep.evidence:
                rec_count = getattr(ep.evidence, 'record_count', None)
                size_bytes = getattr(ep.evidence, 'size_bytes', None)
                name = url.rstrip('/').split('/')[-1]
                if rec_count is not None:
                    part = f"{rec_count} records from /{name}"
                    if size_bytes:
                        part += f" ({size_bytes:,} bytes)"
                    blast_parts.append(part)

    summary = (
        f"{count} endpoint{'s' if count != 1 else ''} confirmed unauthenticated: "
        f"{', '.join(e.split('/')[-1] for e in endpoints[:5])}"
        + ('...' if len(endpoints) > 5 else '') + '.'
    )
    if blast_parts:
        summary += f" Measured exposure: {'; '.join(blast_parts[:3])}."

    return summary


# ── JSON ──────────────────────────────────────────────────────────────────────

def _build_json_report(result: ScanResult, ctx: dict) -> dict:
    return {
        "sentinel_report": {
            "version":      "2.1",
            "generated_at": _now().isoformat(),
            "session_id":   result.session_id,
            "target":       result.target,
            "scan_mode":    result.mode,
            "agents_run":   [a.value for a in result.agents_run],
        },
        "summary": {
            "factual_summary":           ctx['factual_summary'],
            "llm_narrative":             ctx['llm_narrative'],
            "confirmed_vulnerabilities": ctx['confirmed_count'],
            "disproven_hypotheses":      ctx['disproven_count'],
            "inconclusive_probes":       ctx['inconclusive_count'],
            "total_probed":              ctx['total_probed'],
            "confirmation_rate":         ctx['confirmation_rate'],
            "severity_breakdown":        ctx['by_sev'],
            "integrity_warnings":        ctx['warnings'],
        },
        "root_causes": [
            {"title": rc.title, "severity": rc.severity,
             "endpoints": rc.endpoints, "pattern": rc.pattern}
            for rc in ctx['root_causes']
        ],
        "confirmed_vulnerabilities": [
            _finding_to_dict(f) for f in ctx['confirmed_vulns']
        ],
        "unverified_security_conditions": [
            _finding_to_dict(f) for f in ctx['unverified_security']
        ],
        "informational_observations": [
            _finding_to_dict(f) for f in ctx['info_findings']
        ],
        "supporting_agent_findings": [
            _finding_to_dict(f) for f in ctx['supporting_other']
        ],
        "pipeline_metrics": ctx['pipeline'],
        "attack_chains":    getattr(result, 'attack_chains', []),
        "disclaimer": (
            "This report was generated by Sentinel. "
            "All findings are for defensive purposes only. "
            "Do not use this report to exploit vulnerabilities. "
            "Ensure you have authorization to scan the target system."
        ),
    }


def _finding_to_dict(f: Finding) -> dict:
    return {
        "id":              f.finding_id,
        "severity":        _sev(f),
        "title":           f.title,
        "description":     f.description,
        "agent":           f.agent,
        "file":            f.file_path,
        "cve":             f.cve_id,
        "mitre_tactic":    f.mitre_tactic,
        "mitre_technique": f.mitre_technique,
        "remediation":     f.remediation,
        "timestamp":       f.timestamp.isoformat(),
    }


# ── Markdown ──────────────────────────────────────────────────────────────────

def _build_markdown_report(result: ScanResult, ctx: dict) -> str:
    lines = []

    lines.append("# 🛡️ Sentinel Security Report")
    lines.append(f"\n**Target:** `{result.target}`")
    lines.append(f"**Scan Mode:** `{result.mode}`")
    lines.append(f"**Session ID:** `{result.session_id}`")
    lines.append(f"**Generated:** {_now().strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Agents Run:** {', '.join(a.value for a in result.agents_run)}")
    lines.append("\n---\n")

    # Integrity warnings first
    if ctx['warnings']:
        lines.append("> ⚠️ **Integrity warnings:**")
        for w in ctx['warnings']:
            lines.append(f"> - {w}")
        lines.append("")

    # ── Section 1: Factual Header ─────────────────────────────────────────────
    lines.append("## Executive Summary\n")
    lines.append(f"**{ctx['factual_summary']}**\n")

    # LLM narrative clearly labelled as supporting context
    if ctx['llm_narrative']:
        lines.append("> *Analyst narrative (LLM-generated, not authoritative):*")
        lines.append(f"> {ctx['llm_narrative']}")
        lines.append("")

    lines.append("### Pipeline Truth\n")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| ✅ Confirmed vulnerabilities | **{ctx['confirmed_count']}** |")
    lines.append(f"| ❌ Disproven (NOT vulnerable) | {ctx['disproven_count']} |")
    lines.append(f"| 🔍 Inconclusive | {ctx['inconclusive_count']} |")
    lines.append(f"| Total probed | {ctx['total_probed']} |")
    lines.append(f"| Confirmation rate | {ctx['confirmation_rate']:.0%} |")
    lines.append("")

    if ctx['confirmed_count'] == 0:
        lines.append("✅ No confirmed vulnerabilities detected in this scan.")
        lines.append(_disclaimer())
        return "\n".join(lines)

    lines.append("---\n")

    # ── Section 2: Root Causes ────────────────────────────────────────────────
    if ctx['root_causes']:
        lines.append(f"## 🔗 Root Causes ({len(ctx['root_causes'])})\n")
        lines.append("*Patterns behind confirmed findings — fix the root cause, not just each symptom.*\n")
        for rc in ctx['root_causes']:
            sev = getattr(rc, 'severity', 'HIGH')
            title = getattr(rc, 'title', 'Unknown')
            endpoints = getattr(rc, 'endpoints', [])
            pattern = getattr(rc, 'pattern', '')
            lines.append(f"**[{sev}] {title}**")
            if pattern:
                lines.append(f"- Pattern: {pattern}")
            if endpoints:
                lines.append(f"- Affected endpoints ({len(endpoints)}): "
                             + ', '.join(f'`{e}`' for e in endpoints[:4])
                             + ('...' if len(endpoints) > 4 else ''))
            lines.append("")

    # ── Section 3: Confirmed Vulnerabilities ─────────────────────────────────
    lines.append(f"## 🔴 Confirmed Vulnerabilities ({ctx['confirmed_count']})\n")
    lines.append("*Proven by HTTP evidence. Each has a request/response artifact.*\n")

    if ctx['confirmed_vulns']:
        for i, f in enumerate(ctx['confirmed_vulns'], 1):
            icon = _severity_icon(_sev(f))
            lines.append(f"### {i}. {icon} {f.title}")
            lines.append(f"\n**Severity:** {_sev(f)} | **Agent:** `{f.agent}`")
            if f.file_path:
                lines.append(f"**Endpoint:** `{f.file_path}`")
            if f.mitre_tactic:
                tactic = f.mitre_tactic + (f" → {f.mitre_technique}" if f.mitre_technique else "")
                lines.append(f"**MITRE ATT&CK:** {tactic}")
            if f.cve_id:
                lines.append(f"**CVE/ID:** `{f.cve_id}`")
            lines.append(f"\n{f.description}")
            if f.remediation:
                lines.append(f"\n**Remediation:** {f.remediation}")
            lines.append("\n---")
    else:
        lines.append("*Pipeline confirmed endpoints but no agent findings linked. "
                     "Check finding file_path alignment.*\n---")

    # ── Section 4: Unverified Security Conditions ─────────────────────────────
    if ctx['unverified_security']:
        lines.append(f"\n## 🟡 Unverified Security Conditions ({len(ctx['unverified_security'])})\n")
        lines.append("*Detected but not confirmed by HTTP evidence pipeline. Require manual verification.*\n")
        for sev_label in ['CRITICAL', 'HIGH', 'MEDIUM']:
            sev_group = [f for f in ctx['unverified_security'] if _sev(f) == sev_label]
            if sev_group:
                icon = _severity_icon(sev_label)
                lines.append(f"**{icon} {sev_label} ({len(sev_group)})**")
                for f in sev_group:
                    lines.append(f"- {f.title}")
                    if f.file_path:
                        lines.append(f"  - `{f.file_path}`")
                lines.append("")

    # ── Section 5: Informational ──────────────────────────────────────────────
    if ctx['info_findings']:
        lines.append(f"\n## ⚪ Informational Observations ({len(ctx['info_findings'])})\n")
        for f in ctx['info_findings']:
            lines.append(f"- **{f.title}** (`{f.agent}`)" +
                         (f" — `{f.file_path}`" if f.file_path else ""))

    # ── Section 5b: Supporting Agent Findings ───────────────────────────────────
    if ctx['supporting_other']:
        lines.append(f"\n## 🔵 Supporting Agent Findings ({len(ctx['supporting_other'])})\n")
        lines.append("*LOW severity and structural agent findings — context only, not security findings.*\n")
        for f in ctx['supporting_other']:
            lines.append(f"- **{f.title}** (`{f.agent}`)" +
                         (f" — `{f.file_path}`" if f.file_path else ""))

    # ── Section 6: Pipeline Metrics ───────────────────────────────────────────
    lines.append("\n---\n")
    lines.append("## 📊 Evidence Pipeline Metrics\n")
    p = ctx['pipeline']
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Hypotheses tested | {p.get('hypotheses_tested', 0)} |")
    lines.append(f"| Confirmed | {p.get('confirmed_findings', 0)} |")
    lines.append(f"| Refuted (NOT vulnerable) | {p.get('refuted_findings', 0)} |")
    lines.append(f"| Inconclusive | {p.get('inconclusive', 0)} |")
    lines.append(f"| Confirmation rate | {p.get('confirmation_rate', 0):.0%} |")
    lines.append(f"| Probes prevented (dedup) | {p.get('probes_prevented', 0)} |")
    ag = p.get('attack_graph', {})
    if ag and ag.get('active_chains', 0):
        lines.append(f"| Active attack chains | {ag.get('active_chains', 0)} |")
    lines.append("")

    lines.append(_disclaimer())
    return "\n".join(lines)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sev(f: Finding) -> str:
    s = str(f.severity)
    return s.split(".")[-1] if "." in s else s

def _sev_str(sev) -> str:
    s = str(sev)
    return s.split(".")[-1] if "." in s else s

def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return sorted(findings, key=lambda f: order.get(_sev(f), 5))

def _severity_icon(sev_str: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🔵", "INFO": "⚪"}.get(sev_str, "⚪")

def _disclaimer() -> str:
    return (
        "\n\n---\n\n"
        "*This report was generated by Sentinel. "
        "All findings are for **defensive purposes only**. "
        "Do not use this report to exploit vulnerabilities. "
        "Ensure you have explicit authorization to test the target system.*"
    )
