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
from sentinel.core.models import ScanResult, Finding, Severity, FindingType, DataSurfaceType

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
    Exact URL match after normalization.
    Both file_path and confirmed_urls are normalized via _normalize_url before comparison.
    No substring, suffix, or path-only matching — those produce false confirmations.
    """
    if not file_path:
        return False
    norm = _normalize_url(file_path)
    normalized_confirmed = {_normalize_url(cu) for cu in confirmed_urls}
    return norm in normalized_confirmed


def _build_context(result: ScanResult) -> dict:
    """
    Build reconciled context from session_intel (authoritative).
    Phase 8 pipeline: classify → gate → normalize → dedup → group → surface → blast → mitre → sanitize → emit
    """
    session = getattr(result, '_session', None)
    intel   = getattr(session, '_session_intel', None) if session else None

    all_findings   = result.findings or []
    confirmed_urls = intel.confirmed_urls   if intel else set()
    disproven_urls = intel.disproven_urls   if intel else set()
    inconclusive_u = intel.inconclusive_urls if intel else set()

    # ── surface: target context for suppression gates ─────────────────────────
    from urllib.parse import urlparse as _urlparse
    _target_host = _urlparse(result.target).hostname or ""
    _is_loopback = _target_host in ("localhost", "127.0.0.1", "::1", "0.0.0.0")

    # ── surface: apply pre-emission filters A–F in order ─────────────────────
    filtered = []
    _dedup_seen: set = set()

    for f in all_findings:
        sev   = _sev(f)
        title = f.title or ""
        agent = str(f.agent) if f.agent else ""

        # Filter A — META: Queen posture/narrative findings never in sections
        if ("queen" in agent.lower() and
                (title.startswith("[Queen] Defensive Posture") or
                 title.startswith("[Queen] Executive"))):
            continue

        # Filter B — OPERATIONAL: skipped checks and auth context notes
        if ("Skipped" in title or
                title == "Authenticated Scan Skipped \u2014 No Auth Context Provided" or
                title == "Authenticated Scan Skipped — No Auth Context Provided"):
            continue

        # Filter C — localhost HTTPS suppression
        if _is_loopback and title == "No HTTPS Redirect Detected":
            continue

        # Filter E — finding_type enforcement (before severity cap)
        if f.finding_type is None:
            if f.evidence is not None:
                f.finding_type = FindingType.VULNERABILITY
            elif sev == "INFO":
                f.finding_type = FindingType.OBSERVATION
            else:
                f.finding_type = FindingType.EXPOSURE

        # Filter D — evidence-gated severity cap (type-aware, safety net)
        # VULNERABILITY without evidence → cap to LOW
        # EXPOSURE with file_path + HTTP access indicator in description → allow up to MEDIUM
        # EXPOSURE without access indicator → cap to LOW
        # OBSERVATION → cap to INFO
        if f.evidence is None and sev in ("CRITICAL", "HIGH", "MEDIUM"):
            ftype = f.finding_type
            if ftype == FindingType.OBSERVATION:
                # Observations are never MEDIUM+
                f.severity = Severity.INFO
                sev = "INFO"
            elif ftype == FindingType.EXPOSURE:
                # EXPOSURE may stay MEDIUM if directly observed HTTP access is noted
                _access_indicators = (
                    "http 200", "accessible", "returned", "exposed at",
                    "preview:", "publicly accessible", "endpoint is accessible",
                )
                desc_lower = (f.description or "").lower()
                has_access = (
                    f.file_path is not None and
                    any(ind in desc_lower for ind in _access_indicators)
                )
                if has_access and sev in ("CRITICAL", "HIGH"):
                    # Observed but not evidence-confirmed — cap at MEDIUM
                    f.severity = Severity.MEDIUM
                    sev = "MEDIUM"
                elif not has_access:
                    f.severity = Severity.LOW
                    f.title    = f.title + " [unverified — no HTTP evidence]"
                    sev = "LOW"
                # sev == "MEDIUM" already → allow through unchanged
            else:
                # VULNERABILITY without evidence → always LOW
                f.severity = Severity.LOW
                f.title    = f.title + " [unverified — no HTTP evidence]"
                if f.finding_type == FindingType.VULNERABILITY:
                    f.finding_type = FindingType.EXPOSURE
                sev = "LOW"

        # Filter F — dedup key: (normalized url, vulnerability class from title)
        _vuln_class = _extract_vuln_class(title)
        _dedup_key  = (_normalize_url(f.file_path or ""), _vuln_class)
        if _dedup_key in _dedup_seen and f.file_path:
            continue
        if f.file_path:
            _dedup_seen.add(_dedup_key)

        filtered.append(f)

    # ── surface: partition into sections ──────────────────────────────────────
    confirmed_vulns     = []
    unverified_security = []
    info_findings       = []
    supporting_other    = []

    for f in filtered:
        sev = _sev(f)
        if sev == "INFO":
            info_findings.append(f)
        elif _url_matches_confirmed(f.file_path or "", confirmed_urls):
            confirmed_vulns.append(f)
        elif sev in ("CRITICAL", "HIGH", "MEDIUM"):
            unverified_security.append(f)
        else:
            supporting_other.append(f)

    # Pipeline metrics — session_intel is authoritative
    confirmed_count    = len(confirmed_urls)  if intel else len(confirmed_vulns)
    disproven_count    = len(disproven_urls)  if intel else 0
    inconclusive_count = len(inconclusive_u)  if intel else 0
    total_probed       = confirmed_count + disproven_count + inconclusive_count
    confirmation_rate  = round(confirmed_count / max(total_probed, 1), 2)
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

    by_sev: dict = {}
    for f in confirmed_vulns:
        s = _sev(f)
        by_sev[s] = by_sev.get(s, 0) + 1

    factual_summary = _build_factual_summary(confirmed_urls, confirmed_vulns, intel)

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

    request_failures = intel.get_request_failure_summary() if intel else {
        "total_failures": 0, "by_agent": {}, "recent_url_failures": {}
    }

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
        'llm_narrative':        result.summary or '',
        'request_failures':     request_failures,
    }


def _build_factual_summary(confirmed_urls: set, confirmed_vulns: list,
                            intel) -> str:
    """
    Factual summary from session_intel root causes (authoritative).
    Blast radius uses aggregate_record_count + aggregate_bytes (PRIMARY only).
    DERIVATIVE endpoints noted as additional access paths, not counted twice.
    """
    if not confirmed_urls:
        return "No confirmed vulnerabilities detected in this scan."

    count     = len(confirmed_urls)
    endpoints = sorted(confirmed_urls)

    summary = (
        f"{count} endpoint{'s' if count != 1 else ''} confirmed unauthenticated: "
        f"{', '.join(e.split('/')[-1] for e in endpoints[:5])}"
        + ('...' if len(endpoints) > 5 else '') + '.'
    )

    # ── blast: read aggregate from session_intel root causes (Phase 8) ───────
    if intel and hasattr(intel, 'root_causes') and intel.root_causes:
        blast_parts = []
        for rc in intel.root_causes:
            agg_records      = getattr(rc, 'aggregate_record_count', None)
            agg_bytes        = getattr(rc, 'aggregate_bytes', None)
            breakdown        = getattr(rc, 'data_surface_breakdown', {})
            derivative_count = sum(1 for v in breakdown.values() if v == "DERIVATIVE")

            if agg_records is not None:
                part = f"{agg_records} unique records"
                if agg_bytes:
                    part += f" ({agg_bytes:,} bytes)"
                if derivative_count:
                    part += f" via {len(rc.endpoints)} paths ({derivative_count} derivative)"
                blast_parts.append(part)
            elif agg_bytes:
                blast_parts.append(f"{agg_bytes:,} bytes")

        if blast_parts:
            summary += f" Measured exposure: {'; '.join(blast_parts)}."
    else:
        # Fallback: per-endpoint evidence (no root cause grouping available)
        blast_parts = []
        if intel and hasattr(intel, 'endpoints'):
            for url in confirmed_urls:
                ep = intel.endpoints.get(url)
                if ep and ep.evidence:
                    rec_count  = getattr(ep.evidence, 'record_count', None)
                    size_bytes = getattr(ep.evidence, 'size_bytes', None)
                    name       = url.rstrip('/').split('/')[-1]
                    if rec_count is not None:
                        part = f"{rec_count} records from /{name}"
                        if size_bytes:
                            part += f" ({size_bytes:,} bytes)"
                        blast_parts.append(part)
        if blast_parts:
            summary += f" Measured exposure: {'; '.join(blast_parts[:3])}."

    return summary




# ── JSON ──────────────────────────────────────────────────────────────────────

def _build_json_report(result: ScanResult, ctx: dict) -> dict:
    # emit: consolidated confirmed vulns — root cause groups with 2+ endpoints
    # emit as one consolidated finding; single-endpoint groups remain individual
    confirmed_emit = _consolidate_confirmed(ctx['confirmed_vulns'], ctx['root_causes'])

    return {
        "sentinel_report": {
            "version":      "2.2",
            "generated_at": _now().isoformat(),
            "session_id":   result.session_id,
            "target":       result.target,
            "scan_mode":    result.mode,
            "agents_run":   [a.value for a in result.agents_run],
        },
        "summary": {
            "factual_summary":      ctx['factual_summary'],
            "llm_narrative":        ctx['llm_narrative'],
            # confirmed_endpoints = distinct URLs confirmed by session_intel (authoritative)
            # confirmed_findings  = emitted finding objects after consolidation
            # These differ: 6 endpoints may consolidate to 2 findings.
            "confirmed_endpoints":  ctx['confirmed_count'],
            "confirmed_findings":   len(confirmed_emit),
            "disproven_hypotheses": ctx['disproven_count'],
            "inconclusive_probes":  ctx['inconclusive_count'],
            "total_probed":         ctx['total_probed'],
            "confirmation_rate":    ctx['confirmation_rate'],
            "severity_breakdown":   ctx['by_sev'],
            "integrity_warnings":   ctx['warnings'],
        },
        "root_causes": [
            {
                "title":    rc.title,
                "severity": rc.severity,
                "endpoints": rc.endpoints,
                "pattern":  rc.pattern,
                "aggregate_record_count": getattr(rc, 'aggregate_record_count', None),
                "aggregate_bytes":        getattr(rc, 'aggregate_bytes', None),
                "data_surface_breakdown": {
                    k: v for k, v in getattr(rc, 'data_surface_breakdown', {}).items()
                    if not k.startswith("_")
                },
            }
            for rc in ctx['root_causes']
        ],
        "confirmed_vulnerabilities": confirmed_emit,
        "unverified_security_conditions": [
            _finding_to_dict(f, is_confirmed=False) for f in ctx['unverified_security']
        ],
        "informational_observations": [
            _finding_to_dict(f, is_confirmed=False) for f in ctx['info_findings']
        ],
        "supporting_agent_findings": [
            _finding_to_dict(f, is_confirmed=False) for f in ctx['supporting_other']
        ],
        "pipeline_metrics": ctx['pipeline'],
        "request_failures": ctx['request_failures'],
        "attack_chains":    getattr(result, 'attack_chains', []),
        "disclaimer": (
            "This report was generated by Sentinel. "
            "All findings are for defensive purposes only. "
            "Do not use this report to exploit vulnerabilities. "
            "Ensure you have authorization to scan the target system."
        ),
    }


def _finding_to_dict(f: Finding, is_confirmed: bool = False) -> dict:
    """
    mitre stage: strip tactic/technique on unconfirmed findings.
    sanitize stage: clean title, strip duplicate blast radius lines from description.
    """
    mitre_tactic    = f.mitre_tactic    if is_confirmed else None
    mitre_technique = f.mitre_technique if is_confirmed else None

    # sanitize: clean description — strip duplicate blast radius lines
    desc = _sanitize_description(f.description or "")

    # sanitize: clean title — strip [Alpha] prefix, enforce noun phrase format
    title = _sanitize_title(f.title or "")

    return {
        "id":              f.finding_id,
        "severity":        _sev(f),
        "title":           title,
        "description":     desc,
        "agent":           f.agent,
        "file":            f.file_path,
        "cve":             f.cve_id,
        "mitre_tactic":    mitre_tactic,
        "mitre_technique": mitre_technique,
        "remediation":     f.remediation,
        "timestamp":       f.timestamp.isoformat(),
        "evidence":        f.evidence.model_dump() if f.evidence else None,
        "asvs_refs":       f.asvs_refs,
        "wstg_refs":       f.wstg_refs,
        "control_family":  f.control_family,
        "finding_type":    f.finding_type.value if f.finding_type else None,
        "data_surface_type": f.data_surface_type.value if f.data_surface_type else None,
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

        # ── Request Failures (rendered even on clean scans) ───────────────────
        rf = ctx.get('request_failures', {})
        total_failures = rf.get('total_failures', 0)
        if total_failures > 0:
            lines.append("\n---\n")
            lines.append("## ⚠️ Request Failures\n")
            lines.append(f"**Total failed requests:** {total_failures}\n")
            by_agent = rf.get('by_agent', {})
            if by_agent:
                lines.append("| Agent | Failure Class | Count |")
                lines.append("|-------|---------------|-------|")
                for agent, classes in sorted(by_agent.items()):
                    for failure_class, count in sorted(classes.items()):
                        lines.append(f"| {agent} | {failure_class} | {count} |")
            recent = rf.get('recent_url_failures', {})
            if recent:
                lines.append("\n**Recent URL failures:**\n")
                for url, detail in list(recent.items())[:10]:
                    lines.append(f"- `{url}` — {detail.get('failure_class', 'unknown')}: {detail.get('failure_reason', '')[:80]}")
            lines.append("")

        lines.append(_disclaimer())
        return "\n".join(lines)

    lines.append("---\n")

    # ── Section 2: Root Causes ────────────────────────────────────────────────
    if ctx['root_causes']:
        lines.append(f"## 🔗 Root Causes ({len(ctx['root_causes'])})\n")
        lines.append("*Patterns behind confirmed findings — fix the root cause, not just each symptom.*\n")
        for rc in ctx['root_causes']:
            sev       = getattr(rc, 'severity', 'HIGH')
            title     = getattr(rc, 'title', 'Unknown')
            endpoints = getattr(rc, 'endpoints', [])
            pattern   = getattr(rc, 'pattern', '')
            agg_rec   = getattr(rc, 'aggregate_record_count', None)
            agg_bytes = getattr(rc, 'aggregate_bytes', None)
            breakdown = getattr(rc, 'data_surface_breakdown', {})
            deriv_cnt = sum(1 for v in breakdown.values() if v == "DERIVATIVE")

            lines.append(f"**[{sev}] {title}**")
            if pattern:
                lines.append(f"- Pattern: `{pattern}`")
            if endpoints:
                lines.append(f"- Affected endpoints ({len(endpoints)}): "
                             + ', '.join(f'`{e}`' for e in endpoints[:6])
                             + ('...' if len(endpoints) > 6 else ''))
            if agg_rec is not None:
                blast_str = f"{agg_rec} unique records"
                if agg_bytes:
                    blast_str += f" ({agg_bytes:,} bytes)"
                if deriv_cnt:
                    blast_str += f" — {deriv_cnt} derivative path(s) not counted"
                lines.append(f"- Aggregate blast radius: {blast_str}")
            lines.append("")

    # ── Section 3: Confirmed Vulnerabilities ─────────────────────────────────
    lines.append(f"## 🔴 Confirmed Vulnerabilities ({ctx['confirmed_count']})\n")
    lines.append("*Proven by HTTP evidence. Each has a request/response artifact.*\n")

    if ctx['confirmed_vulns']:
        for i, f in enumerate(ctx['confirmed_vulns'], 1):
            icon  = _severity_icon(_sev(f))
            clean_title = _sanitize_title(f.title)
            lines.append(f"### {i}. {icon} {clean_title}")
            lines.append(f"\n**Severity:** {_sev(f)} | **Agent:** `{f.agent}`")
            if f.file_path:
                lines.append(f"**Endpoint:** `{f.file_path}`")
            # mitre: only on confirmed findings
            if f.mitre_tactic:
                tactic = f.mitre_tactic + (f" → {f.mitre_technique}" if f.mitre_technique else "")
                lines.append(f"**MITRE ATT&CK:** {tactic}")
            if f.cve_id:
                lines.append(f"**CVE/ID:** `{f.cve_id}`")
            lines.append(f"\n{_sanitize_description(f.description or '')}")
            if f.remediation:
                lines.append(f"\n**Remediation:** {f.remediation}")
            lines.append("\n---")
    else:
        lines.append("*Pipeline confirmed endpoints but no agent findings linked. "
                     "Check finding file_path alignment.*\n---")

    # ── Section 4: Unverified Security Conditions ─────────────────────────────
    if ctx['unverified_security']:
        lines.append(f"\n## 🟡 Unverified Security Conditions ({len(ctx['unverified_security'])})\n")
        lines.append("*Detected but not confirmed by HTTP evidence pipeline. Require manual verification. MITRE mappings withheld pending confirmation.*\n")
        for sev_label in ['CRITICAL', 'HIGH', 'MEDIUM']:
            sev_group = [f for f in ctx['unverified_security'] if _sev(f) == sev_label]
            if sev_group:
                icon = _severity_icon(sev_label)
                lines.append(f"**{icon} {sev_label} ({len(sev_group)})**")
                for f in sev_group:
                    lines.append(f"- {_sanitize_title(f.title)}")
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

    # ── Section 7: Request Failures ───────────────────────────────────────────
    rf = ctx.get('request_failures', {})
    total_failures = rf.get('total_failures', 0)
    if total_failures > 0:
        lines.append("\n---\n")
        lines.append("## ⚠️ Request Failures\n")
        lines.append(f"**Total failed requests:** {total_failures}\n")
        by_agent = rf.get('by_agent', {})
        if by_agent:
            lines.append("| Agent | Failure Class | Count |")
            lines.append("|-------|---------------|-------|")
            for agent, classes in sorted(by_agent.items()):
                for failure_class, count in sorted(classes.items()):
                    lines.append(f"| {agent} | {failure_class} | {count} |")
        recent = rf.get('recent_url_failures', {})
        if recent:
            lines.append("\n**Recent URL failures:**\n")
            for url, detail in list(recent.items())[:10]:
                lines.append(f"- `{url}` — {detail.get('failure_class', 'unknown')}: {detail.get('failure_reason', '')[:80]}")
        lines.append("")

    lines.append(_disclaimer())
    return "\n".join(lines)


# ── Phase 8 Helpers ───────────────────────────────────────────────────────────

def _extract_vuln_class(title: str) -> str:
    """Extract vulnerability class token from title for dedup key."""
    title_lower = title.lower()
    if "unauthenticated access" in title_lower:
        return "unauthenticated_access"
    if "no https" in title_lower or "https redirect" in title_lower:
        return "no_https"
    if "rate limit" in title_lower:
        return "rate_limiting"
    if "stack trace" in title_lower:
        return "stack_trace"
    if "api version" in title_lower:
        return "api_versioning"
    if "dangerous http" in title_lower:
        return "dangerous_methods"
    if "dns" in title_lower:
        return "dns_info"
    if "metrics" in title_lower or "monitoring" in title_lower:
        return "monitoring_endpoint"
    if "javascript" in title_lower or "hidden api" in title_lower:
        return "js_endpoint_disclosure"
    if "disclosure" in title_lower or "exposed" in title_lower:
        return "information_disclosure"
    # fallback: first 40 chars normalized
    import re
    return re.sub(r'[^a-z0-9]', '_', title_lower[:40]).strip('_')


def _sanitize_title(title: str) -> str:
    """
    sanitize stage: enforce noun phrase title format.
    - Strip [Alpha] prefix
    - Strip 'Confirmed ' prefix (redundant — confirmed section already says confirmed)
    - Strip narrative verb phrases
    - Strip [unverified] suffix handling is done before this point
    """
    import re
    t = title
    # Strip [Alpha] prefix
    t = re.sub(r'^\[Alpha\]\s*', '', t)
    # Strip 'Confirmed Unauthenticated' → 'Unauthenticated'
    t = re.sub(r'^Confirmed\s+', '', t)
    # Strip leading/trailing whitespace
    t = t.strip()
    return t


def _sanitize_description(desc: str) -> str:
    """
    sanitize stage:
    - Remove duplicate blast radius lines (keep first only)
    - Remove duplicate 'CONFIRMED:' occurrences after the first
    - Strip APT group lines from non-confirmed context (handled by mitre gate)
    """
    import re
    if not desc:
        return desc

    # Remove duplicate blast radius appended lines — keep first occurrence
    lines = desc.split('\n')
    blast_seen = False
    cleaned = []
    for line in lines:
        if line.strip().startswith('📊 Blast radius'):
            if blast_seen:
                continue
            blast_seen = True
        cleaned.append(line)
    desc = '\n'.join(cleaned)

    # Remove duplicate CONFIRMED: prefix in body (keep only first sentence's)
    parts = desc.split('CONFIRMED:')
    if len(parts) > 2:
        desc = 'CONFIRMED:' + parts[1] + ''.join(parts[2:])

    return desc.strip()


def _consolidate_confirmed(confirmed_vulns: list, root_causes: list) -> list:
    """
    emit stage: root cause groups with 2+ endpoints → one consolidated finding.
    Single-endpoint findings emit individually.
    Consolidated findings carry 'consolidated': True and 'endpoints': [...].
    """
    if not root_causes:
        return [_finding_to_dict(f, is_confirmed=True) for f in confirmed_vulns]

    emitted_urls: set = set()
    result_list  = []

    for rc in root_causes:
        eps = getattr(rc, 'endpoints', [])
        if len(eps) < 2:
            continue  # handled by individual emit below

        # Find best representative finding for this root cause group
        group_findings = [
            f for f in confirmed_vulns
            if f.file_path and _normalize_url(f.file_path) in
               {_normalize_url(e) for e in eps}
        ]
        if not group_findings:
            continue

        # Use highest-severity finding as representative
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        rep   = sorted(group_findings, key=lambda f: order.get(_sev(f), 5))[0]

        breakdown      = getattr(rc, 'data_surface_breakdown', {})
        agg_records    = getattr(rc, 'aggregate_record_count', None)
        agg_bytes      = getattr(rc, 'aggregate_bytes', None)

        consolidated = _finding_to_dict(rep, is_confirmed=True)
        consolidated["title"]        = _sanitize_title(rc.title)
        consolidated["severity"]     = rc.severity
        consolidated["consolidated"] = True
        consolidated["endpoints"]    = eps
        consolidated["data_surface_breakdown"] = breakdown
        consolidated["aggregate_record_count"] = agg_records
        consolidated["aggregate_bytes"]        = agg_bytes
        consolidated["file"]                   = None  # group finding, not single URL

        result_list.append(consolidated)
        for e in eps:
            emitted_urls.add(_normalize_url(e))

    # Emit individual findings not covered by a root cause group
    for f in confirmed_vulns:
        if _normalize_url(f.file_path or '') not in emitted_urls:
            result_list.append(_finding_to_dict(f, is_confirmed=True))

    return result_list


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
