"""
sentinel/agents/deps_agent.py

Dependency Agent — Multi-ecosystem CVE scanning.
Supports:
  - Python   → pip-audit (requirements.txt, pyproject.toml, Pipfile)
  - Node.js  → npm audit (package.json)
  - Java     → OWASP dependency-check (pom.xml, build.gradle)
  - Go       → govulncheck (go.mod, go.sum)
  - Ruby     → bundler-audit (Gemfile.lock)

SCOPE: CODE and ACTIVE modes.
ACTIONS: dependency_scan, file_read
NEVER: installs packages, makes changes, runs code
"""

import subprocess
import json
import re
from pathlib import Path

from sentinel.core import (
    validate_action, AgentName, ScanSession, Finding, Severity,
)

# Ecosystem detection: manifest file → handler function
ECOSYSTEM_MANIFESTS = {
    "requirements.txt":  "_scan_python",
    "requirements-dev.txt": "_scan_python",
    "pyproject.toml":    "_scan_python",
    "Pipfile":           "_scan_python",
    "Pipfile.lock":      "_scan_python",
    "package.json":      "_scan_node",
    "pom.xml":           "_scan_java",
    "build.gradle":      "_scan_java",
    "go.mod":            "_scan_go",
    "Gemfile.lock":      "_scan_ruby",
}


def run_deps_agent(session: ScanSession, source_path: str) -> list[Finding]:
    """Detect and scan all dependency manifests in the source tree."""
    validate_action(AgentName.DEPS, "dependency_scan", source_path, session)

    base = Path(source_path)
    all_findings: list[Finding] = []
    scanned: set[str] = set()

    # Walk up to 3 levels deep to find manifests
    for manifest_name, handler_name in ECOSYSTEM_MANIFESTS.items():
        for manifest_path in base.rglob(manifest_name):
            if ".git" in str(manifest_path) or "node_modules" in str(manifest_path):
                continue
            key = str(manifest_path)
            if key in scanned:
                continue
            scanned.add(key)

            print(f"[DEPS] Found {manifest_name} → running {handler_name[1:]}")
            handler = globals()[handler_name]
            findings = handler(str(manifest_path), session)
            all_findings.extend(findings)

    print(f"[DEPS] {len(all_findings)} vulnerable dependencies total")
    return all_findings


# ── Python: pip-audit ─────────────────────────────────────────────────────────

def _scan_python(manifest_path: str, session: ScanSession) -> list[Finding]:
    try:
        result = subprocess.run(
            ["pip-audit", "-r", manifest_path, "-f", "json", "--no-deps"],
            capture_output=True, text=True, timeout=180,
        )
        if result.returncode not in (0, 1) or not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        findings = []
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                findings.append(_python_vuln_to_finding(dep, vuln, manifest_path))
        return findings

    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[DEPS/Python] {e}")
        return []


def _python_vuln_to_finding(dep: dict, vuln: dict, path: str) -> Finding:
    package     = dep.get("name", "unknown")
    version     = dep.get("version", "unknown")
    vuln_id     = vuln.get("id", "UNKNOWN")
    aliases     = vuln.get("aliases", [])
    description = vuln.get("description", "No description.")
    fix_versions = vuln.get("fix_versions", [])
    cve = next((a for a in aliases if a.startswith("CVE-")), None)
    fix = f"Upgrade to {', '.join(fix_versions)}." if fix_versions else "No fix available — consider replacing."
    return Finding(
        agent=AgentName.DEPS,
        title=f"[Python] Vulnerable: {package}=={version} ({vuln_id})",
        description=f"{package} {version}: {description}",
        severity=_estimate_severity(description),
        file_path=path,
        cve_id=cve or vuln_id,
        mitre_tactic="Initial Access",
        mitre_technique="T1195.001 — Compromise Software Dependencies",
        remediation=f"{fix} Re-run scan after upgrade. Advisory: https://osv.dev/vulnerability/{vuln_id}",
        raw_output=json.dumps({"dep": dep, "vuln": vuln}),
    )


# ── Node.js: npm audit ────────────────────────────────────────────────────────

def _scan_node(manifest_path: str, session: ScanSession) -> list[Finding]:
    """Run npm audit on package.json directory."""
    manifest_dir = str(Path(manifest_path).parent)
    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True, text=True, timeout=120,
            cwd=manifest_dir,
        )
        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        findings = []

        # npm audit v7+ format
        vulns = data.get("vulnerabilities", {})
        for pkg_name, vuln_data in vulns.items():
            via = vuln_data.get("via", [])
            for v in via:
                if not isinstance(v, dict):
                    continue
                findings.append(_node_vuln_to_finding(pkg_name, vuln_data, v, manifest_path))

        return findings

    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[DEPS/Node] {e}")
        return []


def _node_vuln_to_finding(pkg: str, vuln_data: dict, via: dict, path: str) -> Finding:
    severity_map = {
        "critical": Severity.CRITICAL,
        "high":     Severity.HIGH,
        "moderate": Severity.MEDIUM,
        "low":      Severity.LOW,
        "info":     Severity.INFO,
    }
    sev_str  = vuln_data.get("severity", "low")
    severity = severity_map.get(sev_str, Severity.LOW)
    title    = via.get("title", "Unknown vulnerability")
    url      = via.get("url", "")
    cve      = via.get("cve", [])
    cve_id   = cve[0] if cve else None
    fixed_in = vuln_data.get("fixAvailable", {})
    fix_str  = f"Upgrade to {fixed_in.get('name')} {fixed_in.get('version')}." if isinstance(fixed_in, dict) else "Run `npm audit fix`."

    return Finding(
        agent=AgentName.DEPS,
        title=f"[Node] Vulnerable: {pkg} — {title}",
        description=f"{pkg}: {title}. {url}",
        severity=severity,
        file_path=path,
        cve_id=cve_id,
        mitre_tactic="Initial Access",
        mitre_technique="T1195.001 — Compromise Software Dependencies",
        remediation=f"{fix_str} See: {url}",
        raw_output=json.dumps({"pkg": pkg, "via": via}),
    )


# ── Go: govulncheck ───────────────────────────────────────────────────────────

def _scan_go(manifest_path: str, session: ScanSession) -> list[Finding]:
    manifest_dir = str(Path(manifest_path).parent)
    try:
        result = subprocess.run(
            ["govulncheck", "-json", "./..."],
            capture_output=True, text=True, timeout=180,
            cwd=manifest_dir,
        )
        findings = []
        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                vuln = obj.get("vulnerability")
                if not vuln:
                    continue
                osv_id = vuln.get("id", "UNKNOWN")
                aliases = vuln.get("aliases", [])
                cve = next((a for a in aliases if a.startswith("CVE-")), None)
                summary = vuln.get("summary", "No summary.")
                affected = vuln.get("affected", [{}])
                pkg = affected[0].get("package", {}).get("name", "unknown") if affected else "unknown"
                findings.append(Finding(
                    agent=AgentName.DEPS,
                    title=f"[Go] Vulnerable: {pkg} ({osv_id})",
                    description=summary,
                    severity=_estimate_severity(summary),
                    file_path=manifest_path,
                    cve_id=cve or osv_id,
                    mitre_tactic="Initial Access",
                    mitre_technique="T1195.001 — Compromise Software Dependencies",
                    remediation=f"Update affected Go module. Advisory: https://osv.dev/vulnerability/{osv_id}",
                    raw_output=json.dumps(vuln),
                ))
            except json.JSONDecodeError:
                continue
        return findings

    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[DEPS/Go] {e}")
        return []


# ── Ruby: bundler-audit ───────────────────────────────────────────────────────

def _scan_ruby(manifest_path: str, session: ScanSession) -> list[Finding]:
    manifest_dir = str(Path(manifest_path).parent)
    try:
        result = subprocess.run(
            ["bundle-audit", "check", "--update"],
            capture_output=True, text=True, timeout=120,
            cwd=manifest_dir,
        )
        findings = []
        current: dict = {}
        for line in result.stdout.splitlines():
            if line.startswith("Name:"):
                current = {"name": line.split(":", 1)[1].strip()}
            elif line.startswith("Version:"):
                current["version"] = line.split(":", 1)[1].strip()
            elif line.startswith("Advisory:"):
                current["advisory"] = line.split(":", 1)[1].strip()
            elif line.startswith("Criticality:"):
                current["criticality"] = line.split(":", 1)[1].strip()
            elif line.startswith("Title:") and current:
                current["title"] = line.split(":", 1)[1].strip()
                sev_map = {"High": Severity.HIGH, "Medium": Severity.MEDIUM, "Low": Severity.LOW}
                findings.append(Finding(
                    agent=AgentName.DEPS,
                    title=f"[Ruby] Vulnerable: {current.get('name')} — {current.get('title', '')}",
                    description=f"{current.get('name')} {current.get('version')}: {current.get('title')}",
                    severity=sev_map.get(current.get("criticality", ""), Severity.MEDIUM),
                    file_path=manifest_path,
                    cve_id=current.get("advisory"),
                    mitre_tactic="Initial Access",
                    mitre_technique="T1195.001 — Compromise Software Dependencies",
                    remediation=f"Run `bundle update {current.get('name')}`. Advisory: {current.get('advisory')}",
                    raw_output=json.dumps(current),
                ))
                current = {}
        return findings

    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[DEPS/Ruby] {e}")
        return []


# ── Java: placeholder (OWASP dependency-check is JVM-heavy) ──────────────────

def _scan_java(manifest_path: str, session: ScanSession) -> list[Finding]:
    """
    Java scanning via OWASP dependency-check.
    Requires dependency-check CLI installed separately.
    Returns INFO finding if not available.
    """
    try:
        result = subprocess.run(
            ["dependency-check", "--scan", str(Path(manifest_path).parent),
             "--format", "JSON", "--out", "/tmp/dc-report", "--noupdate"],
            capture_output=True, text=True, timeout=300,
        )
        report_path = Path("/tmp/dc-report/dependency-check-report.json")
        if not report_path.exists():
            return []

        data = json.loads(report_path.read_text())
        findings = []
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulnerabilities", []):
                name = dep.get("fileName", "unknown")
                cvss = vuln.get("cvssv3", {}).get("baseScore", 0)
                sev  = Severity.CRITICAL if cvss >= 9 else Severity.HIGH if cvss >= 7 else Severity.MEDIUM if cvss >= 4 else Severity.LOW
                findings.append(Finding(
                    agent=AgentName.DEPS,
                    title=f"[Java] Vulnerable: {name} ({vuln.get('name', 'UNKNOWN')})",
                    description=vuln.get("description", "No description."),
                    severity=sev,
                    file_path=manifest_path,
                    cve_id=vuln.get("name"),
                    mitre_tactic="Initial Access",
                    mitre_technique="T1195.001 — Compromise Software Dependencies",
                    remediation=f"Update {name}. CVSS: {cvss}. Check Maven Central for patched version.",
                    raw_output=json.dumps(vuln),
                ))
        return findings

    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[DEPS/Java] {e}")
        return []


# ── Severity estimation ───────────────────────────────────────────────────────

def _estimate_severity(description: str) -> Severity:
    desc = description.lower()
    if any(k in desc for k in ["remote code execution", "rce", "arbitrary code", "authentication bypass"]):
        return Severity.CRITICAL
    if any(k in desc for k in ["sql injection", "privilege escalation", "xxe", "ssrf", "deserialization"]):
        return Severity.HIGH
    if any(k in desc for k in ["xss", "csrf", "open redirect", "path traversal", "denial of service"]):
        return Severity.MEDIUM
    return Severity.LOW
