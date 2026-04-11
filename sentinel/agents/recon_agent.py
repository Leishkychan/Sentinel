"""
sentinel/agents/recon_agent.py

Recon Agent — Passive Reconnaissance.
Collects surface-level information about a target:
- DNS records
- WHOIS data
- HTTP headers + technology fingerprinting
- Passive port scan (ping only — no port enumeration in PASSIVE mode)
- Port enumeration (ACTIVE mode only)

SCOPE: PASSIVE and ACTIVE modes.
NEVER: exploits, fuzzes, brute forces, submits forms, modifies anything.
"""

import subprocess
import socket
import json
import requests  # for RequestException type only
from sentinel.core.evidence import safe_request
from datetime import datetime, timezone

from sentinel.core import (
    validate_action, AgentName, ScanSession, Finding, Severity, ScanMode,
)


def run_recon_agent(session: ScanSession, target: str) -> list[Finding]:
    """
    Run recon on the target.
    PASSIVE: DNS, WHOIS, HTTP headers, whatweb (if available)
    ACTIVE:  Above + port scan
    """
    findings = []

    findings.extend(_dns_lookup(session, target))
    findings.extend(_http_headers(session, target))
    findings.extend(_whois_lookup(session, target))

    if session.mode == ScanMode.ACTIVE:
        findings.extend(_port_scan_active(session, target))
    else:
        findings.extend(_port_scan_passive(session, target))

    print(f"[RECON] {len(findings)} recon findings for {target}")
    return findings


# ── DNS Lookup ────────────────────────────────────────────────────────────────

def _dns_lookup(session: ScanSession, target: str) -> list[Finding]:
    validate_action(AgentName.RECON, "dns_lookup", target, session)

    findings = []
    # Strip protocol, path, AND port to get bare hostname
    from urllib.parse import urlparse
    parsed = urlparse(target if "://" in target else "http://" + target)
    clean = parsed.hostname or target

    try:
        ip = socket.gethostbyname(clean)
        findings.append(Finding(
            agent=AgentName.RECON,
            title=f"DNS Resolution: {clean}",
            description=f"Target resolves to IP: {ip}",
            severity=Severity.INFO,
            file_path=target,
            mitre_tactic="Reconnaissance",
            mitre_technique="T1590.002 — DNS",
            remediation="Informational. Ensure DNS records are intentional and up to date.",
        ))

        # Check for multiple A records (load balancer / CDN)
        results = socket.getaddrinfo(clean, None)
        ips = list(set(r[4][0] for r in results))
        if len(ips) > 1:
            findings.append(Finding(
                agent=AgentName.RECON,
                title=f"Multiple DNS Records: {clean}",
                description=f"Target resolves to {len(ips)} IPs: {', '.join(ips)}. May indicate load balancer or CDN.",
                severity=Severity.INFO,
                file_path=target,
                mitre_tactic="Reconnaissance",
                mitre_technique="T1590.002 — DNS",
                remediation="Informational. Confirm all IPs are expected and secured equally.",
            ))

    except socket.gaierror as e:
        findings.append(Finding(
            agent=AgentName.RECON,
            title=f"DNS Resolution Failed: {clean}",
            description=f"Could not resolve {clean}: {e}",
            severity=Severity.INFO,
            file_path=target,
            remediation="Verify the target hostname is correct and reachable.",
        ))

    return findings


# ── HTTP Headers ──────────────────────────────────────────────────────────────

def _http_headers(session: ScanSession, target: str) -> list[Finding]:
    validate_action(AgentName.RECON, "http_headers", target, session)

    findings = []
    url = target if target.startswith("http") else f"http://{target}"

    try:
        resp = safe_request("GET", url, timeout=10, allow_redirects=True)

        # Collect interesting headers as INFO findings
        interesting = {}
        for h in ["Server", "X-Powered-By", "X-Generator", "X-Drupal-Cache",
                  "X-WordPress", "X-AspNet-Version", "Via", "X-Cache"]:
            if h in resp.headers:
                interesting[h] = resp.headers[h]

        if interesting:
            findings.append(Finding(
                agent=AgentName.RECON,
                title="Technology Stack Identified via Headers",
                description=f"Server headers reveal: {json.dumps(interesting)}",
                severity=Severity.LOW,
                file_path=url,
                mitre_tactic="Reconnaissance",
                mitre_technique="T1592.002 — Gather Victim Host Information: Software",
                remediation="Remove or obscure headers that reveal server technology. Attackers use these for targeted CVE lookups.",
            ))

        # Check if HTTP redirects to HTTPS
        if resp.url.startswith("https://") and url.startswith("http://"):
            findings.append(Finding(
                agent=AgentName.RECON,
                title="HTTP to HTTPS Redirect Confirmed",
                description=f"Target redirects HTTP to HTTPS. Good.",
                severity=Severity.INFO,
                file_path=url,
                remediation="Informational. Ensure redirect is permanent (301) not temporary (302).",
            ))
        elif url.startswith("http://") and not resp.url.startswith("https://"):
            findings.append(Finding(
                agent=AgentName.RECON,
                title="No HTTPS Redirect Detected",
                description="Target does not redirect HTTP to HTTPS. Traffic may be sent unencrypted.",
                severity=Severity.HIGH,
                file_path=url,
                mitre_tactic="Defense Evasion",
                mitre_technique="T1557 — Adversary-in-the-Middle",
                remediation="Configure permanent 301 redirect from HTTP to HTTPS on all endpoints.",
            ))

    except requests.RequestException as e:
        findings.append(Finding(
            agent=AgentName.RECON,
            title=f"HTTP Probe Failed: {url}",
            description=str(e),
            severity=Severity.INFO,
            file_path=url,
            remediation="Target may be unreachable or firewalled. Verify connectivity.",
        ))

    return findings


# ── WHOIS ─────────────────────────────────────────────────────────────────────

def _whois_lookup(session: ScanSession, target: str) -> list[Finding]:
    validate_action(AgentName.RECON, "whois_lookup", target, session)

    findings = []
    # Strip protocol, path, AND port to get bare hostname
    from urllib.parse import urlparse
    parsed = urlparse(target if "://" in target else "http://" + target)
    clean = parsed.hostname or target

    # Skip WHOIS for IPs and localhost
    if clean in ("localhost", "127.0.0.1") or clean.replace(".", "").isdigit():
        return findings

    try:
        result = subprocess.run(
            ["whois", clean],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout:
            # Extract expiry date if present
            for line in result.stdout.splitlines():
                if "expir" in line.lower() and ":" in line:
                    findings.append(Finding(
                        agent=AgentName.RECON,
                        title=f"Domain Expiry Info: {clean}",
                        description=f"WHOIS record: {line.strip()}",
                        severity=Severity.INFO,
                        file_path=clean,
                        mitre_tactic="Reconnaissance",
                        mitre_technique="T1590.001 — Determine Physical Locations",
                        remediation="Informational. Ensure domain renewal is monitored — expired domains can be hijacked.",
                    ))
                    break
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass  # WHOIS not available or timed out — not critical

    return findings


# ── Port Scan (Passive — ping only) ──────────────────────────────────────────

def _port_scan_passive(session: ScanSession, target: str) -> list[Finding]:
    """Ping scan only — confirms host is up. No port enumeration."""
    validate_action(AgentName.RECON, "port_scan_passive", target, session)

    # Strip protocol, path, AND port to get bare hostname
    from urllib.parse import urlparse
    parsed = urlparse(target if "://" in target else "http://" + target)
    clean = parsed.hostname or target
    findings = []

    try:
        result = subprocess.run(
            ["nmap", "-sn", "-T2", "--host-timeout", "10s", clean],
            capture_output=True, text=True, timeout=20,
        )
        if "Host is up" in result.stdout:
            findings.append(Finding(
                agent=AgentName.RECON,
                title=f"Host Reachable: {clean}",
                description="Ping scan confirms host is up and responding.",
                severity=Severity.INFO,
                file_path=clean,
                mitre_tactic="Reconnaissance",
                mitre_technique="T1595.001 — Scanning IP Blocks",
                remediation="Informational. Consider ICMP filtering if host discovery should be restricted.",
            ))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass  # nmap not installed or timed out

    return findings


# ── Port Scan (Active — port enumeration) ────────────────────────────────────

def _port_scan_active(session: ScanSession, target: str) -> list[Finding]:
    """Port scan — ACTIVE mode only. Enumerates common ports."""
    validate_action(AgentName.RECON, "port_scan_active", target, session)

    # Strip protocol, path, AND port to get bare hostname
    from urllib.parse import urlparse
    parsed = urlparse(target if "://" in target else "http://" + target)
    clean = parsed.hostname or target
    findings = []

    # High-risk ports to flag
    risky_ports = {
        21:   ("FTP",        Severity.HIGH,   "FTP transmits credentials in plaintext. Replace with SFTP."),
        22:   ("SSH",        Severity.INFO,   "SSH open. Ensure key-based auth only, disable root login."),
        23:   ("Telnet",     Severity.CRITICAL,"Telnet transmits all data in plaintext. Disable immediately."),
        25:   ("SMTP",       Severity.MEDIUM,  "SMTP open. Ensure authentication required."),
        3306: ("MySQL",      Severity.CRITICAL,"MySQL exposed publicly. Should never be internet-facing."),
        5432: ("PostgreSQL", Severity.CRITICAL,"PostgreSQL exposed publicly. Should never be internet-facing."),
        6379: ("Redis",      Severity.CRITICAL,"Redis exposed publicly. Often unauthenticated by default."),
        27017:("MongoDB",    Severity.CRITICAL,"MongoDB exposed publicly. Often unauthenticated by default."),
        8080: ("HTTP Alt",   Severity.MEDIUM,  "Alternate HTTP port open. Ensure it's intentional."),
        8443: ("HTTPS Alt",  Severity.LOW,     "Alternate HTTPS port open."),
        9200: ("Elasticsearch", Severity.CRITICAL, "Elasticsearch often unauthenticated. Restrict immediately."),
    }

    try:
        ports = ",".join(str(p) for p in risky_ports.keys())
        result = subprocess.run(
            ["nmap", "-p", ports, "-T3", "--open", "--host-timeout", "30s",
             "-oX", "-", clean],
            capture_output=True, text=True, timeout=60,
        )

        for port, (service, severity, remediation) in risky_ports.items():
            if f"{port}/open" in result.stdout or f"<port protocol" in result.stdout:
                # Parse XML output for open ports
                if f'portid="{port}"' in result.stdout and 'state="open"' in result.stdout:
                    findings.append(Finding(
                        agent=AgentName.RECON,
                        title=f"Open Port Detected: {port}/{service}",
                        description=f"Port {port} ({service}) is open on {clean}.",
                        severity=severity,
                        file_path=clean,
                        mitre_tactic="Reconnaissance",
                        mitre_technique="T1046 — Network Service Discovery",
                        remediation=remediation,
                    ))

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return findings
