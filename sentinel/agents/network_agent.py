"""
sentinel/agents/network_agent.py

Network Topology Agent — Trust boundary and lateral movement mapping.
Analyzes:
  - What services can reach what other services
  - Which services are unnecessarily exposed
  - Lateral movement paths if a component is compromised
  - Trust boundary violations
  - Network segmentation gaps
  - DNS exposure and subdomain enumeration

SCOPE: PASSIVE, PROBE, and ACTIVE modes.
ACTIONS: dns_lookup, http_headers, port_scan_passive, port_scan_active, subfinder_scan
NEVER: exploits, modifies network config, sends payloads
"""

import subprocess
import socket
import json
import requests
from urllib.parse import urlparse
# TLS warnings suppressed per-request in safe_request/probe_with_evidence

from sentinel.core import (
    validate_action, AgentName, ScanSession, Finding, Severity, ScanMode,
)

# Services that should NEVER be internet-facing
NEVER_PUBLIC = {
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    9300: "Elasticsearch (cluster)",
    2379: "etcd",
    2380: "etcd (peer)",
    11211: "Memcached",
    5984: "CouchDB",
    8086: "InfluxDB",
    9042: "Cassandra",
    7000: "Cassandra (inter-node)",
    2181: "ZooKeeper",
}

# Services that are suspicious if public (should be behind VPN/firewall)
SUSPICIOUS_PUBLIC = {
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    161:  "SNMP",
    389:  "LDAP",
    445:  "SMB",
    1433: "MSSQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt (often dev/debug)",
    8443: "HTTPS-Alt",
    9090: "Prometheus/admin",
    9091: "Prometheus",
    4848: "GlassFish Admin",
    8161: "ActiveMQ Admin",
    61616: "ActiveMQ",
}


def run_network_agent(session: ScanSession, target: str) -> list[Finding]:
    """Run network topology analysis on target."""
    findings = []

    # DNS and subdomain analysis
    findings.extend(_analyze_dns(session, target))

    if session.mode in (ScanMode.PASSIVE, ScanMode.ACTIVE):
        findings.extend(_analyze_exposed_services(session, target))

    if session.mode == ScanMode.ACTIVE:
        findings.extend(_enumerate_subdomains(session, target))
        findings.extend(_analyze_lateral_movement(session, target, findings))

    print(f"[NETWORK] {len(findings)} network topology findings")
    return findings


def _analyze_dns(session: ScanSession, target: str) -> list[Finding]:
    """Analyze DNS records for security issues."""
    validate_action(AgentName.NETWORK, "dns_lookup", target, session)

    findings = []
    hostname = _extract_hostname(target)

    if hostname in ("localhost", "127.0.0.1") or _is_ip(hostname):
        return findings

    # Check for wildcard DNS
    try:
        wildcard = f"definitely-does-not-exist-sentinel-check.{hostname}"
        try:
            socket.gethostbyname(wildcard)
            findings.append(Finding(
                agent=AgentName.NETWORK,
                title="Wildcard DNS Configured",
                description=f"Wildcard DNS is active on {hostname}. Any subdomain resolves to an IP, enabling subdomain takeover attacks.",
                severity=Severity.MEDIUM,
                file_path=hostname,
                mitre_tactic="Resource Development",
                mitre_technique="T1584.001 — Domains",
                remediation="Remove wildcard DNS records unless specifically required. Use explicit subdomain records only.",
            ))
        except socket.gaierror:
            pass  # No wildcard — good
    except Exception:
        pass

    # MX record check — do mail servers accept connections?
    try:
        result = subprocess.run(
            ["nslookup", "-type=MX", hostname],
            capture_output=True, text=True, timeout=10,
        )
        if "mail exchanger" in result.stdout.lower():
            findings.append(Finding(
                agent=AgentName.NETWORK,
                title=f"Mail Server Configured: {hostname}",
                description="MX records found. Ensure SPF, DKIM, and DMARC records are properly configured to prevent email spoofing.",
                severity=Severity.INFO,
                file_path=hostname,
                mitre_tactic="Initial Access",
                mitre_technique="T1566 — Phishing",
                remediation="Verify SPF record exists with -all. Ensure DMARC policy is 'reject'. Confirm DKIM is signing outbound mail.",
            ))
    except Exception:
        pass

    return findings


def _analyze_exposed_services(session: ScanSession, target: str) -> list[Finding]:
    """Check for dangerously exposed services."""
    validate_action(AgentName.NETWORK, "port_scan_passive", target, session)

    findings = []
    hostname = _extract_hostname(target)

    # Check database and critical services
    all_risky = {**NEVER_PUBLIC, **SUSPICIOUS_PUBLIC}

    for port, service in all_risky.items():
        if _port_is_open(hostname, port):
            is_critical = port in NEVER_PUBLIC
            severity = Severity.CRITICAL if is_critical else Severity.HIGH

            findings.append(Finding(
                agent=AgentName.NETWORK,
                title=f"Exposed Service: {service} (port {port})",
                description=(
                    f"{service} on port {port} is reachable from the scan origin. "
                    f"{'This service should NEVER be internet-facing.' if is_critical else 'This service is suspicious when publicly accessible.'}"
                ),
                severity=severity,
                file_path=f"{hostname}:{port}",
                mitre_tactic="Discovery",
                mitre_technique="T1046 — Network Service Discovery",
                remediation=(
                    f"Immediately restrict {service} port {port} via firewall rules. "
                    f"{'Place behind VPN or internal network only.' if is_critical else 'Ensure access is authenticated and limited to authorized IPs.'}"
                ),
            ))

    return findings


def _enumerate_subdomains(session: ScanSession, target: str) -> list[Finding]:
    """Enumerate subdomains using subfinder if available."""
    validate_action(AgentName.NETWORK, "subfinder_scan", target, session)

    hostname = _extract_hostname(target)
    if _is_ip(hostname) or hostname == "localhost":
        return []

    findings = []
    subdomains = []

    # Try subfinder first
    try:
        result = subprocess.run(
            ["subfinder", "-d", hostname, "-silent", "-timeout", "30"],
            capture_output=True, text=True, timeout=60,
        )
        subdomains = [s.strip() for s in result.stdout.splitlines() if s.strip()]
    except FileNotFoundError:
        # Fallback: check common subdomains manually
        subdomains = _check_common_subdomains(hostname)

    if subdomains:
        findings.append(Finding(
            agent=AgentName.NETWORK,
            title=f"Subdomains Discovered: {hostname}",
            description=(
                f"Found {len(subdomains)} subdomains: {', '.join(subdomains[:10])}. "
                "Each subdomain is an additional attack surface. Review each for security posture."
            ),
            severity=Severity.INFO,
            file_path=hostname,
            mitre_tactic="Reconnaissance",
            mitre_technique="T1590.001 — Gather Victim Network Information",
            remediation=(
                "Audit all subdomains. Remove unused/forgotten subdomains (prevent takeover). "
                "Ensure each subdomain has proper security headers and TLS. "
                "Check for development/staging subdomains that may have weaker security."
            ),
        ))

        # Check for potentially sensitive subdomains
        sensitive_keywords = ["dev", "staging", "test", "admin", "api", "internal",
                              "beta", "old", "backup", "db", "database", "vpn"]
        sensitive_found = [s for s in subdomains
                          if any(kw in s.lower() for kw in sensitive_keywords)]

        if sensitive_found:
            findings.append(Finding(
                agent=AgentName.NETWORK,
                title=f"Sensitive Subdomains Exposed: {', '.join(sensitive_found[:5])}",
                description=(
                    f"Potentially sensitive subdomains are publicly accessible: "
                    f"{', '.join(sensitive_found[:5])}. "
                    "Development and admin subdomains often have weaker security controls."
                ),
                severity=Severity.HIGH,
                file_path=hostname,
                mitre_tactic="Reconnaissance",
                mitre_technique="T1590.001 — Gather Victim Network Information",
                remediation=(
                    "Restrict access to dev/staging/admin subdomains by IP or VPN. "
                    "Ensure these subdomains are not accessible from the public internet. "
                    "Remove any subdomains that are no longer in use."
                ),
            ))

    return findings


def _analyze_lateral_movement(session: ScanSession, target: str,
                               existing_findings: list[Finding]) -> list[Finding]:
    """
    Analyze potential lateral movement paths based on discovered services.
    If X is compromised, what else can be reached?
    """
    findings = []

    # Look for exposed internal services in existing findings
    exposed_services = [
        f for f in existing_findings
        if "Exposed Service" in f.title
    ]

    if len(exposed_services) >= 2:
        service_names = [f.title.split(":")[1].strip() for f in exposed_services[:5]]
        findings.append(Finding(
            agent=AgentName.NETWORK,
            title="Lateral Movement Risk: Multiple Services Exposed",
            description=(
                f"Multiple sensitive services are exposed: {', '.join(service_names)}. "
                "If any single service is compromised, an attacker can pivot to others "
                "without crossing a network boundary. This indicates missing network segmentation."
            ),
            severity=Severity.CRITICAL,
            file_path=target,
            mitre_tactic="Lateral Movement",
            mitre_technique="T1210 — Exploitation of Remote Services",
            remediation=(
                "Implement network segmentation immediately. "
                "Database servers should only accept connections from application servers, not the internet. "
                "Use separate VLANs or security groups for each tier (web, app, database). "
                "Implement zero-trust networking: every service authenticates every connection."
            ),
        ))

    return findings


def _check_common_subdomains(hostname: str) -> list[str]:
    """Check common subdomain names when subfinder unavailable."""
    common = ["www", "api", "dev", "staging", "test", "admin", "mail",
              "vpn", "remote", "portal", "dashboard", "app", "beta"]
    found = []
    for sub in common:
        try:
            socket.gethostbyname(f"{sub}.{hostname}")
            found.append(f"{sub}.{hostname}")
        except socket.gaierror:
            pass
    return found


def _port_is_open(hostname: str, port: int, timeout: float = 2.0) -> bool:
    """Quick TCP connect check."""
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _extract_hostname(target: str) -> str:
    """Extract hostname from URL or return as-is."""
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split(":")[0]


def _is_ip(hostname: str) -> bool:
    """Check if hostname is an IP address."""
    try:
        socket.inet_aton(hostname)
        return True
    except socket.error:
        return False
