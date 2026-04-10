"""
sentinel/core/mitre.py

MITRE ATT&CK Enrichment.
Takes a Finding and enriches it with:
- Tactic (the "why" — what the attacker is trying to achieve)
- Technique ID + name (the "how")
- ATT&CK URL for reference

Full mapping table covering the most common findings
from SAST, deps, config, and recon agents.
"""

from dataclasses import dataclass
from typing import Optional
from .models import Finding, AgentName


@dataclass
class MitreMapping:
    tactic:        str
    technique_id:  str
    technique_name: str

    @property
    def url(self) -> str:
        tid = self.technique_id.replace(".", "/")
        return f"https://attack.mitre.org/techniques/{tid}/"

    @property
    def full_technique(self) -> str:
        return f"{self.technique_id} — {self.technique_name}"


# ── Master Mapping Table ──────────────────────────────────────────────────────
# Key: lowercase keyword found in finding title or description
# Value: MitreMapping

KEYWORD_MAP: dict[str, MitreMapping] = {

    # Credential Access
    "hardcoded password":        MitreMapping("Credential Access",    "T1552.001", "Credentials in Files"),
    "hardcoded secret":          MitreMapping("Credential Access",    "T1552.001", "Credentials in Files"),
    "hardcoded token":           MitreMapping("Credential Access",    "T1552.001", "Credentials in Files"),
    "hardcoded api key":         MitreMapping("Credential Access",    "T1552.001", "Credentials in Files"),
    "aws access key":            MitreMapping("Credential Access",    "T1552.005", "Cloud Instance Metadata API"),
    "aws secret":                MitreMapping("Credential Access",    "T1552.005", "Cloud Instance Metadata API"),
    "database url":              MitreMapping("Credential Access",    "T1552.001", "Credentials in Files"),
    "weak crypto":               MitreMapping("Credential Access",    "T1600",     "Weaken Encryption"),
    "md5":                       MitreMapping("Credential Access",    "T1600",     "Weaken Encryption"),
    "sha1":                      MitreMapping("Credential Access",    "T1600",     "Weaken Encryption"),
    "insecure cookie":           MitreMapping("Credential Access",    "T1539",     "Steal Web Session Cookie"),
    "cookie":                    MitreMapping("Credential Access",    "T1539",     "Steal Web Session Cookie"),

    # Initial Access
    "sql injection":             MitreMapping("Initial Access",       "T1190",     "Exploit Public-Facing Application"),
    "xss":                       MitreMapping("Initial Access",       "T1059.007", "JavaScript"),
    "cross-site scripting":      MitreMapping("Initial Access",       "T1059.007", "JavaScript"),
    "flask debug":               MitreMapping("Initial Access",       "T1190",     "Exploit Public-Facing Application"),
    "debug mode":                MitreMapping("Initial Access",       "T1190",     "Exploit Public-Facing Application"),
    "exposed admin":             MitreMapping("Initial Access",       "T1190",     "Exploit Public-Facing Application"),
    "admin panel":               MitreMapping("Initial Access",       "T1190",     "Exploit Public-Facing Application"),
    "content security policy":   MitreMapping("Initial Access",       "T1059.007", "JavaScript"),
    "cors":                      MitreMapping("Initial Access",       "T1185",     "Browser Session Hijacking"),
    "xml":                       MitreMapping("Initial Access",       "T1190",     "Exploit Public-Facing Application"),
    "deserialization":           MitreMapping("Initial Access",       "T1190",     "Exploit Public-Facing Application"),
    "pickle":                    MitreMapping("Initial Access",       "T1190",     "Exploit Public-Facing Application"),

    # Execution
    "eval":                      MitreMapping("Execution",            "T1059.006", "Python"),
    "exec":                      MitreMapping("Execution",            "T1059.006", "Python"),
    "subprocess":                MitreMapping("Execution",            "T1059",     "Command and Scripting Interpreter"),
    "shell=true":                MitreMapping("Execution",            "T1059",     "Command and Scripting Interpreter"),
    "command injection":         MitreMapping("Execution",            "T1059",     "Command and Scripting Interpreter"),
    "yaml.load":                 MitreMapping("Execution",            "T1059.006", "Python"),
    "template injection":        MitreMapping("Execution",            "T1059.007", "JavaScript"),

    # Defense Evasion
    "ssl":                       MitreMapping("Defense Evasion",      "T1553",     "Subvert Trust Controls"),
    "tls":                       MitreMapping("Defense Evasion",      "T1553",     "Subvert Trust Controls"),
    "verify=false":              MitreMapping("Defense Evasion",      "T1553",     "Subvert Trust Controls"),
    "certificate":               MitreMapping("Defense Evasion",      "T1553",     "Subvert Trust Controls"),
    "hsts":                      MitreMapping("Defense Evasion",      "T1557",     "Adversary-in-the-Middle"),
    "strict-transport":          MitreMapping("Defense Evasion",      "T1557",     "Adversary-in-the-Middle"),
    "x-frame":                   MitreMapping("Defense Evasion",      "T1185",     "Browser Session Hijacking"),
    "clickjacking":              MitreMapping("Defense Evasion",      "T1185",     "Browser Session Hijacking"),
    "random":                    MitreMapping("Defense Evasion",      "T1600",     "Weaken Encryption"),

    # Discovery
    "server version":            MitreMapping("Reconnaissance",       "T1592",     "Gather Victim Host Information"),
    "version disclosure":        MitreMapping("Reconnaissance",       "T1592",     "Gather Victim Host Information"),
    "x-powered-by":              MitreMapping("Reconnaissance",       "T1592",     "Gather Victim Host Information"),
    "directory listing":         MitreMapping("Discovery",            "T1083",     "File and Directory Discovery"),
    "exposed path":              MitreMapping("Discovery",            "T1083",     "File and Directory Discovery"),
    "open port":                 MitreMapping("Reconnaissance",       "T1046",     "Network Service Discovery"),
    "port scan":                 MitreMapping("Reconnaissance",       "T1046",     "Network Service Discovery"),

    # Persistence
    "backdoor":                  MitreMapping("Persistence",          "T1505",     "Server Software Component"),
    "webshell":                  MitreMapping("Persistence",          "T1505.003", "Web Shell"),

    # Privilege Escalation
    "privilege":                 MitreMapping("Privilege Escalation", "T1068",     "Exploitation for Privilege Escalation"),
    "permission":                MitreMapping("Privilege Escalation", "T1222",     "File and Directory Permissions Modification"),

    # Lateral Movement
    "ssrf":                      MitreMapping("Lateral Movement",     "T1599",     "Network Boundary Bridging"),
    "server-side request":       MitreMapping("Lateral Movement",     "T1599",     "Network Boundary Bridging"),

    # Exfiltration
    "ftp":                       MitreMapping("Exfiltration",         "T1048",     "Exfiltration Over Alternative Protocol"),
    "telnet":                    MitreMapping("Exfiltration",         "T1048",     "Exfiltration Over Alternative Protocol"),

    # Supply Chain
    "vulnerable dependency":     MitreMapping("Initial Access",       "T1195.001", "Compromise Software Dependencies"),
    "cve":                       MitreMapping("Initial Access",       "T1195.001", "Compromise Software Dependencies"),
    "outdated":                  MitreMapping("Initial Access",       "T1195.001", "Compromise Software Dependencies"),
    "dependency":                MitreMapping("Initial Access",       "T1195.001", "Compromise Software Dependencies"),
}


# ── Enrichment Function ───────────────────────────────────────────────────────

def enrich_finding(finding: Finding) -> Finding:
    """
    Attempt to enrich a Finding with MITRE ATT&CK data.
    Only updates if the finding doesn't already have a mapping.
    Returns the (possibly enriched) finding.
    """
    if finding.mitre_tactic and finding.mitre_technique:
        return finding  # Already mapped

    mapping = _find_mapping(finding)
    if mapping:
        finding.mitre_tactic     = mapping.tactic
        finding.mitre_technique  = mapping.full_technique
    return finding


def enrich_all(findings: list[Finding]) -> list[Finding]:
    """Enrich a list of findings. Returns enriched list."""
    return [enrich_finding(f) for f in findings]


def get_tactic_summary(findings: list[Finding]) -> dict[str, int]:
    """
    Return a count of findings per MITRE tactic.
    Useful for the report summary.
    """
    summary: dict[str, int] = {}
    for f in findings:
        tactic = f.mitre_tactic or "Unmapped"
        summary[tactic] = summary.get(tactic, 0) + 1
    return dict(sorted(summary.items(), key=lambda x: x[1], reverse=True))


# ── Private ───────────────────────────────────────────────────────────────────

def _find_mapping(finding: Finding) -> Optional[MitreMapping]:
    """
    Search the keyword map against the finding title and description.
    Returns the first match found.
    """
    search_text = f"{finding.title} {finding.description}".lower()

    for keyword, mapping in KEYWORD_MAP.items():
        if keyword in search_text:
            return mapping

    return None
