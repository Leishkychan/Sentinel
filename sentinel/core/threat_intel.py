"""
sentinel/core/threat_intel.py

Live MITRE ATT&CK + D3FEND Intelligence.

Pulls the full ATT&CK enterprise matrix from MITRE's GitHub.
Caches locally so we don't hit the network on every scan.
Cache refreshes every 7 days automatically.

Provides:
  - get_technique(technique_id) → full technique data
  - get_tactic_techniques(tactic) → all techniques for a tactic
  - get_mitigations(technique_id) → what defenses counter this technique
  - get_apt_groups(technique_id) → which APT groups use this technique
  - enrich_finding_with_intel(finding) → full enrichment on a Finding
  - get_dfend_countermeasures(technique_id) → D3FEND defensive countermeasures
"""

import json
import os
import time
from pathlib import Path
from typing import Optional
import requests
# TLS warnings suppressed per-request in safe_request/probe_with_evidence

# Cache location
CACHE_DIR  = Path("data/threat_intel")
ATTACK_CACHE = CACHE_DIR / "enterprise-attack.json"
CACHE_MAX_AGE_DAYS = 7

# MITRE ATT&CK Enterprise JSON
ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# D3FEND API base
DFEND_API = "https://d3fend.mitre.org/api/offensive-technique/attack"

# In-memory index after load
_attack_data:      dict = {}
_techniques_index: dict = {}   # technique_id → object
_tactics_index:    dict = {}   # tactic_name  → [technique_ids]
_groups_index:     dict = {}   # technique_id → [group_names]
_mitigations_index:dict = {}   # technique_id → [mitigation descriptions]
_loaded:           bool = False


# ── Public API ────────────────────────────────────────────────────────────────

def load_attack_data(force_refresh: bool = False) -> bool:
    """
    Load ATT&CK data into memory.
    Downloads if not cached or cache is stale.
    Returns True if loaded successfully.
    """
    global _loaded
    if _loaded and not force_refresh:
        return True

    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if _cache_is_fresh() and not force_refresh:
        print("[INTEL] Loading ATT&CK from cache...")
        return _load_from_cache()
    else:
        print("[INTEL] Downloading MITRE ATT&CK (this happens once every 7 days)...")
        return _download_and_cache()


def get_technique(technique_id: str) -> Optional[dict]:
    """Get full technique data by ID (e.g. 'T1190' or 'T1190.001')"""
    _ensure_loaded()
    return _techniques_index.get(technique_id.upper())


def get_techniques_for_tactic(tactic: str) -> list[dict]:
    """Get all techniques for a given tactic name."""
    _ensure_loaded()
    ids = _tactics_index.get(tactic.lower(), [])
    return [_techniques_index[i] for i in ids if i in _techniques_index]


def get_apt_groups_for_technique(technique_id: str) -> list[str]:
    """Get list of APT group names known to use this technique."""
    _ensure_loaded()
    return _groups_index.get(technique_id.upper(), [])


def get_mitigations_for_technique(technique_id: str) -> list[str]:
    """Get defensive mitigations for a technique."""
    _ensure_loaded()
    return _mitigations_index.get(technique_id.upper(), [])


def get_dfend_countermeasures(technique_id: str) -> list[str]:
    """
    Query D3FEND API for countermeasures against an ATT&CK technique.
    Returns list of defensive technique names.
    Falls back to empty list if API unavailable.
    """
    try:
        url = f"{DFEND_API}/{technique_id}.json"
        resp = requests.get(url, timeout=5)
        if resp.status_code != 200:
            return []
        data = resp.json()
        countermeasures = []
        for item in data.get("@graph", []):
            label = item.get("rdfs:label", "")
            if label:
                countermeasures.append(label)
        return countermeasures[:5]  # Top 5
    except Exception:
        return []


def enrich_finding_intel(finding_title: str, finding_desc: str,
                          mitre_tactic: str, mitre_technique_id: str) -> dict:
    """
    Full intelligence enrichment for a finding.
    Returns dict with:
      - technique_name
      - technique_description
      - apt_groups (who uses this in the wild)
      - mitigations (defensive controls)
      - dfend_countermeasures (D3FEND specific controls)
      - real_world_incidents (how this has been exploited)
    """
    _ensure_loaded()
    result = {
        "technique_name":        None,
        "technique_description": None,
        "apt_groups":            [],
        "mitigations":           [],
        "dfend_countermeasures": [],
        "severity_context":      None,
    }

    if not mitre_technique_id:
        return result

    # Extract technique ID from "T1190 — Exploit Public-Facing Application"
    tid = _extract_technique_id(mitre_technique_id)
    if not tid:
        return result

    technique = get_technique(tid)
    if technique:
        result["technique_name"]        = technique.get("name")
        result["technique_description"] = technique.get("description", "")[:300]

    result["apt_groups"]            = get_apt_groups_for_technique(tid)
    result["mitigations"]           = get_mitigations_for_technique(tid)
    result["dfend_countermeasures"] = get_dfend_countermeasures(tid)

    # Add severity context based on APT usage
    if result["apt_groups"]:
        result["severity_context"] = (
            f"This technique is actively used by {len(result['apt_groups'])} "
            f"known threat groups including: {', '.join(result['apt_groups'][:3])}."
        )

    return result


def get_stats() -> dict:
    """Return stats about loaded data."""
    _ensure_loaded()
    return {
        "techniques": len(_techniques_index),
        "tactics":    len(_tactics_index),
        "loaded":     _loaded,
        "cache_path": str(ATTACK_CACHE),
    }


# ── Private ───────────────────────────────────────────────────────────────────

def _ensure_loaded():
    if not _loaded:
        load_attack_data()


def _cache_is_fresh() -> bool:
    if not ATTACK_CACHE.exists():
        return False
    age_days = (time.time() - ATTACK_CACHE.stat().st_mtime) / 86400
    return age_days < CACHE_MAX_AGE_DAYS


def _download_and_cache() -> bool:
    try:
        resp = requests.get(ATTACK_URL, timeout=60)
        resp.raise_for_status()
        ATTACK_CACHE.write_text(resp.text, encoding="utf-8")
        print(f"[INTEL] ATT&CK downloaded ({len(resp.content) // 1024}KB)")
        return _load_from_cache()
    except Exception as e:
        print(f"[INTEL] Download failed: {e}. Using static MITRE mappings.")
        return False


def _load_from_cache() -> bool:
    global _attack_data, _loaded
    try:
        _attack_data = json.loads(ATTACK_CACHE.read_text(encoding="utf-8"))
        _build_indexes()
        _loaded = True
        print(f"[INTEL] Loaded {len(_techniques_index)} techniques, {len(_tactics_index)} tactics")
        return True
    except Exception as e:
        print(f"[INTEL] Cache load failed: {e}")
        return False


def _build_indexes():
    """Build fast-lookup indexes from raw ATT&CK STIX data."""
    global _techniques_index, _tactics_index, _groups_index, _mitigations_index

    objects = _attack_data.get("objects", [])

    # Index all objects by ID for relationship lookups
    obj_by_id = {o.get("id"): o for o in objects if o.get("id")}

    # Index techniques
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        ext = obj.get("external_references", [])
        tid = next((r.get("external_id") for r in ext
                    if r.get("source_name") == "mitre-attack"), None)
        if not tid:
            continue

        _techniques_index[tid] = {
            "id":          tid,
            "name":        obj.get("name", ""),
            "description": obj.get("description", ""),
            "stix_id":     obj.get("id"),
            "url":         next((r.get("url") for r in ext
                                  if r.get("source_name") == "mitre-attack"), None),
        }

        # Index by tactic
        for phase in obj.get("kill_chain_phases", []):
            tactic = phase.get("phase_name", "").lower()
            if tactic not in _tactics_index:
                _tactics_index[tactic] = []
            _tactics_index[tactic].append(tid)

    # Index relationships (groups using techniques, mitigations)
    for obj in objects:
        if obj.get("type") != "relationship":
            continue

        rel_type   = obj.get("relationship_type")
        source_ref = obj.get("source_ref", "")
        target_ref = obj.get("target_ref", "")

        # Group → uses → technique
        if rel_type == "uses":
            source_obj = obj_by_id.get(source_ref, {})
            target_obj = obj_by_id.get(target_ref, {})

            if source_obj.get("type") == "intrusion-set":
                # Find technique ID
                tid = _stix_to_tid(target_obj)
                if tid:
                    group_name = source_obj.get("name", "Unknown")
                    if tid not in _groups_index:
                        _groups_index[tid] = []
                    if group_name not in _groups_index[tid]:
                        _groups_index[tid].append(group_name)

        # Mitigation → mitigates → technique
        if rel_type == "mitigates":
            source_obj = obj_by_id.get(source_ref, {})
            target_obj = obj_by_id.get(target_ref, {})

            if source_obj.get("type") == "course-of-action":
                tid = _stix_to_tid(target_obj)
                if tid:
                    mit_name = source_obj.get("name", "")
                    mit_desc = source_obj.get("description", "")[:200]
                    if tid not in _mitigations_index:
                        _mitigations_index[tid] = []
                    if mit_name:
                        _mitigations_index[tid].append(f"{mit_name}: {mit_desc}")


def _stix_to_tid(obj: dict) -> Optional[str]:
    """Extract ATT&CK technique ID from a STIX object."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _extract_technique_id(technique_str: str) -> Optional[str]:
    """Extract T-number from strings like 'T1190 — Exploit Public-Facing Application'"""
    import re
    match = re.search(r'T\d{4}(?:\.\d{3})?', technique_str)
    return match.group(0) if match else None
