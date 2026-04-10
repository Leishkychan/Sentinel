"""
sentinel/core/nvd_lookup.py

NVD (National Vulnerability Database) Live CVE Lookup.
Maps software/service versions to known CVEs with CVSS scores.

Uses the NVD REST API v2 (free, no auth required for basic use).
Rate limited to 5 requests/30s without API key.

Provides:
  - lookup_cves(product, version) → list of CVEs
  - lookup_service_cves(service_name, version) → CVEs for running services
  - get_cve_details(cve_id) → full CVE record
  - scan_dependencies(deps_dict) → bulk CVE lookup for dependency list
"""

import json
import time
import hashlib
from pathlib import Path
from typing import Optional
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# NVD API v2
NVD_API_BASE  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CVE_BASE  = "https://services.nvd.nist.gov/rest/json/cve/2.0"

# Local cache for CVE lookups (avoid hammering NVD)
CACHE_DIR = Path("data/nvd_cache")
CACHE_TTL_HOURS = 24

# Rate limiting — NVD allows 5 req/30s without API key
_last_request_time = 0.0
_REQUEST_INTERVAL  = 6.5  # seconds between requests (conservative)


def lookup_cves(product: str, version: str, max_results: int = 10) -> list[dict]:
    """
    Look up CVEs for a specific product + version.
    Returns list of CVE dicts with id, description, cvss_score, severity.

    Example:
        lookup_cves("flask", "2.0.0") → [{"id": "CVE-...", "cvss": 7.5, ...}]
    """
    cache_key = _cache_key(f"{product}:{version}")
    cached    = _load_cache(cache_key)
    if cached is not None:
        return cached

    _rate_limit()

    params = {
        "keywordSearch": f"{product} {version}",
        "resultsPerPage": max_results,
    }

    try:
        resp = requests.get(NVD_API_BASE, params=params, timeout=15, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            results = _parse_nvd_response(data)
            _save_cache(cache_key, results)
            return results
        elif resp.status_code == 429:
            print(f"[NVD] Rate limited — waiting 30s")
            time.sleep(30)
            return lookup_cves(product, version, max_results)
        else:
            print(f"[NVD] API returned {resp.status_code} for {product} {version}")
            return []
    except requests.RequestException as e:
        print(f"[NVD] Request failed: {e}")
        return []


def get_cve_details(cve_id: str) -> Optional[dict]:
    """Get full details for a specific CVE ID."""
    cache_key = _cache_key(cve_id)
    cached    = _load_cache(cache_key)
    if cached is not None:
        return cached[0] if cached else None

    _rate_limit()

    try:
        resp = requests.get(f"{NVD_CVE_BASE}/{cve_id}", timeout=15, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            results = _parse_nvd_response(data)
            _save_cache(cache_key, results)
            return results[0] if results else None
    except requests.RequestException as e:
        print(f"[NVD] CVE lookup failed for {cve_id}: {e}")
    return None


def scan_service_versions(services: dict[str, str]) -> list[dict]:
    """
    Bulk CVE lookup for running services.
    Input: {"nginx": "1.14.0", "openssl": "1.0.2", ...}
    Returns: list of findings with service, version, CVEs
    """
    all_findings = []

    for service, version in services.items():
        print(f"[NVD] Checking {service} {version}...")
        cves = lookup_cves(service, version)

        for cve in cves:
            if cve.get("cvss_score", 0) >= 4.0:  # Only MEDIUM+
                all_findings.append({
                    "service":     service,
                    "version":     version,
                    "cve_id":      cve["id"],
                    "description": cve["description"],
                    "cvss_score":  cve["cvss_score"],
                    "severity":    cve["severity"],
                    "published":   cve.get("published"),
                    "references":  cve.get("references", [])[:2],
                })

    return all_findings


def cvss_to_severity(score: float) -> str:
    """Convert CVSS score to severity string."""
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >= 0.1: return "LOW"
    return "INFO"


# ── Private ───────────────────────────────────────────────────────────────────

def _parse_nvd_response(data: dict) -> list[dict]:
    """Parse NVD API v2 response into simplified CVE list."""
    results = []
    vulnerabilities = data.get("vulnerabilities", [])

    for item in vulnerabilities:
        cve_obj = item.get("cve", {})
        cve_id  = cve_obj.get("id", "")

        # Get description (English preferred)
        descriptions = cve_obj.get("descriptions", [])
        description  = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )

        # Get CVSS score (prefer v3.1, fall back to v3.0, then v2)
        metrics    = cve_obj.get("metrics", {})
        cvss_score = 0.0
        cvss_vector = None

        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(version_key, [])
            if metric_list:
                cvss_data   = metric_list[0].get("cvssData", {})
                cvss_score  = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString")
                break

        # References
        refs = [r.get("url") for r in cve_obj.get("references", [])[:3]]

        results.append({
            "id":          cve_id,
            "description": description[:300],
            "cvss_score":  cvss_score,
            "severity":    cvss_to_severity(cvss_score),
            "cvss_vector": cvss_vector,
            "published":   cve_obj.get("published"),
            "modified":    cve_obj.get("lastModified"),
            "references":  [r for r in refs if r],
        })

    # Sort by CVSS score descending
    results.sort(key=lambda x: x["cvss_score"], reverse=True)
    return results


def _rate_limit():
    """Enforce NVD rate limit."""
    global _last_request_time
    elapsed  = time.time() - _last_request_time
    if elapsed < _REQUEST_INTERVAL:
        time.sleep(_REQUEST_INTERVAL - elapsed)
    _last_request_time = time.time()


def _cache_key(key: str) -> str:
    return hashlib.md5(key.encode()).hexdigest()


def _cache_path(key: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{key}.json"


def _load_cache(key: str) -> Optional[list]:
    path = _cache_path(key)
    if not path.exists():
        return None
    age_hours = (time.time() - path.stat().st_mtime) / 3600
    if age_hours > CACHE_TTL_HOURS:
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _save_cache(key: str, data: list):
    try:
        _cache_path(key).write_text(json.dumps(data), encoding="utf-8")
    except Exception:
        pass
