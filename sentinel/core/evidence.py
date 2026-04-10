"""
sentinel/core/evidence.py

Evidence Artifact System.

Every probe produces a documented request/response pair.
No finding without evidence. No claim without proof.

Evidence artifacts are:
  - Stored with every finding
  - Shown in console output
  - Included in reports
  - Sanitized (no real credentials shown)
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional
import requests as _requests


@dataclass
class RequestArtifact:
    method:    str
    url:       str
    headers:   dict = field(default_factory=dict)
    body:      Optional[str] = None


@dataclass 
class ResponseArtifact:
    status_code:    int
    status_text:    str
    content_type:   str
    size_bytes:     int
    auth_required:  bool          # True if 401/403
    auth_bypassed:  bool          # True if 200 without auth header sent
    response_type:  str           # JSON | HTML | TEXT | EMPTY
    sample:         Optional[str] = None  # Sanitized snippet (max 200 chars)
    record_count:   Optional[int] = None  # If JSON array
    sensitive_fields: list[str] = field(default_factory=list)


@dataclass
class EvidenceArtifact:
    """
    A complete request/response evidence pair.
    This is proof — not inference.
    """
    request:     RequestArtifact
    response:    ResponseArtifact
    finding:     str              # What this proves
    confirmed:   bool             # Is this a confirmed vulnerability?
    notes:       list[str] = field(default_factory=list)

    def format_console(self) -> str:
        """Format for terminal output."""
        auth_str = "YES — 401/403 returned" if self.response.auth_required else \
                   "NO — data returned without credentials" if self.response.auth_bypassed else \
                   "UNKNOWN"
        
        lines = [
            f"  ┌─ Evidence ─────────────────────────────────",
            f"  │ Request:  {self.request.method} {self.request.url}",
            f"  │ Status:   {self.response.status_code} {self.response.status_text}",
            f"  │ Type:     {self.response.response_type} ({self.response.size_bytes} bytes)",
            f"  │ Auth req: {auth_str}",
        ]
        if self.response.record_count is not None:
            lines.append(f"  │ Records:  {self.response.record_count} returned")
        if self.response.sensitive_fields:
            lines.append(f"  │ Sensitive fields: {', '.join(self.response.sensitive_fields)}")
        if self.response.sample:
            lines.append(f"  │ Sample:   {self.response.sample}")
        lines.append(f"  │ Confirmed: {'YES' if self.confirmed else 'NO'}")
        lines.append(f"  └────────────────────────────────────────────")
        return "\n".join(lines)

    def format_report(self) -> str:
        """Format for markdown report."""
        auth_str = "YES (401/403)" if self.response.auth_required else \
                   "NO — accessible without credentials" if self.response.auth_bypassed else \
                   "Unknown"
        
        lines = [
            f"**Evidence Artifact**",
            f"```",
            f"Request:       {self.request.method} {self.request.url}",
            f"Status:        {self.response.status_code} {self.response.status_text}",
            f"Response type: {self.response.response_type}",
            f"Size:          {self.response.size_bytes} bytes",
            f"Auth required: {auth_str}",
        ]
        if self.response.record_count is not None:
            lines.append(f"Records:       {self.response.record_count}")
        if self.response.sensitive_fields:
            lines.append(f"Sensitive:     {', '.join(self.response.sensitive_fields)}")
        if self.response.sample:
            lines.append(f"Sample:        {self.response.sample}")
        lines.append(f"Confirmed:     {'YES' if self.confirmed else 'NO — requires further verification'}")
        lines.append("```")
        return "\n".join(lines)


# ── Probe executor with evidence capture ─────────────────────────────────────

STATUS_TEXT = {
    200: "OK", 201: "Created", 204: "No Content",
    301: "Moved Permanently", 302: "Found",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed",
    429: "Too Many Requests", 500: "Internal Server Error",
    503: "Service Unavailable",
}

SENSITIVE_FIELDS = [
    "password", "passwd", "passwordhash", "totpsecret",
    "token", "accesstoken", "authtoken", "apikey",
    "secret", "privatekey", "credential",
    "email", "username",
    "creditcard", "cardnumber", "cvv",
    "ssn", "socialsecurity",
    "address", "phone",
]


def probe_with_evidence(url: str, method: str = "GET",
                        headers: Optional[dict] = None,
                        body: Optional[dict] = None,
                        auth_sent: bool = False,
                        timeout: int = 10) -> tuple[Optional[_requests.Response], EvidenceArtifact]:
    """
    Execute a probe and capture full evidence artifact.
    Returns (response, artifact) — artifact always populated even on failure.
    """
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    _requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    base_headers = {"User-Agent": "Sentinel-SecurityScanner/1.0"}
    if headers:
        base_headers.update(headers)

    req_artifact = RequestArtifact(
        method=method,
        url=url,
        headers={k: v for k, v in base_headers.items() if "authorization" not in k.lower()},
        body=json.dumps(body) if body else None,
    )

    try:
        if method == "GET":
            resp = _requests.get(url, headers=base_headers, timeout=timeout, verify=False)
        elif method == "POST":
            resp = _requests.post(url, json=body, headers=base_headers,
                                  timeout=timeout, verify=False)
        elif method == "OPTIONS":
            resp = _requests.options(url, headers=base_headers, timeout=timeout, verify=False)
        else:
            resp = _requests.head(url, headers=base_headers, timeout=timeout, verify=False)

        artifact = _build_artifact(req_artifact, resp, auth_sent)
        return resp, artifact

    except _requests.exceptions.ConnectionError:
        artifact = _failed_artifact(req_artifact, "Connection refused")
        return None, artifact
    except _requests.exceptions.Timeout:
        artifact = _failed_artifact(req_artifact, "Request timed out")
        return None, artifact
    except Exception as e:
        artifact = _failed_artifact(req_artifact, str(e)[:100])
        return None, artifact


def _build_artifact(req: RequestArtifact, resp: _requests.Response,
                    auth_sent: bool) -> EvidenceArtifact:
    """Build evidence artifact from actual HTTP response."""
    status  = resp.status_code
    ctype   = resp.headers.get("Content-Type", "")
    size    = len(resp.content)
    content = resp.text

    # Determine response type
    if "json" in ctype or (content.strip().startswith(("{", "["))):
        rtype = "JSON"
    elif "html" in ctype:
        rtype = "HTML"
    elif content.strip():
        rtype = "TEXT"
    else:
        rtype = "EMPTY"

    # Auth analysis
    auth_required = status in (401, 403)
    auth_bypassed = (status == 200 and not auth_sent and size > 100)

    # Count records if JSON array
    record_count = None
    if rtype == "JSON":
        try:
            data = json.loads(content)
            if isinstance(data, list):
                record_count = len(data)
            elif isinstance(data, dict):
                for key in ["data", "items", "results"]:
                    if key in data and isinstance(data[key], list):
                        record_count = len(data[key])
                        break
        except (json.JSONDecodeError, ValueError):
            pass

    # Detect sensitive fields
    sensitive = []
    content_lower = content.lower()
    for field in SENSITIVE_FIELDS:
        if field in content_lower:
            sensitive.append(field)

    # Build sanitized sample
    sample = _build_sample(content, rtype, status)

    # Determine if confirmed vulnerability
    confirmed = (
        status == 200 and
        not auth_sent and
        size > 200 and
        rtype == "JSON" and
        not _is_spa_shell(size, ctype)
    )

    resp_artifact = ResponseArtifact(
        status_code=status,
        status_text=STATUS_TEXT.get(status, str(status)),
        content_type=ctype[:60],
        size_bytes=size,
        auth_required=auth_required,
        auth_bypassed=auth_bypassed,
        response_type=rtype,
        sample=sample,
        record_count=record_count,
        sensitive_fields=sensitive[:5],
    )

    return EvidenceArtifact(
        request=req,
        response=resp_artifact,
        finding=_infer_finding(status, auth_bypassed, sensitive, record_count),
        confirmed=confirmed,
    )


def _build_sample(content: str, rtype: str, status: int) -> Optional[str]:
    """Build a sanitized sample snippet — max 200 chars."""
    if not content or status not in (200, 400, 500):
        return None

    if rtype == "JSON":
        try:
            data = json.loads(content)
            # Take first record or top-level keys
            if isinstance(data, list) and data:
                sample = json.dumps(data[0])[:200]
            elif isinstance(data, dict):
                sample = json.dumps({k: "..." for k in list(data.keys())[:5]})
            else:
                sample = content[:200]
            # Sanitize — replace actual values of sensitive fields
            sample = _sanitize_sample(sample)
            return sample[:200]
        except (json.JSONDecodeError, ValueError):
            return content[:100]

    if rtype == "HTML":
        if _is_spa_shell(len(content.encode()), "text/html"):
            return "[Angular/React SPA shell — not real data]"
        return content[:100].replace("\n", " ").strip()

    return content[:100]


def _sanitize_sample(sample: str) -> str:
    """Replace sensitive values with [REDACTED]."""
    patterns = [
        (r'"password"\s*:\s*"[^"]*"',     '"password": "[REDACTED]"'),
        (r'"passwordHash"\s*:\s*"[^"]*"', '"passwordHash": "[REDACTED]"'),
        (r'"token"\s*:\s*"[^"]*"',        '"token": "[REDACTED]"'),
        (r'"secret"\s*:\s*"[^"]*"',       '"secret": "[REDACTED]"'),
        (r'"apiKey"\s*:\s*"[^"]*"',       '"apiKey": "[REDACTED]"'),
    ]
    for pattern, replacement in patterns:
        sample = re.sub(pattern, replacement, sample, flags=re.IGNORECASE)
    return sample


def _is_spa_shell(size: int, content_type: str) -> bool:
    """Detect if response is a SPA fallback shell."""
    return (70000 < size < 82000 and "html" in content_type.lower())


def _infer_finding(status: int, auth_bypassed: bool,
                   sensitive: list, record_count: Optional[int]) -> str:
    """Infer what this evidence proves."""
    if auth_bypassed and sensitive:
        return f"Unauthenticated access returns sensitive fields: {', '.join(sensitive[:3])}"
    if auth_bypassed and record_count:
        return f"Unauthenticated access returns {record_count} records"
    if auth_bypassed:
        return "Endpoint accessible without authentication"
    if status == 401:
        return "Authentication enforced — endpoint protected"
    if status == 403:
        return "Authorization enforced — access denied"
    if status == 404:
        return "Endpoint does not exist"
    return f"HTTP {status} — requires manual review"


def _failed_artifact(req: RequestArtifact, error: str) -> EvidenceArtifact:
    return EvidenceArtifact(
        request=req,
        response=ResponseArtifact(
            status_code=0,
            status_text=f"Failed: {error}",
            content_type="",
            size_bytes=0,
            auth_required=False,
            auth_bypassed=False,
            response_type="EMPTY",
        ),
        finding="Probe failed — no evidence captured",
        confirmed=False,
        notes=[error],
    )


# For type hints
from typing import Optional
