"""
sentinel/api/app.py

Flask backend API for Sentinel.
Exposes endpoints to:
- Create and authorize scan sessions
- Start scans (async — returns job_id immediately)
- Poll for results
- Retrieve audit logs
- Download reports

All scan endpoints require an authorized session token.
"""

import os
import uuid
import threading
import secrets
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

load_dotenv()

from sentinel.core import ScanMode, ScanSession
from sentinel.core.audit import get_session_log, get_full_log
from sentinel.agents import run_orchestrator, generate_report


# ── Secret key — fail hard if not set in production ──────────────────────────

_secret_key = os.getenv("FLASK_SECRET_KEY")
if not _secret_key:
    env = os.getenv("FLASK_ENV", "development")
    if env == "production":
        raise RuntimeError(
            "FLASK_SECRET_KEY must be set in production. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    # Development only — generate a random key per process start
    _secret_key = secrets.token_hex(32)
    print("[WARNING] FLASK_SECRET_KEY not set. Using ephemeral key (development only).")

app = Flask(__name__, template_folder="templates")
app.secret_key = _secret_key


# ── CORS — restrict to configured origins, never wildcard ────────────────────

_allowed_origins_raw = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5000")
_allowed_origins = [o.strip() for o in _allowed_origins_raw.split(",") if o.strip()]
CORS(app, resources={r"/api/*": {"origins": _allowed_origins}})


# ── Rate limiting ─────────────────────────────────────────────────────────────

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"],
    storage_uri="memory://",
)


# ── Session store with TTL ────────────────────────────────────────────────────

_SESSION_TTL_HOURS = int(os.getenv("SESSION_TTL_HOURS", "24"))
_MAX_RESULTS       = int(os.getenv("MAX_RESULTS_STORED", "100"))

_sessions: dict[str, ScanSession] = {}
_session_created_at: dict[str, datetime] = {}

# Results store: capped at _MAX_RESULTS entries (FIFO eviction)
_results: dict[str, dict] = {}
_results_order: list[str] = []  # insertion-ordered keys for eviction

# Scan job status store
_jobs: dict[str, dict] = {}  # job_id → {"status": ..., "session_id": ..., "error": ...}


def _store_result(session_id: str, data: dict) -> None:
    """Store result with FIFO eviction when cap is reached."""
    if session_id in _results:
        _results[session_id] = data
        return
    if len(_results) >= _MAX_RESULTS:
        oldest = _results_order.pop(0)
        _results.pop(oldest, None)
    _results[session_id] = data
    _results_order.append(session_id)


def _purge_expired_sessions() -> None:
    """Remove sessions older than TTL. Called on each scan start."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=_SESSION_TTL_HOURS)
    expired = [
        sid for sid, created in _session_created_at.items()
        if created < cutoff
    ]
    for sid in expired:
        _sessions.pop(sid, None)
        _session_created_at.pop(sid, None)


# ── UI ────────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "sentinel"})


# ── Sessions ──────────────────────────────────────────────────────────────────

@app.route("/api/sessions", methods=["POST"])
@limiter.limit("20 per hour")
def create_session():
    """
    Create a new scan session.
    Body: { "target": "localhost", "mode": "CODE", "approved_targets": [...] }
    Returns: { "session_id": "...", "requires_second_confirm": bool }
    """
    body = request.get_json(silent=True) or {}
    target = body.get("target", "").strip()
    mode_str = body.get("mode", "CODE").upper()
    extra_targets = body.get("approved_targets", [])

    if not target:
        return jsonify({"error": "target is required"}), 400

    try:
        mode = ScanMode(mode_str)
    except ValueError:
        return jsonify({"error": f"Invalid mode. Must be one of: {[m.value for m in ScanMode]}"}), 400

    session = ScanSession(
        target=target,
        mode=mode,
        approved=False,
        approved_targets=extra_targets,
    )
    _sessions[session.session_id] = session
    _session_created_at[session.session_id] = datetime.now(timezone.utc)

    return jsonify({
        "session_id":              session.session_id,
        "target":                  target,
        "mode":                    mode,
        "approved":                False,
        "requires_second_confirm": mode == ScanMode.ACTIVE,
        "message": (
            "Session created. Call /api/sessions/{id}/authorize to approve it. "
            + ("ACTIVE mode requires a second confirmation after authorization."
               if mode == ScanMode.ACTIVE else "")
        ),
    }), 201


@app.route("/api/sessions/<session_id>/authorize", methods=["POST"])
@limiter.limit("20 per hour")
def authorize_session(session_id: str):
    """
    First authorization — user confirms they own/have permission to scan the target.
    Body: { "confirmed": true }
    """
    session = _get_session_or_404(session_id)
    if session is None:
        return jsonify({"error": "Session not found"}), 404

    body = request.get_json(silent=True) or {}
    if not body.get("confirmed", False):
        return jsonify({"error": "confirmed must be true to authorize the session"}), 400

    session.approved = True
    return jsonify({
        "session_id": session_id,
        "approved": True,
        "message": (
            "Session authorized. "
            + ("Call /api/sessions/{id}/confirm-active to proceed with ACTIVE mode."
               if session.mode == ScanMode.ACTIVE
               else "Call /api/scans to start the scan.")
        ),
    })


@app.route("/api/sessions/<session_id>/confirm-active", methods=["POST"])
@limiter.limit("10 per hour")
def confirm_active(session_id: str):
    """
    Second confirmation required for ACTIVE mode only.
    Body: { "confirmed": true, "acknowledgement": "I confirm I have authorization to actively probe this target" }
    """
    session = _get_session_or_404(session_id)
    if session is None:
        return jsonify({"error": "Session not found"}), 404

    if session.mode != ScanMode.ACTIVE:
        return jsonify({"error": "Second confirmation only required for ACTIVE mode"}), 400

    body = request.get_json(silent=True) or {}
    ack = body.get("acknowledgement", "")
    required_phrase = "I confirm I have authorization to actively probe this target"

    if not body.get("confirmed") or required_phrase.lower() not in ack.lower():
        return jsonify({
            "error": "Must confirm=true and include the required acknowledgement phrase.",
            "required_phrase": required_phrase,
        }), 400

    session.active_confirmed = True
    return jsonify({
        "session_id":     session_id,
        "active_confirmed": True,
        "message": "ACTIVE mode confirmed. You may now start the scan.",
    })


# ── Scans (async) ─────────────────────────────────────────────────────────────

@app.route("/api/scans", methods=["POST"])
@limiter.limit("10 per hour")
def start_scan():
    """
    Start a scan for an authorized session.
    Returns immediately with a job_id.
    Poll /api/scans/<job_id>/status for completion.
    Body: { "session_id": "...", "source_path": "/path/to/code" }
    """
    _purge_expired_sessions()

    body = request.get_json(silent=True) or {}
    session_id  = body.get("session_id", "")
    source_path = body.get("source_path", None)

    session = _get_session_or_404(session_id)
    if session is None:
        return jsonify({"error": "Session not found"}), 404

    if not session.approved:
        return jsonify({"error": "Session must be authorized before scanning"}), 403

    if session.mode == ScanMode.ACTIVE and not session.active_confirmed:
        return jsonify({"error": "ACTIVE mode requires second confirmation"}), 403

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {"status": "running", "session_id": session_id, "error": None}

    def _run():
        try:
            result = run_orchestrator(session, source_path=source_path)
            report = generate_report(result)
            _store_result(session_id, {
                "result":    result.model_dump(),
                "json_path": report["json_path"],
                "md_path":   report["md_path"],
            })
            _jobs[job_id]["status"]  = "complete"
            _jobs[job_id]["summary"] = {
                "session_id":     session_id,
                "total_findings": result.total,
                "by_severity":    result.by_severity,
                "summary":        result.summary,
                "agents_run":     [a.value for a in result.agents_run],
            }
        except Exception as e:
            _jobs[job_id]["status"] = "failed"
            _jobs[job_id]["error"]  = str(e)

    threading.Thread(target=_run, daemon=True).start()

    return jsonify({
        "job_id":    job_id,
        "session_id": session_id,
        "status":    "running",
        "poll_url":  f"/api/scans/{job_id}/status",
    }), 202


@app.route("/api/scans/<job_id>/status", methods=["GET"])
def scan_status(job_id: str):
    """Poll scan job status. Returns summary when complete."""
    job = _jobs.get(job_id)
    if job is None:
        return jsonify({"error": "Job not found"}), 404

    response = {"job_id": job_id, "status": job["status"]}

    if job["status"] == "complete":
        response["result"] = job.get("summary", {})
    elif job["status"] == "failed":
        response["error"] = job.get("error", "Unknown error")

    return jsonify(response)


@app.route("/api/scans/<session_id>/report", methods=["GET"])
def get_report(session_id: str):
    """Get the full scan report for a completed session."""
    if session_id not in _results:
        return jsonify({"error": "No results found for this session"}), 404
    return jsonify(_results[session_id]["result"])


# ── Audit ─────────────────────────────────────────────────────────────────────

@app.route("/api/audit/<session_id>", methods=["GET"])
def get_audit(session_id: str):
    """Get the full audit log for a session."""
    entries = get_session_log(session_id)
    return jsonify({"session_id": session_id, "entries": entries, "count": len(entries)})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_session_or_404(session_id: str) -> ScanSession | None:
    return _sessions.get(session_id)


if __name__ == "__main__":
    port  = int(os.getenv("FLASK_PORT", 5000))
    debug = os.getenv("FLASK_ENV", "development") == "development"
    print(f"\n🛡️  Sentinel starting on http://localhost:{port}")
    print(f"   CORS allowed origins: {_allowed_origins}")
    print(f"   Session TTL: {_SESSION_TTL_HOURS}h | Max results: {_MAX_RESULTS}")
    app.run(host="0.0.0.0", port=port, debug=debug)
