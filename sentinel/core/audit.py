"""
sentinel/core/audit.py

Append-only audit log.
Every allowed and blocked action is recorded here.
Nothing is ever deleted from the audit log during a session.

Storage: local JSONL file (always) + Azure Cosmos DB (if configured).
"""

import json
import os
from pathlib import Path
from datetime import datetime
from .models import AuditEntry

# Local log file location
LOG_DIR  = Path("logs")
LOG_FILE = LOG_DIR / "audit.jsonl"


def log_audit_entry(entry: AuditEntry) -> None:
    """
    Write an audit entry to local log file.
    Also writes to Cosmos DB if configured.
    Never raises — audit logging must not crash the scan.
    """
    try:
        _write_local(entry)
    except Exception as e:
        # If local logging fails, print to stderr but don't crash
        import sys
        print(f"[AUDIT ERROR] Failed to write local log: {e}", file=sys.stderr)

    try:
        if _cosmos_configured():
            _write_cosmos(entry)
    except Exception as e:
        import sys
        print(f"[AUDIT ERROR] Failed to write Cosmos log: {e}", file=sys.stderr)


def get_session_log(session_id: str) -> list[dict]:
    """
    Retrieve all audit entries for a specific session.
    """
    entries = []
    if not LOG_FILE.exists():
        return entries
    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if entry.get("session_id") == session_id:
                    entries.append(entry)
            except json.JSONDecodeError:
                continue
    return entries


def get_full_log() -> list[dict]:
    """Return entire audit log. For admin/debug use only."""
    entries = []
    if not LOG_FILE.exists():
        return entries
    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


# ── Private ───────────────────────────────────────────────────────────────────

def _write_local(entry: AuditEntry) -> None:
    LOG_DIR.mkdir(exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(entry.model_dump_json() + "\n")


def _cosmos_configured() -> bool:
    return bool(
        os.getenv("COSMOS_ENDPOINT")
        and os.getenv("COSMOS_KEY")
        and os.getenv("COSMOS_DB_NAME")
    )


def _write_cosmos(entry: AuditEntry) -> None:
    from azure.cosmos import CosmosClient

    client = CosmosClient(
        url=os.getenv("COSMOS_ENDPOINT"),
        credential=os.getenv("COSMOS_KEY"),
    )
    db        = client.get_database_client(os.getenv("COSMOS_DB_NAME", "sentinel"))
    container = db.get_container_client(os.getenv("COSMOS_CONTAINER", "audit_log"))

    doc = entry.model_dump()
    doc["id"] = entry.entry_id
    # Cosmos needs timestamps as strings
    doc["timestamp"] = entry.timestamp.isoformat()
    container.upsert_item(doc)
