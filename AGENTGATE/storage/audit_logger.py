"""Audit Logger and SQLite Persistence for AGENTGATE.

Guarantees:
- Every protected operation request and its authorization decision is persistently recorded.
- Blocked actions, allowed actions, and pending approval events are auditable.
- Failures in audit logging do not silently grant authorization.
"""

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from models.action_request import AuthorizationDecision, AuthorizationResponse, Operation, RiskLevel
from models.workflow import ExecutionStatus, WorkflowState
from storage.hash_chain_audit import compute_event_hash, GENESIS_HASH


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLogger:
    """Thread-safe SQLite-backed audit and persistence manager."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            base_dir = Path(__file__).resolve().parent.parent / "data"
            base_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = str(base_dir / "agentgate.db")
        else:
            self.db_path = db_path
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                # Audit table with Hash Chain support
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS audit_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT UNIQUE NOT NULL,
                        timestamp TEXT NOT NULL,
                        user_id TEXT NOT NULL,
                        operation TEXT NOT NULL,
                        resource_id TEXT NOT NULL,
                        recipient_id TEXT,
                        decision TEXT NOT NULL,
                        risk_level TEXT NOT NULL,
                        explanation TEXT NOT NULL,
                        status TEXT NOT NULL,
                        details_json TEXT,
                        prev_hash TEXT,
                        event_hash TEXT
                    )
                """)
                cursor.execute("PRAGMA table_info(audit_events)")
                cols = [row["name"] for row in cursor.fetchall()]
                if "prev_hash" not in cols:
                    cursor.execute("ALTER TABLE audit_events ADD COLUMN prev_hash TEXT")
                if "event_hash" not in cols:
                    cursor.execute("ALTER TABLE audit_events ADD COLUMN event_hash TEXT")
                # Workflows table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS workflows (
                        workflow_id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        status TEXT NOT NULL,
                        current_step_index INTEGER NOT NULL,
                        state_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                # Mock inbox table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS mock_inbox (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        message_id TEXT UNIQUE NOT NULL,
                        recipient_id TEXT NOT NULL,
                        report_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        content TEXT NOT NULL,
                        classification TEXT NOT NULL,
                        sender_user_id TEXT NOT NULL,
                        delivered_at TEXT NOT NULL
                    )
                """)
                # Derived reports table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS saved_reports (
                        report_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        file_path TEXT NOT NULL,
                        classification TEXT NOT NULL,
                        created_by TEXT NOT NULL,
                        sources_json TEXT NOT NULL,
                        provenance_json TEXT,
                        created_at TEXT NOT NULL
                    )
                """)
                conn.commit()

    def log_event(
        self,
        event_id: str,
        user_id: str,
        operation: Operation,
        resource_id: str,
        decision: AuthorizationDecision,
        risk_level: RiskLevel,
        explanation: str,
        status: ExecutionStatus,
        recipient_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Persist an audit log entry with SHA-256 hash chaining."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT event_hash FROM audit_events WHERE event_hash IS NOT NULL ORDER BY id DESC LIMIT 1")
                row = cursor.fetchone()
                prev_hash = row["event_hash"] if row and row["event_hash"] else GENESIS_HASH

                ts = utc_now_iso()
                op_str = operation.value if isinstance(operation, Operation) else str(operation)
                dec_str = decision.value if isinstance(decision, AuthorizationDecision) else str(decision)
                risk_str = risk_level.value if isinstance(risk_level, RiskLevel) else str(risk_level)
                stat_str = status.value if isinstance(status, ExecutionStatus) else str(status)

                event_hash = compute_event_hash(
                    prev_hash=prev_hash,
                    event_id=event_id,
                    timestamp=ts,
                    user_id=user_id,
                    operation=op_str,
                    resource_id=resource_id,
                    recipient_id=recipient_id,
                    decision=dec_str,
                    risk_level=risk_str,
                    status=stat_str,
                )

                cursor.execute(
                    """
                    INSERT INTO audit_events (
                        event_id, timestamp, user_id, operation, resource_id,
                        recipient_id, decision, risk_level, explanation, status, details_json,
                        prev_hash, event_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        ts,
                        user_id,
                        op_str,
                        resource_id,
                        recipient_id,
                        dec_str,
                        risk_str,
                        explanation,
                        stat_str,
                        json.dumps(details or {}),
                        prev_hash,
                        event_hash,
                    ),
                )
                conn.commit()

    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent audit events for verification and dashboard display."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
                )
                rows = cursor.fetchall()
                results = []
                for row in rows:
                    item = dict(row)
                    if item.get("details_json"):
                        try:
                            item["details"] = json.loads(item["details_json"])
                        except Exception:
                            item["details"] = {}
                    results.append(item)
                return results

    def save_workflow_state(self, state: WorkflowState) -> None:
        """Persist current workflow state."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                state_json = state.model_dump_json()
                cursor.execute(
                    """
                    INSERT INTO workflows (
                        workflow_id, user_id, status, current_step_index, state_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(workflow_id) DO UPDATE SET
                        status = excluded.status,
                        current_step_index = excluded.current_step_index,
                        state_json = excluded.state_json,
                        updated_at = excluded.updated_at
                    """,
                    (
                        state.workflow_id,
                        state.user_id,
                        state.status.value,
                        state.current_step_index,
                        state_json,
                        state.created_at.isoformat(),
                        utc_now_iso(),
                    ),
                )
                conn.commit()

    def load_workflow_state(self, workflow_id: str) -> Optional[WorkflowState]:
        """Load a persisted workflow state."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT state_json FROM workflows WHERE workflow_id = ?",
                    (workflow_id,),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return WorkflowState.model_validate_json(row["state_json"])

    def record_inbox_delivery(
        self,
        message_id: str,
        recipient_id: str,
        report_id: str,
        title: str,
        content: str,
        classification: str,
        sender_user_id: str,
    ) -> None:
        """Record an authorized delivery into the mock inbox table."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO mock_inbox (
                        message_id, recipient_id, report_id, title, content,
                        classification, sender_user_id, delivered_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        message_id,
                        recipient_id,
                        report_id,
                        title,
                        content,
                        classification,
                        sender_user_id,
                        utc_now_iso(),
                    ),
                )
                conn.commit()

    def get_inbox_messages(self, recipient_id: str) -> List[Dict[str, Any]]:
        """Get delivered messages for a recipient."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM mock_inbox WHERE recipient_id = ? ORDER BY id DESC",
                    (recipient_id,),
                )
                return [dict(row) for row in cursor.fetchall()]

    def record_saved_report(
        self,
        report_id: str,
        title: str,
        file_path: str,
        classification: str,
        created_by: str,
        sources: List[str],
        provenance_dict: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record report metadata in SQLite."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO saved_reports (
                        report_id, title, file_path, classification, created_by,
                        sources_json, provenance_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        report_id,
                        title,
                        file_path,
                        classification,
                        created_by,
                        json.dumps(sources),
                        json.dumps(provenance_dict or {}),
                        utc_now_iso(),
                    ),
                )
                conn.commit()

    def get_saved_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Look up a saved report."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM saved_reports WHERE report_id = ?", (report_id,))
                row = cursor.fetchone()
                return dict(row) if row else None


# Default singleton instance
default_audit_logger = AuditLogger()
