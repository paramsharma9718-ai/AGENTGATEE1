"""Tamper-Evident SHA-256 Hash Chain Audit Logger for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)

Guarantees:
- Every security decision is bound to a cryptographic SHA-256 hash.
- Each event includes the hash of the preceding event, forming an immutable hash chain.
- An integrity verification engine detects any unauthorized insertion, deletion, or modification of historical audit records.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from models.action_request import AuthorizationDecision, Operation, RiskLevel
from models.workflow import ExecutionStatus

GENESIS_HASH = "0" * 64


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_event_hash(
    prev_hash: str,
    event_id: str,
    timestamp: str,
    user_id: str,
    operation: str,
    resource_id: str,
    recipient_id: Optional[str],
    decision: str,
    risk_level: str,
    status: str,
) -> str:
    """Compute SHA-256 digest over the canonical representation of an audit event."""
    canonical_payload = (
        f"{prev_hash}|{event_id}|{timestamp}|{user_id}|{operation}|"
        f"{resource_id}|{recipient_id or ''}|{decision}|{risk_level}|{status}"
    )
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


class HashChainAuditLogger:
    """Thread-safe, tamper-evident audit logger with SHA-256 hash chaining."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            base_dir = Path(__file__).resolve().parent.parent / "data"
            base_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = str(base_dir / "agentgate.db")
        else:
            self.db_path = db_path
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self._ensure_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        """Ensure audit_events table has prev_hash and event_hash columns."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
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

                # Check if prev_hash and event_hash columns exist (in case table was created by Module 03)
                cursor.execute("PRAGMA table_info(audit_events)")
                columns = [row["name"] for row in cursor.fetchall()]
                if "prev_hash" not in columns:
                    cursor.execute("ALTER TABLE audit_events ADD COLUMN prev_hash TEXT")
                if "event_hash" not in columns:
                    cursor.execute("ALTER TABLE audit_events ADD COLUMN event_hash TEXT")

                conn.commit()

            # Backfill existing records if any exist without hashes
            self._backfill_hashes_if_needed()

    def _backfill_hashes_if_needed(self) -> None:
        """Backfill cryptographic hash chain for legacy rows."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM audit_events ORDER BY id ASC")
                rows = cursor.fetchall()

                prev_hash = GENESIS_HASH
                needs_update = False
                updates = []

                for row in rows:
                    row_dict = dict(row)
                    current_prev = row_dict.get("prev_hash")
                    current_hash = row_dict.get("event_hash")

                    expected_hash = compute_event_hash(
                        prev_hash=prev_hash,
                        event_id=row_dict["event_id"],
                        timestamp=row_dict["timestamp"],
                        user_id=row_dict["user_id"],
                        operation=row_dict["operation"],
                        resource_id=row_dict["resource_id"],
                        recipient_id=row_dict.get("recipient_id"),
                        decision=row_dict["decision"],
                        risk_level=row_dict["risk_level"],
                        status=row_dict["status"],
                    )

                    if current_hash != expected_hash or current_prev != prev_hash:
                        needs_update = True
                        updates.append((prev_hash, expected_hash, row_dict["id"]))

                    prev_hash = expected_hash

                if needs_update:
                    for p_h, e_h, row_id in updates:
                        cursor.execute(
                            "UPDATE audit_events SET prev_hash = ?, event_hash = ? WHERE id = ?",
                            (p_h, e_h, row_id),
                        )
                    conn.commit()

    def get_latest_hash(self) -> str:
        """Return the event_hash of the most recent audit entry, or GENESIS_HASH."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_hash FROM audit_events WHERE event_hash IS NOT NULL ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            if row and row["event_hash"]:
                return row["event_hash"]
            return GENESIS_HASH

    def log_event(
        self,
        event_id: str,
        user_id: str,
        operation: Operation | str,
        resource_id: str,
        decision: AuthorizationDecision | str,
        risk_level: RiskLevel | str,
        explanation: str,
        status: ExecutionStatus | str,
        recipient_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record an audit event with SHA-256 hash chaining."""
        with self._lock:
            ts = timestamp or utc_now_iso()
            op_str = operation.value if isinstance(operation, Operation) else str(operation)
            dec_str = decision.value if isinstance(decision, AuthorizationDecision) else str(decision)
            risk_str = risk_level.value if isinstance(risk_level, RiskLevel) else str(risk_level)
            stat_str = status.value if isinstance(status, ExecutionStatus) else str(status)

            prev_hash = self.get_latest_hash()
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

            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO audit_events (
                        event_id, timestamp, user_id, operation, resource_id,
                        recipient_id, decision, risk_level, explanation, status,
                        details_json, prev_hash, event_hash
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

            return {
                "event_id": event_id,
                "timestamp": ts,
                "prev_hash": prev_hash,
                "event_hash": event_hash,
            }

    def verify_chain_integrity(self) -> Dict[str, Any]:
        """Verify the cryptographic integrity of the entire audit chain.

        Returns:
            Dict containing:
            - is_valid: bool
            - total_events: int
            - error_message: Optional[str]
            - tampered_event_id: Optional[str]
            - tampered_index: Optional[int]
            - head_hash: str
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM audit_events ORDER BY id ASC")
                rows = cursor.fetchall()

            if not rows:
                return {
                    "is_valid": True,
                    "total_events": 0,
                    "error_message": None,
                    "tampered_event_id": None,
                    "tampered_index": None,
                    "head_hash": GENESIS_HASH,
                }

            expected_prev_hash = GENESIS_HASH

            for index, row in enumerate(rows):
                item = dict(row)
                stored_prev = item.get("prev_hash") or ""
                stored_hash = item.get("event_hash") or ""

                # 1. Verify link to previous event
                if stored_prev != expected_prev_hash:
                    return {
                        "is_valid": False,
                        "total_events": len(rows),
                        "error_message": (
                            f"Hash chain broken at event #{index + 1} (ID: {item['event_id']}). "
                            f"Stored prev_hash does not match preceding event hash."
                        ),
                        "tampered_event_id": item["event_id"],
                        "tampered_index": index,
                        "head_hash": stored_hash,
                    }

                # 2. Recompute hash and verify
                computed_hash = compute_event_hash(
                    prev_hash=stored_prev,
                    event_id=item["event_id"],
                    timestamp=item["timestamp"],
                    user_id=item["user_id"],
                    operation=item["operation"],
                    resource_id=item["resource_id"],
                    recipient_id=item.get("recipient_id"),
                    decision=item["decision"],
                    risk_level=item["risk_level"],
                    status=item["status"],
                )

                if computed_hash != stored_hash:
                    return {
                        "is_valid": False,
                        "total_events": len(rows),
                        "error_message": (
                            f"Data tampering detected at event #{index + 1} (ID: {item['event_id']}). "
                            f"Record content has been modified!"
                        ),
                        "tampered_event_id": item["event_id"],
                        "tampered_index": index,
                        "head_hash": stored_hash,
                    }

                expected_prev_hash = stored_hash

            return {
                "is_valid": True,
                "total_events": len(rows),
                "error_message": None,
                "tampered_event_id": None,
                "tampered_index": None,
                "head_hash": expected_prev_hash,
            }

    def simulate_tampering_for_demo(self, event_id: str, field: str, new_value: str) -> bool:
        """Educational demonstration helper: Alter a field directly to prove tamper-detection."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(f"UPDATE audit_events SET {field} = ? WHERE event_id = ?", (new_value, event_id))
                conn.commit()
                return cursor.rowcount > 0

    def get_events(
        self,
        limit: int = 100,
        user_id: Optional[str] = None,
        decision: Optional[str] = None,
        operation: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve audit events with optional filtering."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = "SELECT * FROM audit_events WHERE 1=1"
                params: List[Any] = []

                if user_id:
                    query += " AND user_id = ?"
                    params.append(user_id)
                if decision:
                    query += " AND decision = ?"
                    params.append(decision)
                if operation:
                    query += " AND operation = ?"
                    params.append(operation)

                query += " ORDER BY id DESC LIMIT ?"
                params.append(limit)

                cursor.execute(query, params)
                rows = cursor.fetchall()

                results = []
                for row in rows:
                    item = dict(row)
                    if item.get("details_json"):
                        try:
                            item["details"] = json.loads(item["details_json"])
                        except Exception:
                            item["details"] = {}
                    else:
                        item["details"] = {}
                    results.append(item)
                return results


# Default singleton instance for Module 04
default_hash_chain_logger = HashChainAuditLogger()
