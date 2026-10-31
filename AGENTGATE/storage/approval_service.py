"""Approval Queue and Workflow Management Service for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)

Features:
- Tracks all operations held in REQUIRE_APPROVAL state.
- Enforces administrator clearance for approval execution.
- Integrates with security.approval and tools.mock_inbox for safe post-approval execution.
- Cryptographically logs approval/rejection decisions in audit trail.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from models.action_request import AuthorizationDecision, Operation, RiskLevel
from models.workflow import ActionProposal, ExecutionResult, ExecutionStatus
from security.approval import apply_approval
from security.policy_manager import get_user_role
from storage.audit_logger import default_audit_logger
from tools.mock_inbox import default_mock_inbox


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ApprovalService:
    """Manages pending human approval queues and authorization validation."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            base_dir = Path(__file__).resolve().parent.parent / "data"
            base_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = str(base_dir / "agentgate.db")
        else:
            self.db_path = db_path

        self._lock = threading.RLock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS pending_approvals (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        approval_id TEXT UNIQUE NOT NULL,
                        request_id TEXT NOT NULL,
                        user_id TEXT NOT NULL,
                        operation TEXT NOT NULL,
                        resource_id TEXT NOT NULL,
                        recipient_id TEXT,
                        risk_level TEXT NOT NULL,
                        explanation TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        resolved_by TEXT,
                        resolved_at TEXT,
                        resolution_notes TEXT,
                        serialized_result_json TEXT
                    )
                """)
                conn.commit()

    def queue_approval(
        self,
        execution_result: ExecutionResult,
        resolution_notes: str = "",
    ) -> str:
        """Queue a request that returned REQUIRE_APPROVAL for human review."""
        approval_id = f"APPR-{uuid.uuid4().hex[:8].upper()}"
        resp = execution_result.authorization_response

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO pending_approvals (
                        approval_id, request_id, user_id, operation, resource_id,
                        recipient_id, risk_level, explanation, status, created_at,
                        resolution_notes, serialized_result_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        approval_id,
                        resp.request_id,
                        execution_result.user_id,
                        execution_result.operation.value,
                        execution_result.resource_id,
                        execution_result.recipient_id,
                        resp.risk_level.value,
                        resp.explanation,
                        "PENDING",
                        utc_now_iso(),
                        resolution_notes,
                        execution_result.model_dump_json(),
                    ),
                )
                conn.commit()

        return approval_id

    def list_pending(self, status: str = "PENDING") -> List[Dict[str, Any]]:
        """List requests pending approval."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                if status == "ALL":
                    cursor.execute("SELECT * FROM pending_approvals ORDER BY id DESC")
                else:
                    cursor.execute("SELECT * FROM pending_approvals WHERE status = ? ORDER BY id DESC", (status,))
                return [dict(row) for row in cursor.fetchall()]

    def count_pending(self) -> int:
        """Count active pending approval requests."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT count(*) as count FROM pending_approvals WHERE status = 'PENDING'")
                return cursor.fetchone()["count"]

    def approve_request(
        self,
        approval_id: str,
        approver_user_id: str,
        approver_role: str,
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Approve a held request and execute the protected action."""
        if approver_role != "ADMINISTRATOR":
            return False, "Access Denied: Only users with ADMINISTRATOR clearance can approve high-risk actions.", None

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM pending_approvals WHERE approval_id = ?", (approval_id,))
                row = cursor.fetchone()
                if not row:
                    return False, f"Approval request '{approval_id}' not found.", None

                item = dict(row)
                if item["status"] != "PENDING":
                    return False, f"Request is already resolved ({item['status']}).", None

                # Deserialize original result
                raw_json = item["serialized_result_json"]
                pending_res = ExecutionResult.model_validate_json(raw_json)

                # Execute delivery with approval
                if pending_res.operation == Operation.SEND_REPORT:
                    final_result = default_mock_inbox.deliver_with_approval(
                        pending_result=pending_res,
                        approver_user_id=approver_user_id,
                    )
                else:
                    # Generic approval
                    appr_resp = apply_approval(
                        original_response=pending_res.authorization_response,
                        approver_user_id=approver_user_id,
                    )
                    final_result = ExecutionResult(
                        user_id=pending_res.user_id,
                        operation=pending_res.operation,
                        resource_id=pending_res.resource_id,
                        recipient_id=pending_res.recipient_id,
                        authorization_response=appr_resp,
                        status=ExecutionStatus.SUCCESS if appr_resp.decision == AuthorizationDecision.ALLOW else ExecutionStatus.BLOCKED,
                        output={"approved_by": approver_user_id},
                    )

                now_str = utc_now_iso()
                cursor.execute(
                    """
                    UPDATE pending_approvals
                    SET status = 'APPROVED', resolved_by = ?, resolved_at = ?
                    WHERE approval_id = ?
                    """,
                    (approver_user_id, now_str, approval_id),
                )
                conn.commit()

                return True, f"Request '{approval_id}' successfully APPROVED and executed!", final_result.model_dump()

    def reject_request(
        self,
        approval_id: str,
        approver_user_id: str,
        approver_role: str,
        reason: str = "Rejected by administrator policy review.",
    ) -> Tuple[bool, str]:
        """Reject a held request."""
        if approver_role != "ADMINISTRATOR":
            return False, "Access Denied: Only administrators can reject approval requests."

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM pending_approvals WHERE approval_id = ?", (approval_id,))
                row = cursor.fetchone()
                if not row:
                    return False, f"Approval request '{approval_id}' not found."

                item = dict(row)
                if item["status"] != "PENDING":
                    return False, f"Request is already resolved ({item['status']})."

                now_str = utc_now_iso()
                cursor.execute(
                    """
                    UPDATE pending_approvals
                    SET status = 'REJECTED', resolved_by = ?, resolved_at = ?, resolution_notes = ?
                    WHERE approval_id = ?
                    """,
                    (approver_user_id, now_str, reason, approval_id),
                )
                conn.commit()

                # Cryptographically log rejection
                default_audit_logger.log_event(
                    event_id=f"EVT-REJ-{uuid.uuid4().hex[:8].upper()}",
                    user_id=item["user_id"],
                    operation=item["operation"],
                    resource_id=item["resource_id"],
                    decision=AuthorizationDecision.BLOCK,
                    risk_level=item["risk_level"],
                    explanation=f"HUMAN APPROVAL REJECTED by {approver_user_id}: {reason}",
                    status=ExecutionStatus.BLOCKED,
                    recipient_id=item["recipient_id"],
                )

                return True, f"Request '{approval_id}' REJECTED."


# Default singleton instance
default_approval_service = ApprovalService()
