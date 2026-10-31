"""Protected Mock Inbox Delivery Tool for AGENTGATE.

Security Guarantees:
- Report delivery CANNOT bypass the Centralized Execution Gateway.
- Verifies recipient authorization and report sensitivity via Module 01 policies.
- A BLOCKED or PENDING delivery never inserts a record into the recipient's inbox.
- Only an ALLOW decision creates a delivery record.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from models.action_request import Operation
from models.workflow import ActionProposal, ExecutionResult
from storage.audit_logger import AuditLogger, default_audit_logger
from tools.execution_gateway import ExecutionGateway, default_execution_gateway


class MockInbox:
    """Protected tool for delivering reports to a local simulated inbox."""

    def __init__(
        self,
        gateway: Optional[ExecutionGateway] = None,
        audit_logger: Optional[AuditLogger] = None,
        inbox_dir: Optional[str] = None,
    ):
        self.gateway = gateway or default_execution_gateway
        self.audit_logger = audit_logger or default_audit_logger

        if inbox_dir is None:
            self.inbox_dir = Path(__file__).resolve().parent.parent / "data" / "inbox"
        else:
            self.inbox_dir = Path(inbox_dir)

        self.inbox_dir.mkdir(parents=True, exist_ok=True)

    def deliver_report(
        self,
        user_id: str,
        report_id: str,
        recipient_id: str,
    ) -> ExecutionResult:
        """Attempt to deliver a report through the security gateway."""
        # 1. Lookup report to find classification and content
        saved_report = self.audit_logger.get_saved_report(report_id)
        if not saved_report:
            return ExecutionResult(
                proposal_id=f"PROP-SEND-{uuid.uuid4().hex[:8].upper()}",
                status=ExecutionStatus.FAILED,
                operation=Operation.SEND_REPORT,
                resource_id=report_id,
                user_id=user_id,
                recipient_id=recipient_id,
                error_message=f"Report '{report_id}' does not exist in saved reports.",
            )

        classification_str = saved_report["classification"].lower()

        # 2. Build proposal
        proposal = ActionProposal(
            proposal_id=f"PROP-SEND-{uuid.uuid4().hex[:8].upper()}",
            user_id=user_id,
            operation=Operation.SEND_REPORT,
            resource_id=report_id,
            recipient_id=recipient_id,
            parameters={
                "classification": classification_str,
                "title": saved_report.get("title", "Untitled Report"),
            },
        )

        # 3. Define protected delivery callback
        def _protected_delivery_callback() -> Dict[str, Any]:
            msg_id = f"MSG-{uuid.uuid4().hex[:8].upper()}"
            title = saved_report.get("title", "Untitled Report")

            # Read report content if file exists
            content = "Report content preview"
            file_path = saved_report.get("file_path")
            if file_path and Path(file_path).exists():
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        content = data.get("content", content)
                except Exception:
                    pass

            # Write to SQLite mock inbox table
            self.audit_logger.record_inbox_delivery(
                message_id=msg_id,
                recipient_id=recipient_id,
                report_id=report_id,
                title=title,
                content=content,
                classification=saved_report["classification"],
                sender_user_id=user_id,
            )

            # Also maintain a local recipient JSON inbox file for inspectability
            recipient_file = self.inbox_dir / f"{recipient_id}.json"
            inbox_messages = []
            if recipient_file.exists():
                try:
                    with open(recipient_file, "r", encoding="utf-8") as f:
                        inbox_messages = json.load(f)
                except Exception:
                    inbox_messages = []

            inbox_messages.append({
                "message_id": msg_id,
                "report_id": report_id,
                "title": title,
                "classification": saved_report["classification"],
                "sender": user_id,
            })

            with open(recipient_file, "w", encoding="utf-8") as f:
                json.dump(inbox_messages, f, indent=2)

            return {
                "message_id": msg_id,
                "recipient_id": recipient_id,
                "report_id": report_id,
                "status": "DELIVERED",
            }

        return self.gateway.execute_proposal(proposal, _protected_delivery_callback)

    def deliver_with_approval(
        self,
        pending_result: ExecutionResult,
        approver_user_id: str,
    ) -> ExecutionResult:
        """Execute a delivery that was previously held in PENDING_APPROVAL."""
        saved_report = self.audit_logger.get_saved_report(pending_result.resource_id)
        title = saved_report.get("title", "Untitled Report") if saved_report else "Report"
        content = "Approved Report Delivery"

        def _protected_delivery_callback() -> Dict[str, Any]:
            msg_id = f"MSG-{uuid.uuid4().hex[:8].upper()}"
            self.audit_logger.record_inbox_delivery(
                message_id=msg_id,
                recipient_id=pending_result.recipient_id or "UNKNOWN",
                report_id=pending_result.resource_id,
                title=title,
                content=content,
                classification=saved_report["classification"] if saved_report else "confidential",
                sender_user_id=pending_result.user_id,
            )
            return {
                "message_id": msg_id,
                "recipient_id": pending_result.recipient_id,
                "report_id": pending_result.resource_id,
                "status": "DELIVERED_POST_APPROVAL",
            }

        return self.gateway.execute_with_approval(
            pending_result=pending_result,
            approver_user_id=approver_user_id,
            tool_callback=_protected_delivery_callback,
        )

    def get_recipient_messages(self, recipient_id: str) -> List[Dict[str, Any]]:
        """Retrieve delivered messages for a recipient."""
        return self.audit_logger.get_inbox_messages(recipient_id)


# Default singleton instance
default_mock_inbox = MockInbox()
