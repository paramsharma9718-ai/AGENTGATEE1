"""Workflow Manager for AGENTGATE Module 03.

Security Guarantees:
- Orchestrates multi-step agent workflows through the Execution Gateway.
- Persists workflow state in SQLite across execution sessions.
- CRITICAL: When a suspended workflow resumes, it NEVER reuses stale authorization decisions.
  It re-evaluates policy restrictions via the gateway before executing any resumed protected step.
- An unauthorized or blocked step halts workflow progression immediately.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from models.action_request import Operation
from models.workflow import (
    ActionProposal,
    ExecutionResult,
    ExecutionStatus,
    WorkflowState,
    WorkflowStatus,
    WorkflowStep,
    utc_now,
)
from storage.audit_logger import AuditLogger, default_audit_logger
from tools.document_reader import DocumentReader, default_document_reader
from tools.execution_gateway import ExecutionGateway, default_execution_gateway
from tools.mock_inbox import MockInbox, default_mock_inbox
from tools.report_saver import ReportSaver, default_report_saver


class WorkflowManager:
    """Manages creation, execution, suspension, and secure resumption of multi-step workflows."""

    def __init__(
        self,
        gateway: Optional[ExecutionGateway] = None,
        reader: Optional[DocumentReader] = None,
        saver: Optional[ReportSaver] = None,
        inbox: Optional[MockInbox] = None,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.gateway = gateway or default_execution_gateway
        self.reader = reader or default_document_reader
        self.saver = saver or default_report_saver
        self.inbox = inbox or default_mock_inbox
        self.audit_logger = audit_logger or default_audit_logger

    def create_workflow(
        self,
        user_id: str,
        proposals: List[ActionProposal],
        workflow_id: Optional[str] = None,
    ) -> WorkflowState:
        """Initialize a new workflow with a sequence of action proposals."""
        w_id = workflow_id or f"WF-{uuid.uuid4().hex[:8].upper()}"
        steps = [
            WorkflowStep(
                step_id=f"STEP-{idx + 1}",
                proposal=prop,
                status=ExecutionStatus.PENDING_APPROVAL,
            )
            for idx, prop in enumerate(proposals)
        ]

        state = WorkflowState(
            workflow_id=w_id,
            user_id=user_id,
            status=WorkflowStatus.CREATED,
            steps=steps,
            current_step_index=0,
            created_at=utc_now(),
            updated_at=utc_now(),
        )

        self.audit_logger.save_workflow_state(state)
        return state

    def _execute_step(self, step: WorkflowStep) -> ExecutionResult:
        """Route proposal to its protected tool execution via the gateway."""
        prop = step.proposal

        if prop.operation == Operation.READ_DOCUMENT:
            return self.reader.read_document(prop.user_id, prop.resource_id)

        elif prop.operation == Operation.SAVE_REPORT:
            title = prop.parameters.get("title", f"Report {prop.resource_id}")
            content = prop.parameters.get("content", "Generated Report Content")
            source_docs = prop.parameters.get("source_doc_ids", [])
            return self.saver.save_report(
                user_id=prop.user_id,
                report_id=prop.resource_id,
                title=title,
                content=content,
                source_doc_ids=source_docs,
            )

        elif prop.operation == Operation.SEND_REPORT:
            if not prop.recipient_id:
                return ExecutionResult(
                    proposal_id=prop.proposal_id,
                    status=ExecutionStatus.FAILED,
                    operation=prop.operation,
                    resource_id=prop.resource_id,
                    user_id=prop.user_id,
                    error_message="SEND_REPORT proposal requires a recipient_id.",
                )
            return self.inbox.deliver_report(
                user_id=prop.user_id,
                report_id=prop.resource_id,
                recipient_id=prop.recipient_id,
            )

        else:
            return ExecutionResult(
                proposal_id=prop.proposal_id,
                status=ExecutionStatus.FAILED,
                operation=prop.operation,
                resource_id=prop.resource_id,
                user_id=prop.user_id,
                error_message=f"Unsupported operation '{prop.operation}'.",
            )

    def execute_workflow(self, workflow_id: str) -> WorkflowState:
        """Execute workflow steps sequentially until completion, block, or suspension."""
        state = self.audit_logger.load_workflow_state(workflow_id)
        if not state:
            raise ValueError(f"Workflow '{workflow_id}' not found.")

        state.status = WorkflowStatus.RUNNING
        state.updated_at = utc_now()

        while state.current_step_index < len(state.steps):
            current_step = state.steps[state.current_step_index]

            # Execute step via gateway
            result = self._execute_step(current_step)
            current_step.result = result
            current_step.status = result.status

            if result.status == ExecutionStatus.SUCCESS:
                state.current_step_index += 1
                state.updated_at = utc_now()
                self.audit_logger.save_workflow_state(state)

            elif result.status == ExecutionStatus.PENDING_APPROVAL:
                # Requires human intervention -> suspend workflow
                state.status = WorkflowStatus.SUSPENDED
                state.updated_at = utc_now()
                self.audit_logger.save_workflow_state(state)
                return state

            elif result.status == ExecutionStatus.BLOCKED:
                # Blocked by security policy -> halt workflow immediately
                state.status = WorkflowStatus.BLOCKED
                state.updated_at = utc_now()
                self.audit_logger.save_workflow_state(state)
                return state

            else:
                # Tool or gateway failure -> fail workflow
                state.status = WorkflowStatus.FAILED
                state.updated_at = utc_now()
                self.audit_logger.save_workflow_state(state)
                return state

        state.status = WorkflowStatus.COMPLETED
        state.updated_at = utc_now()
        self.audit_logger.save_workflow_state(state)
        return state

    def suspend_workflow(self, workflow_id: str) -> WorkflowState:
        """Explicitly suspend an in-progress workflow."""
        state = self.audit_logger.load_workflow_state(workflow_id)
        if not state:
            raise ValueError(f"Workflow '{workflow_id}' not found.")

        state.status = WorkflowStatus.SUSPENDED
        state.updated_at = utc_now()
        self.audit_logger.save_workflow_state(state)
        return state

    def resume_workflow(self, workflow_id: str) -> WorkflowState:
        """Resume a suspended workflow.
        
        Security Enforcement:
        Re-validates authorization policies via the gateway for the current step.
        Does not assume previous authorization still holds.
        """
        state = self.audit_logger.load_workflow_state(workflow_id)
        if not state:
            raise ValueError(f"Workflow '{workflow_id}' not found.")

        if state.status not in (WorkflowStatus.SUSPENDED, WorkflowStatus.CREATED):
            return state

        return self.execute_workflow(workflow_id)

    def get_workflow_state(self, workflow_id: str) -> Optional[WorkflowState]:
        """Fetch current workflow state."""
        return self.audit_logger.load_workflow_state(workflow_id)


# Default singleton instance
default_workflow_manager = WorkflowManager()
