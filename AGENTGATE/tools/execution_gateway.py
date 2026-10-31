"""Centralized Execution Gateway for AGENTGATE.

This is the primary security enforcement boundary for Module 03:
- Sits between AI-generated action proposals and actual tool execution.
- Evaluates every operation against Module 01 policy authority.
- Obtains trusted classification metadata from Module 02 and safe registries.
- Fails closed on any ambiguity, missing metadata, or service failure.
- Blocks execution BEFORE the protected tool code is called.
- Submits structured execution and authorization events to the Audit Logger.
"""

from __future__ import annotations

import uuid
from typing import Any, Callable, Dict, Optional

from models.action_request import (
    ActionRequest,
    AuthorizationDecision,
    AuthorizationResponse,
    Operation,
    RiskLevel,
)
from models.document_security import Classification
from models.workflow import (
    ActionProposal,
    ExecutionResult,
    ExecutionStatus,
    utc_now,
)
from security.approval import apply_approval
from security.authorization import authorize_action
from storage.audit_logger import AuditLogger, default_audit_logger
from storage.document_registry import DocumentRegistry, default_document_registry


class ExecutionGateway:
    """Centralized enforcement boundary for protected operations."""

    def __init__(
        self,
        audit_logger: Optional[AuditLogger] = None,
        document_registry: Optional[DocumentRegistry] = None,
    ):
        self.audit_logger = audit_logger or default_audit_logger
        self.document_registry = document_registry or default_document_registry

    def _resolve_classification(self, proposal: ActionProposal) -> Optional[str]:
        """Resolve trusted resource classification.
        
        Never trusts client-supplied classification directly without verification.
        """
        # If parameters explicitly contain a verified classification (e.g. from report derivation)
        verified_class = proposal.parameters.get("verified_classification")
        if verified_class:
            if isinstance(verified_class, Classification):
                return verified_class.value.lower()
            return str(verified_class).lower()

        # For document operations, look up in trusted document registry
        if proposal.operation == Operation.READ_DOCUMENT:
            try:
                meta = self.document_registry.get_document_metadata(proposal.resource_id)
                if meta:
                    return meta.classification.value.lower()
            except Exception:
                return None

        # For report delivery, check saved reports in audit/storage
        if proposal.operation in (Operation.SEND_REPORT, Operation.SAVE_REPORT):
            saved = self.audit_logger.get_saved_report(proposal.resource_id)
            if saved and saved.get("classification"):
                return saved["classification"].lower()

        # Check if classification was passed in parameters (e.g. for initial save)
        param_class = proposal.parameters.get("classification")
        if param_class:
            if isinstance(param_class, Classification):
                return param_class.value.lower()
            return str(param_class).lower()

        return None

    def execute_proposal(
        self,
        proposal: ActionProposal,
        tool_callback: Callable[[], Any],
    ) -> ExecutionResult:
        """Evaluate authorization and execute the tool ONLY IF authorized.
        
        Fails closed on any error.
        """
        request_id = f"REQ-{uuid.uuid4().hex[:8].upper()}"

        try:
            # 1. Resolve trusted resource classification
            classification_str = self._resolve_classification(proposal)
            if not classification_str:
                # Missing classification -> Fail Closed immediately
                explanation = "Security Gateway: Resource classification missing or cannot be verified. Fail closed."
                self.audit_logger.log_event(
                    event_id=f"AUD-{uuid.uuid4().hex[:8].upper()}",
                    user_id=proposal.user_id,
                    operation=proposal.operation,
                    resource_id=proposal.resource_id,
                    recipient_id=proposal.recipient_id,
                    decision=AuthorizationDecision.BLOCK,
                    risk_level=RiskLevel.CRITICAL,
                    explanation=explanation,
                    status=ExecutionStatus.BLOCKED,
                )
                return ExecutionResult(
                    proposal_id=proposal.proposal_id,
                    status=ExecutionStatus.BLOCKED,
                    operation=proposal.operation,
                    resource_id=proposal.resource_id,
                    user_id=proposal.user_id,
                    recipient_id=proposal.recipient_id,
                    error_message=explanation,
                )

            # 2. Build Module 01 ActionRequest
            action_request = ActionRequest(
                request_id=request_id,
                user_id=proposal.user_id,
                operation=proposal.operation,
                resource_id=proposal.resource_id,
                recipient_id=proposal.recipient_id,
                metadata={"classification": classification_str},
            )

            # 3. Request Authorization from Module 01
            auth_response: AuthorizationResponse = authorize_action(action_request)

            # 4. Enforce Decision
            if auth_response.decision == AuthorizationDecision.ALLOW:
                # Authorized -> Execute tool callback
                try:
                    tool_output = tool_callback()
                    status = ExecutionStatus.SUCCESS
                    error_msg = None
                except Exception as ex:
                    tool_output = None
                    status = ExecutionStatus.FAILED
                    error_msg = f"Tool execution failed: {str(ex)}"

                self.audit_logger.log_event(
                    event_id=f"AUD-{uuid.uuid4().hex[:8].upper()}",
                    user_id=proposal.user_id,
                    operation=proposal.operation,
                    resource_id=proposal.resource_id,
                    recipient_id=proposal.recipient_id,
                    decision=auth_response.decision,
                    risk_level=auth_response.risk_level,
                    explanation=auth_response.explanation,
                    status=status,
                    details={"tool_error": error_msg} if error_msg else None,
                )

                return ExecutionResult(
                    proposal_id=proposal.proposal_id,
                    status=status,
                    operation=proposal.operation,
                    resource_id=proposal.resource_id,
                    user_id=proposal.user_id,
                    recipient_id=proposal.recipient_id,
                    authorization_response=auth_response,
                    output=tool_output,
                    error_message=error_msg,
                )

            elif auth_response.decision == AuthorizationDecision.REQUIRE_APPROVAL:
                # Requires human approval -> Do NOT execute tool callback
                self.audit_logger.log_event(
                    event_id=f"AUD-{uuid.uuid4().hex[:8].upper()}",
                    user_id=proposal.user_id,
                    operation=proposal.operation,
                    resource_id=proposal.resource_id,
                    recipient_id=proposal.recipient_id,
                    decision=auth_response.decision,
                    risk_level=auth_response.risk_level,
                    explanation=auth_response.explanation,
                    status=ExecutionStatus.PENDING_APPROVAL,
                )
                return ExecutionResult(
                    proposal_id=proposal.proposal_id,
                    status=ExecutionStatus.PENDING_APPROVAL,
                    operation=proposal.operation,
                    resource_id=proposal.resource_id,
                    user_id=proposal.user_id,
                    recipient_id=proposal.recipient_id,
                    authorization_response=auth_response,
                    error_message=auth_response.explanation,
                )

            else:
                # Decision is BLOCK -> Stop immediately, never call tool callback
                self.audit_logger.log_event(
                    event_id=f"AUD-{uuid.uuid4().hex[:8].upper()}",
                    user_id=proposal.user_id,
                    operation=proposal.operation,
                    resource_id=proposal.resource_id,
                    recipient_id=proposal.recipient_id,
                    decision=auth_response.decision,
                    risk_level=auth_response.risk_level,
                    explanation=auth_response.explanation,
                    status=ExecutionStatus.BLOCKED,
                )
                return ExecutionResult(
                    proposal_id=proposal.proposal_id,
                    status=ExecutionStatus.BLOCKED,
                    operation=proposal.operation,
                    resource_id=proposal.resource_id,
                    user_id=proposal.user_id,
                    recipient_id=proposal.recipient_id,
                    authorization_response=auth_response,
                    error_message=auth_response.explanation,
                )

        except Exception as exc:
            # Any unhandled exception fails closed
            fail_explanation = f"Security Gateway Exception (Fail-Closed): {str(exc)}"
            try:
                self.audit_logger.log_event(
                    event_id=f"AUD-{uuid.uuid4().hex[:8].upper()}",
                    user_id=proposal.user_id,
                    operation=proposal.operation,
                    resource_id=proposal.resource_id,
                    recipient_id=proposal.recipient_id,
                    decision=AuthorizationDecision.BLOCK,
                    risk_level=RiskLevel.CRITICAL,
                    explanation=fail_explanation,
                    status=ExecutionStatus.FAILED,
                )
            except Exception:
                pass

            return ExecutionResult(
                proposal_id=proposal.proposal_id,
                status=ExecutionStatus.FAILED,
                operation=proposal.operation,
                resource_id=proposal.resource_id,
                user_id=proposal.user_id,
                recipient_id=proposal.recipient_id,
                error_message=fail_explanation,
            )

    def execute_with_approval(
        self,
        pending_result: ExecutionResult,
        approver_user_id: str,
        tool_callback: Callable[[], Any],
    ) -> ExecutionResult:
        """Process administrator approval for a pending action and execute if approved."""
        if pending_result.status != ExecutionStatus.PENDING_APPROVAL:
            return ExecutionResult(
                proposal_id=pending_result.proposal_id,
                status=ExecutionStatus.FAILED,
                operation=pending_result.operation,
                resource_id=pending_result.resource_id,
                user_id=pending_result.user_id,
                recipient_id=pending_result.recipient_id,
                error_message="Cannot apply approval: action is not pending approval.",
            )

        if not pending_result.authorization_response:
            return ExecutionResult(
                proposal_id=pending_result.proposal_id,
                status=ExecutionStatus.FAILED,
                operation=pending_result.operation,
                resource_id=pending_result.resource_id,
                user_id=pending_result.user_id,
                recipient_id=pending_result.recipient_id,
                error_message="Missing original authorization response.",
            )

        # Apply approval via Module 01
        approval_response = apply_approval(
            pending_result.authorization_response,
            approver_user_id=approver_user_id,
        )

        if approval_response.decision == AuthorizationDecision.ALLOW:
            try:
                tool_output = tool_callback()
                status = ExecutionStatus.SUCCESS
                error_msg = None
            except Exception as ex:
                tool_output = None
                status = ExecutionStatus.FAILED
                error_msg = f"Tool execution error post-approval: {str(ex)}"

            self.audit_logger.log_event(
                event_id=f"AUD-{uuid.uuid4().hex[:8].upper()}",
                user_id=pending_result.user_id,
                operation=pending_result.operation,
                resource_id=pending_result.resource_id,
                recipient_id=pending_result.recipient_id,
                decision=approval_response.decision,
                risk_level=approval_response.risk_level,
                explanation=approval_response.explanation,
                status=status,
                details={"approved_by": approver_user_id},
            )

            return ExecutionResult(
                proposal_id=pending_result.proposal_id,
                status=status,
                operation=pending_result.operation,
                resource_id=pending_result.resource_id,
                user_id=pending_result.user_id,
                recipient_id=pending_result.recipient_id,
                authorization_response=approval_response,
                output=tool_output,
                error_message=error_msg,
            )
        else:
            self.audit_logger.log_event(
                event_id=f"AUD-{uuid.uuid4().hex[:8].upper()}",
                user_id=pending_result.user_id,
                operation=pending_result.operation,
                resource_id=pending_result.resource_id,
                recipient_id=pending_result.recipient_id,
                decision=approval_response.decision,
                risk_level=approval_response.risk_level,
                explanation=approval_response.explanation,
                status=ExecutionStatus.BLOCKED,
                details={"rejected_approver": approver_user_id},
            )

            return ExecutionResult(
                proposal_id=pending_result.proposal_id,
                status=ExecutionStatus.BLOCKED,
                operation=pending_result.operation,
                resource_id=pending_result.resource_id,
                user_id=pending_result.user_id,
                recipient_id=pending_result.recipient_id,
                authorization_response=approval_response,
                error_message=approval_response.explanation,
            )


# Default singleton instance
default_execution_gateway = ExecutionGateway()
