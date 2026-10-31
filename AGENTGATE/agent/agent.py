"""AI Agent Orchestrator for AGENTGATE Module 03.

Security Guarantees:
- The AI Agent receives user prompts, interprets requests, and plans action sequences.
- CRITICAL: The AI Agent DOES NOT possess authorization privileges.
- Every protected operation proposed by the Agent is routed through the Centralized Execution Gateway.
- Documents containing malicious prompt injections cannot trick the Agent into bypassing security policies.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from agent.action_proposer import ActionProposer
from agent.llm_integration import LLMIntegration, default_llm_integration
from agent.workflow_manager import WorkflowManager, default_workflow_manager
from models.action_request import Operation
from models.workflow import ActionProposal, ExecutionResult, ExecutionStatus, WorkflowState
from tools.document_reader import DocumentReader, default_document_reader
from tools.execution_gateway import ExecutionGateway, default_execution_gateway
from tools.mock_inbox import MockInbox, default_mock_inbox
from tools.report_saver import ReportSaver, default_report_saver


class AgentGateAI:
    """High-level AI Agent interface for AGENTGATE."""

    def __init__(
        self,
        gateway: Optional[ExecutionGateway] = None,
        reader: Optional[DocumentReader] = None,
        saver: Optional[ReportSaver] = None,
        inbox: Optional[MockInbox] = None,
        workflow_manager: Optional[WorkflowManager] = None,
        llm: Optional[LLMIntegration] = None,
    ):
        self.gateway = gateway or default_execution_gateway
        self.reader = reader or default_document_reader
        self.saver = saver or default_report_saver
        self.inbox = inbox or default_mock_inbox
        self.workflow_manager = workflow_manager or default_workflow_manager
        self.llm = llm or default_llm_integration

    def handle_request(
        self,
        user_id: str,
        prompt: str,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Process a user request and execute the proposed protected operations through the gateway."""
        # 1. Propose structured action from natural language (via Nemotron or fallback)
        proposal = self.llm.interpret_user_request(
            user_id=user_id,
            prompt=prompt,
            api_key=api_key,
            model=model,
        )
        if not proposal:
            return {
                "status": "UNRECOGNIZED_REQUEST",
                "message": f"Could not interpret structured action proposal from: '{prompt}'.",
                "result": None,
            }

        # 2. Dispatch to the appropriate protected tool via the gateway
        if proposal.operation == Operation.READ_DOCUMENT:
            result = self.reader.read_document(user_id=user_id, document_id=proposal.resource_id)

        elif proposal.operation == Operation.SAVE_REPORT:
            result = self.saver.save_report(
                user_id=user_id,
                report_id=proposal.resource_id,
                title=proposal.parameters.get("title", f"Report {proposal.resource_id}"),
                content=proposal.parameters.get("content", ""),
                source_doc_ids=proposal.parameters.get("source_doc_ids", []),
            )

        elif proposal.operation == Operation.SEND_REPORT:
            result = self.inbox.deliver_report(
                user_id=user_id,
                report_id=proposal.resource_id,
                recipient_id=proposal.recipient_id or "",
            )

        else:
            return {
                "status": "UNSUPPORTED_OPERATION",
                "message": f"Operation '{proposal.operation}' is not supported.",
                "result": None,
            }

        explanation = self.llm.explain_result(result.model_dump(mode="json"))

        return {
            "proposal": proposal.model_dump(mode="json"),
            "status": result.status.value,
            "decision": (
                result.authorization_response.decision.value
                if result.authorization_response
                else "BLOCKED"
            ),
            "explanation": explanation,
            "result": result.model_dump(mode="json"),
        }

    def run_pipeline(
        self,
        user_id: str,
        source_doc_id: str,
        report_id: str,
        recipient_id: str,
    ) -> WorkflowState:
        """Run standard multi-step pipeline: Read -> Summarize -> Save -> Deliver."""
        step1 = ActionProposer.propose_read(user_id=user_id, document_id=source_doc_id)
        step2 = ActionProposer.propose_save_report(
            user_id=user_id,
            report_id=report_id,
            title=f"Executive Summary of {source_doc_id}",
            content=f"Derived summary content for {source_doc_id}",
            source_doc_ids=[source_doc_id],
        )
        step3 = ActionProposer.propose_send_report(
            user_id=user_id,
            report_id=report_id,
            recipient_id=recipient_id,
        )

        workflow = self.workflow_manager.create_workflow(
            user_id=user_id,
            proposals=[step1, step2, step3],
        )

        return self.workflow_manager.execute_workflow(workflow.workflow_id)


# Default singleton instance
default_agent = AgentGateAI()
