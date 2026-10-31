"""FastAPI REST Service for AGENTGATE.

Headless REST API exposing:
- AI Agent Prompt & Intent Proposal API
- Centralized Execution Gateway Enforcement
- DLP Inspection & Sanitization
- Document Registry & Upload
- Human-in-the-Loop Approval Center
- Cryptographic Audit Log & SHA-256 Chain Verifier
- Protected Tool Registry
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Starlette / FastAPI compatibility shim
import starlette.routing
_orig_router_init = starlette.routing.Router.__init__
starlette.routing.Router.__init__ = lambda self, *a, **kw: _orig_router_init(
    self, *a, **{k: v for k, v in kw.items() if k not in ("on_startup", "on_shutdown")}
)

from fastapi import FastAPI, HTTPException, Query, status
FastAPI.max_body_size = None
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from agent.action_proposer import ActionProposer
from agent.agent import default_agent
from agent.llm_integration import default_llm_integration
from auth.user_manager import default_user_manager
from models.action_request import Operation
from models.document_security import Classification
from models.workflow import ActionProposal, ExecutionResult
from security.dlp_engine import inspect_content, redact_text
from security.policy_manager import get_user_role, is_recipient_authorized
from storage.approval_service import default_approval_service
from storage.document_service import default_document_service
from storage.hash_chain_audit import default_hash_chain_logger
from tools.document_reader import default_document_reader
from tools.execution_gateway import default_execution_gateway
from tools.mock_inbox import default_mock_inbox
from tools.registry import default_tool_registry
from tools.report_saver import default_report_saver

app = FastAPI(
    title="AGENTGATE REST API",
    description="Intelligent Security Gateway & Information-Flow Control for AI Agents",
    version="1.0.0",
)

# Enable CORS for external dashboards / microservices
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request & Response Schemas
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str


class AgentPromptRequest(BaseModel):
    user_id: str
    prompt: str
    api_key: Optional[str] = None
    model: Optional[str] = None


class ProposeActionRequest(BaseModel):
    user_id: str
    operation: str
    resource_id: str
    recipient_id: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None


class ExecuteActionRequest(BaseModel):
    user_id: str
    operation: str
    resource_id: str
    recipient_id: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None


class InspectContentRequest(BaseModel):
    content: str
    auto_redact: bool = False


class ResolveApprovalRequest(BaseModel):
    reviewer_id: str
    approved: bool
    notes: Optional[str] = ""


# ---------------------------------------------------------------------------
# Health & Status
# ---------------------------------------------------------------------------
@app.get("/", tags=["System"])
def root_info() -> Dict[str, Any]:
    return {
        "service": "AGENTGATE Intelligent Security Gateway",
        "status": "ONLINE",
        "enforcement_mode": "FAIL_CLOSED",
        "docs_url": "/docs",
    }


@app.get("/health", tags=["System"])
def health_check() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "gateway": "active",
        "audit_chain": "operational",
    }


# ---------------------------------------------------------------------------
# Authentication & Identity
# ---------------------------------------------------------------------------
@app.post("/api/v1/auth/login", tags=["Auth"])
def login(req: LoginRequest) -> Dict[str, Any]:
    user = default_user_manager.authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )
    return {
        "authenticated": True,
        "user": user,
    }


@app.get("/api/v1/users/{user_id}/role", tags=["Auth"])
def get_role(user_id: str) -> Dict[str, Any]:
    role = get_user_role(user_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found in trusted registry.",
        )
    return {
        "user_id": user_id,
        "role": role,
    }


# ---------------------------------------------------------------------------
# AI Agent & Proposals
# ---------------------------------------------------------------------------
@app.post("/api/v1/agent/prompt", tags=["AI Agent"])
def handle_agent_prompt(req: AgentPromptRequest) -> Dict[str, Any]:
    """Submit a natural language prompt to the AI Agent.

    The AI proposes an action and the Execution Gateway authorizes or blocks it.
    """
    res = default_agent.handle_request(
        user_id=req.user_id,
        prompt=req.prompt,
        api_key=req.api_key,
        model=req.model,
    )
    return res


@app.post("/api/v1/actions/propose", tags=["Actions"])
def propose_action(req: ProposeActionRequest) -> Dict[str, Any]:
    """Create a structured action proposal without self-authorization."""
    try:
        op = Operation(req.operation)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid operation '{req.operation}'.",
        )

    proposal = ActionProposal(
        proposal_id=f"PROP-API-{os.urandom(4).hex().upper()}",
        user_id=req.user_id,
        operation=op,
        resource_id=req.resource_id,
        recipient_id=req.recipient_id,
        parameters=req.parameters or {},
    )
    return proposal.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Centralized Execution Gateway (Zero-Bypass)
# ---------------------------------------------------------------------------
@app.post("/api/v1/actions/execute", tags=["Execution Gateway"])
def execute_action(req: ExecuteActionRequest) -> Dict[str, Any]:
    """Execute an action proposal directly through the security gateway."""
    try:
        op = Operation(req.operation)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid operation '{req.operation}'.",
        )

    # Route to appropriate protected tool
    if op == Operation.READ_DOCUMENT:
        res: ExecutionResult = default_document_reader.read_document(
            user_id=req.user_id,
            document_id=req.resource_id,
        )
        return res.model_dump(mode="json")

    elif op == Operation.SAVE_REPORT:
        params = req.parameters or {}
        res = default_report_saver.save_report(
            user_id=req.user_id,
            report_id=req.resource_id,
            title=params.get("title", req.resource_id),
            content=params.get("content", ""),
            source_doc_ids=params.get("source_doc_ids", []),
            auto_redact=params.get("auto_redact", False),
        )
        return res.model_dump(mode="json")

    elif op == Operation.SEND_REPORT:
        if not req.recipient_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Recipient ID required for SEND_REPORT.",
            )
        res = default_mock_inbox.deliver_report(
            user_id=req.user_id,
            report_id=req.resource_id,
            recipient_id=req.recipient_id,
        )
        return res.model_dump(mode="json")

    else:
        # Check custom tool registry
        tool_meta = default_tool_registry.get_tool(req.resource_id)
        if not tool_meta:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Operation '{op.value}' on resource '{req.resource_id}' is not recognized.",
            )

        # Call wrapped registered tool
        res = tool_meta.func(user_id=req.user_id, **(req.parameters or {}))
        return res.model_dump(mode="json") if hasattr(res, "model_dump") else {"output": res}


# ---------------------------------------------------------------------------
# DLP Inspection & Redaction
# ---------------------------------------------------------------------------
@app.post("/api/v1/dlp/inspect", tags=["DLP"])
def inspect_dlp(req: InspectContentRequest) -> Dict[str, Any]:
    """Run deterministic Data Loss Prevention (DLP) scan on text content."""
    res = inspect_content(req.content)
    redacted = redact_text(req.content, res) if (req.auto_redact and res.findings) else None

    findings_summary = [
        {
            "rule_id": f.rule_id,
            "category": f.category.value,
            "severity": f.severity.value,
            "line": f.line,
            "preview": f.redacted_preview,
        }
        for f in res.findings
    ]

    return {
        "status": res.status.value,
        "sensitive_content_detected": res.sensitive_content_detected,
        "findings_count": len(res.findings),
        "findings": findings_summary,
        "redacted_content": redacted,
    }


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------
@app.get("/api/v1/documents", tags=["Documents"])
def list_documents() -> List[Dict[str, Any]]:
    return default_document_service.list_documents()


# ---------------------------------------------------------------------------
# Human-in-the-Loop Approvals
# ---------------------------------------------------------------------------
@app.get("/api/v1/approvals", tags=["Approvals"])
def list_pending_approvals() -> List[Dict[str, Any]]:
    return default_approval_service.get_pending_approvals()


@app.post("/api/v1/approvals/{ticket_id}/resolve", tags=["Approvals"])
def resolve_approval(ticket_id: str, req: ResolveApprovalRequest) -> Dict[str, Any]:
    reviewer_role = get_user_role(req.reviewer_id)
    if reviewer_role != "ADMINISTRATOR":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only ADMINISTRATOR role can resolve approval requests.",
        )

    if req.approved:
        success, msg = default_approval_service.approve_request(
            ticket_id=ticket_id,
            reviewer_user_id=req.reviewer_id,
            notes=req.notes or "",
        )
    else:
        success, msg = default_approval_service.reject_request(
            ticket_id=ticket_id,
            reviewer_user_id=req.reviewer_id,
            reason=req.notes or "",
        )

    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    return {"ticket_id": ticket_id, "resolved": True, "message": msg}


# ---------------------------------------------------------------------------
# Tamper-Evident Cryptographic Audit
# ---------------------------------------------------------------------------
@app.get("/api/v1/audit/events", tags=["Audit"])
def get_audit_events(limit: int = Query(50, ge=1, le=500)) -> List[Dict[str, Any]]:
    return default_hash_chain_logger.get_events(limit=limit)


@app.get("/api/v1/audit/verify", tags=["Audit"])
def verify_audit_chain() -> Dict[str, Any]:
    """Verify cryptographic SHA-256 hash-chain integrity of the entire audit trail."""
    return default_hash_chain_logger.verify_chain_integrity()


# ---------------------------------------------------------------------------
# Protected Tool Registry
# ---------------------------------------------------------------------------
@app.get("/api/v1/tools", tags=["Tools"])
def list_registered_tools() -> List[Dict[str, Any]]:
    return default_tool_registry.list_tools()
