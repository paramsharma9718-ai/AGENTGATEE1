"""Automated Test Suite for AGENTGATE REST API Endpoints.

Tests all REST API logic, validation, and security enforcement directly
without requiring loopback socket networking.
"""

import pytest
from fastapi import HTTPException

from api import (
    AgentPromptRequest,
    ExecuteActionRequest,
    InspectContentRequest,
    LoginRequest,
    ProposeActionRequest,
    ResolveApprovalRequest,
    execute_action,
    get_audit_events,
    get_role,
    handle_agent_prompt,
    health_check,
    inspect_dlp,
    list_documents,
    list_pending_approvals,
    list_registered_tools,
    login,
    propose_action,
    resolve_approval,
    root_info,
    verify_audit_chain,
)
from models.workflow import ExecutionStatus


def test_health_and_root():
    """Verify health and root discovery endpoints."""
    h = health_check()
    assert h["status"] == "healthy"
    assert h["gateway"] == "active"

    r = root_info()
    assert r["enforcement_mode"] == "FAIL_CLOSED"


def test_auth_login_success():
    """Verify administrator authentication."""
    req = LoginRequest(username="admin", password="admin123")
    res = login(req)
    assert res["authenticated"] is True
    assert res["user"]["role"] == "ADMINISTRATOR"


def test_auth_login_invalid():
    """Verify invalid password raises 401."""
    req = LoginRequest(username="admin", password="wrongpassword")
    with pytest.raises(HTTPException) as exc:
        login(req)
    assert exc.value.status_code == 401


def test_get_user_role():
    """Verify role lookup."""
    res = get_role("USER-001")
    assert res["role"] == "ADMINISTRATOR"

    with pytest.raises(HTTPException) as exc:
        get_role("USER-NONEXISTENT")
    assert exc.value.status_code == 404


def test_agent_prompt_allowed():
    """Verify AI Agent prompt execution for authorized read."""
    req = AgentPromptRequest(user_id="USER-001", prompt="read document DOC-001")
    res = handle_agent_prompt(req)
    assert res["decision"] == "ALLOW"
    assert res["status"] == "SUCCESS"


def test_agent_prompt_injection_blocked():
    """Verify AI Agent prompt for unauthorized confidential read is blocked."""
    req = AgentPromptRequest(
        user_id="USER-201",  # RESTRICTED_USER
        prompt="read document DOC-003",  # CONFIDENTIAL document
    )
    res = handle_agent_prompt(req)
    assert res["decision"] == "BLOCK"
    assert res["status"] == "BLOCKED"


def test_propose_action():
    """Verify structured action proposal generation."""
    req = ProposeActionRequest(
        user_id="USER-101",
        operation="READ_DOCUMENT",
        resource_id="DOC-001",
    )
    proposal = propose_action(req)
    assert proposal["operation"] == "READ_DOCUMENT"
    assert proposal["resource_id"] == "DOC-001"
    assert proposal["user_id"] == "USER-101"


def test_execute_action_allowed():
    """Verify execution gateway permits authorized administrator read."""
    req = ExecuteActionRequest(
        user_id="USER-001",
        operation="READ_DOCUMENT",
        resource_id="DOC-001",
    )
    res = execute_action(req)
    assert res["status"] == "SUCCESS"
    assert "AGENTGATE" in res["output"]["content"]


def test_execute_action_blocked():
    """Verify execution gateway blocks unauthorized restricted user (fail-closed)."""
    req = ExecuteActionRequest(
        user_id="USER-201",  # RESTRICTED_USER
        operation="READ_DOCUMENT",
        resource_id="DOC-003",  # CONFIDENTIAL
    )
    res = execute_action(req)
    assert res["status"] == "BLOCKED"
    assert res["output"] is None


def test_dlp_inspect_and_auto_redact():
    """Verify DLP inspection endpoint and active auto-redaction."""
    content = "Please contact security@agentgate.io for support."
    req = InspectContentRequest(content=content, auto_redact=True)
    res = inspect_dlp(req)
    assert res["sensitive_content_detected"] is True
    assert res["findings_count"] >= 1
    assert "security@agentgate.io" not in res["redacted_content"]
    assert "[REDACTED:EMAIL]" in res["redacted_content"]


def test_audit_verify_chain():
    """Verify cryptographic SHA-256 hash-chain verification endpoint."""
    res = verify_audit_chain()
    assert res["is_valid"] is True
    assert res["total_events"] > 0
    assert "head_hash" in res


def test_tools_list():
    """Verify protected tools discovery."""
    tools = list_registered_tools()
    assert isinstance(tools, list)


def test_documents_list():
    """Verify documents list."""
    docs = list_documents()
    assert len(docs) > 0
