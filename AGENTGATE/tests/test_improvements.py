"""Tests for AGENTGATE System Improvements:
1. Dynamic User Role Resolution & Recipient Authorization
2. DLP Auto-Redaction during Report Saving
3. Extensible @protected_tool Registry and Security Enforcement
4. LLM Tool-Call Translation to ActionProposals
"""

import os
import tempfile
import pytest

from auth.user_manager import UserManager
from models.action_request import Operation, AuthorizationDecision, RiskLevel
from models.document_security import Classification
from models.workflow import ExecutionStatus
from security.policy_manager import get_user_role, is_recipient_authorized, register_trusted_user
from tools.report_saver import ReportSaver
from tools.registry import ProtectedToolRegistry
from agent.llm_integration import LLMIntegration
from storage.audit_logger import AuditLogger
from storage.document_registry import DocumentRegistry


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.remove(path)
    except OSError:
        pass


def test_dynamic_user_role_resolution(temp_db):
    """Test that dynamically registered users are immediately resolved by policy manager."""
    um = UserManager(db_path=temp_db)
    ok, msg, user = um.register_user(
        username="auditor_jane",
        password="securepass123",
        role="AUTHORIZED_USER",
        full_name="Jane Auditor",
    )
    assert ok is True
    uid = user["user_id"]

    # In-memory register / dynamic lookup
    register_trusted_user(uid, "AUTHORIZED_USER")
    resolved_role = get_user_role(uid)
    assert resolved_role == "AUTHORIZED_USER"


def test_dynamic_recipient_authorization():
    """Test that users with authorized roles can be recognized as recipients."""
    # Pre-seeded authorized recipient
    assert is_recipient_authorized("USER-101") is True
    # Unknown recipient
    assert is_recipient_authorized("USER-999") is False


def test_report_saver_auto_redaction(tmp_path):
    """Test that save_report with auto_redact=True scrubs PII / sensitive data."""
    audit_logger = AuditLogger(db_path=str(tmp_path / "test.db"))
    doc_registry = DocumentRegistry()
    reports_dir = tmp_path / "reports"

    saver = ReportSaver(
        registry=doc_registry,
        audit_logger=audit_logger,
        storage_dir=str(reports_dir),
    )

    sensitive_content = (
        "Internal contact: alice@company.com with phone +1 555-234-5678. "
        "Financial figures summarized."
    )

    result = saver.save_report(
        user_id="USER-001",  # Administrator
        report_id="TEST-REP-REDACT",
        title="Sanitized Summary",
        content=sensitive_content,
        source_doc_ids=["DOC-001"],
        auto_redact=True,
    )

    assert result.status == ExecutionStatus.SUCCESS
    assert result.output["is_sanitized"] is True
    assert result.output["dlp_findings_count"] > 0
    assert "alice@company.com" not in result.output["content"]
    assert "[REDACTED:EMAIL]" in result.output["content"]


def test_protected_tool_decorator_enforcement(tmp_path):
    """Test that @protected_tool enforces gateway authorization and fails closed."""
    audit_logger = AuditLogger(db_path=str(tmp_path / "test.db"))
    registry = ProtectedToolRegistry()

    execution_count = 0

    @registry.register(
        name="secure_analytics_query",
        operation=Operation.ACCESS_RESOURCE,
        required_classification=Classification.INTERNAL,
    )
    def run_analytics(user_id: str, query: str):
        nonlocal execution_count
        execution_count += 1
        return {"rows": [1, 2, 3], "query": query}

    # 1. Authorized user (USER-101) has access to INTERNAL resources
    res_allowed = run_analytics(user_id="USER-101", query="SELECT COUNT(*) FROM logs")
    assert res_allowed.status == ExecutionStatus.SUCCESS
    assert execution_count == 1
    assert res_allowed.output["rows"] == [1, 2, 3]

    # 2. Restricted user (USER-201) cannot access INTERNAL resources (Fail-Closed)
    res_blocked = run_analytics(user_id="USER-201", query="SELECT * FROM confidential")
    assert res_blocked.status == ExecutionStatus.BLOCKED
    assert execution_count == 1  # Underlying tool was NEVER called
    assert res_blocked.output is None


def test_llm_tool_call_translation():
    """Test that structured LLM tool calls translate into validated ActionProposals without self-authorization."""
    llm = LLMIntegration()

    proposal = llm.parse_tool_call(
        user_id="USER-101",
        tool_name="read_document",
        arguments={"document_id": "doc-002"},
    )

    assert proposal is not None
    assert proposal.operation == Operation.READ_DOCUMENT
    assert proposal.resource_id == "DOC-002"
    assert proposal.user_id == "USER-101"


def test_nemotron_tool_call_mock(monkeypatch):
    """Test that Nemotron NIM response with function calling translates to ActionProposal."""
    llm = LLMIntegration()

    # Mock response from NVIDIA NIM chat completions
    mock_response_data = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_12345",
                            "type": "function",
                            "function": {
                                "name": "send_report",
                                "arguments": '{"report_id": "REP-SEC-01", "recipient_id": "USER-102"}',
                            },
                        }
                    ],
                }
            }
        ]
    }

    class MockHTTPResponse:
        status_code = 200

        def json(self):
            return mock_response_data

    # Monkeypatch httpx.Client.post
    monkeypatch.setattr(
        "httpx.Client.post",
        lambda *args, **kwargs: MockHTTPResponse(),
    )

    proposal = llm.interpret_user_request(
        user_id="USER-101",
        prompt="Please forward report REP-SEC-01 to user USER-102",
        api_key="nvapi-mock-test-key",
    )

    assert proposal is not None
    assert proposal.operation == Operation.SEND_REPORT
    assert proposal.resource_id == "REP-SEC-01"
    assert proposal.recipient_id == "USER-102"
    assert proposal.user_id == "USER-101"


def test_nemotron_offline_fallback():
    """Test that when no API key is provided, system falls back safely to deterministic parser."""
    llm = LLMIntegration()
    proposal = llm.interpret_user_request(
        user_id="USER-101",
        prompt="read document DOC-001",
        api_key=None,
    )
    assert proposal is not None
    assert proposal.operation == Operation.READ_DOCUMENT
    assert proposal.resource_id == "DOC-001"

