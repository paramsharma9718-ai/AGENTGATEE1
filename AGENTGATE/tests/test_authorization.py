import pytest
from datetime import datetime
from models.action_request import ActionRequest, Operation
from security.authorization import authorize_action
from security.approval import apply_approval
from models.action_request import AuthorizationDecision, RiskLevel

# Helper to create a request with classification in metadata
def make_request(request_id, user_id, operation, resource_id, classification, recipient_id=None):
    metadata = {"classification": classification}
    return ActionRequest(
        request_id=request_id,
        user_id=user_id,
        operation=operation,
        resource_id=resource_id,
        recipient_id=recipient_id,
        metadata=metadata,
    )

# TEST 01 – Administrator accesses an authorized document (public)
def test_admin_read_public_document():
    req = make_request("REQ-001", "USER-001", Operation.READ_DOCUMENT, "DOC-001", "public")
    resp = authorize_action(req)
    assert resp.decision == AuthorizationDecision.ALLOW
    assert resp.risk_level == RiskLevel.LOW
    assert "ALLOW" in resp.explanation

# TEST 02 – Authorized user accesses a permitted internal document
def test_authorized_user_read_internal_document():
    req = make_request("REQ-002", "USER-101", Operation.READ_DOCUMENT, "DOC-002", "internal")
    resp = authorize_action(req)
    assert resp.decision == AuthorizationDecision.ALLOW
    assert resp.risk_level == RiskLevel.MEDIUM

# TEST 03 – Restricted user accesses a confidential document (should be blocked)
def test_restricted_user_confidential_read_blocked():
    req = make_request("REQ-003", "USER-201", Operation.READ_DOCUMENT, "DOC-003", "confidential")
    resp = authorize_action(req)
    assert resp.decision == AuthorizationDecision.BLOCK
    assert resp.risk_level == RiskLevel.CRITICAL

# TEST 04 – User attempts an unauthorized operation (restricted user saving report)
def test_restricted_user_save_report_blocked():
    req = make_request("REQ-004", "USER-201", Operation.SAVE_REPORT, "REP-001", "public")
    resp = authorize_action(req)
    assert resp.decision == AuthorizationDecision.BLOCK
    assert resp.risk_level == RiskLevel.HIGH

# TEST 05 – Send confidential report to unauthorized recipient
def test_send_confidential_to_unauthorized_recipient():
    req = make_request(
        "REQ-005",
        "USER-101",
        Operation.SEND_REPORT,
        "REP-002",
        "confidential",
        recipient_id="USER-999",  # not in authorized list
    )
    resp = authorize_action(req)
    assert resp.decision == AuthorizationDecision.BLOCK
    assert resp.risk_level == RiskLevel.CRITICAL

# TEST 06 – High‑risk operation requires additional approval (confidential send to authorized recipient)
def test_send_confidential_requires_approval():
    req = make_request(
        "REQ-006",
        "USER-101",
        Operation.SEND_REPORT,
        "REP-003",
        "confidential",
        recipient_id="USER-101",
    )
    resp = authorize_action(req)
    assert resp.decision == AuthorizationDecision.REQUIRE_APPROVAL
    assert resp.risk_level == RiskLevel.CRITICAL
    assert resp.approval_required is True

# TEST 07 – Unauthorized modification of classification
def test_modify_classification_by_non_admin_blocked():
    req = make_request("REQ-007", "USER-101", Operation.MODIFY_CLASSIFICATION, "DOC-004", "internal")
    resp = authorize_action(req)
    assert resp.decision == AuthorizationDecision.BLOCK
    assert resp.risk_level == RiskLevel.CRITICAL

# TEST 09 – Invalid user identity (unknown user)
def test_unknown_user_blocked():
    req = make_request("REQ-008", "UNKNOWN-USER", Operation.READ_DOCUMENT, "DOC-005", "public")
    resp = authorize_action(req)
    assert resp.decision == AuthorizationDecision.BLOCK
    assert resp.risk_level == RiskLevel.CRITICAL

# TEST 11 – Missing resource classification (metadata omitted)
def test_missing_classification_blocked():
    # Build request without classification metadata
    req = ActionRequest(
        request_id="REQ-009",
        user_id="USER-101",
        operation=Operation.READ_DOCUMENT,
        resource_id="DOC-006",
        metadata={},
    )
    resp = authorize_action(req)
    assert resp.decision == AuthorizationDecision.BLOCK
    assert resp.risk_level == RiskLevel.CRITICAL

# TEST 14 – Unauthorized person attempts to approve an operation
def test_non_admin_approval_rejected():
    # First get a response that requires approval
    req = make_request(
        "REQ-010",
        "USER-101",
        Operation.SEND_REPORT,
        "REP-004",
        "confidential",
        recipient_id="USER-101",
    )
    pending = authorize_action(req)
    assert pending.decision == AuthorizationDecision.REQUIRE_APPROVAL
    # Try to approve with a restricted user (not admin)
    rejected = apply_approval(pending, "USER-201")
    assert rejected.decision == AuthorizationDecision.BLOCK
    assert "not an administrator" in rejected.explanation

# TEST 15 – Valid admin approval for approval‑dependent operation
def test_admin_approves_confidential_send():
    req = make_request(
        "REQ-011",
        "USER-101",
        Operation.SEND_REPORT,
        "REP-005",
        "confidential",
        recipient_id="USER-101",
    )
    pending = authorize_action(req)
    assert pending.decision == AuthorizationDecision.REQUIRE_APPROVAL
    approved = apply_approval(pending, "USER-001")  # ADMINISTRATOR
    assert approved.decision == AuthorizationDecision.ALLOW
    assert approved.approval_required is False
    assert approved.approved_by == "USER-001"
    assert isinstance(approved.approved_at, datetime)

# TEST 13 – Ensure pending approval is not treated as ALLOW by callers
def test_pending_response_not_executable():
    req = make_request(
        "REQ-012",
        "USER-101",
        Operation.SEND_REPORT,
        "REP-006",
        "confidential",
        recipient_id="USER-101",
    )
    pending = authorize_action(req)
    assert pending.decision == AuthorizationDecision.REQUIRE_APPROVAL
    # Simulate a tool that mistakenly proceeds without approval
    # The tool should check `approval_required` and refuse execution.
    assert pending.approval_required is True
