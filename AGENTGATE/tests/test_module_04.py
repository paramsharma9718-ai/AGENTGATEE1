"""Unit and Integration Tests for Module 04: Application, Database, Dashboard & Monitoring.

Author: Param (Module 04)
Covers:
1. User registration, PBKDF2 password hashing, and authentication.
2. Tamper-evident SHA-256 hash chaining and cryptographic tampering detection.
3. Secure document ingestion, automated DLP classification, and safe storage.
4. Gateway-enforced document reading authorization.
5. Human approval workflow lifecycle and role authorization.
"""

import os
import shutil
import tempfile
import pytest

from auth.user_manager import UserManager, hash_password, verify_password
from models.action_request import AuthorizationDecision, Operation, RiskLevel
from models.document_security import Classification
from models.workflow import ActionProposal, ExecutionResult, ExecutionStatus
from storage.approval_service import ApprovalService
from storage.document_registry import DocumentRegistry
from storage.document_service import DocumentService
from storage.hash_chain_audit import HashChainAuditLogger, compute_event_hash
from tools.execution_gateway import ExecutionGateway


@pytest.fixture
def m4_env():
    """Create isolated sandbox database and storage for Module 04 tests."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_m4_agentgate.db")
    doc_dir = os.path.join(temp_dir, "documents")

    hash_logger = HashChainAuditLogger(db_path=db_path)
    user_mgr = UserManager(db_path=db_path)
    registry = DocumentRegistry(storage_dir=doc_dir)
    gateway = ExecutionGateway(audit_logger=hash_logger, document_registry=registry)
    doc_service = DocumentService(db_path=db_path, registry=registry, gateway=gateway)
    appr_service = ApprovalService(db_path=db_path)

    yield {
        "temp_dir": temp_dir,
        "db_path": db_path,
        "hash_logger": hash_logger,
        "user_mgr": user_mgr,
        "registry": registry,
        "gateway": gateway,
        "doc_service": doc_service,
        "appr_service": appr_service,
    }

    shutil.rmtree(temp_dir, ignore_errors=True)


# -------------------------------------------------------------
# 1. USER AUTHENTICATION & REGISTRATION TESTS
# -------------------------------------------------------------
def test_user_registration_and_password_hashing(m4_env):
    user_mgr: UserManager = m4_env["user_mgr"]

    # Register new user
    ok, msg, user = user_mgr.register_user(
        username="security_analyst",
        password="SecurePassword123!",
        role="AUTHORIZED_USER",
        full_name="Alex Security",
    )
    assert ok is True
    assert user["username"] == "security_analyst"
    assert user["role"] == "AUTHORIZED_USER"

    # Verify password is NOT stored in plaintext
    with user_mgr._get_connection() as conn:
        row = conn.execute("SELECT password_hash, salt FROM users WHERE username = 'security_analyst'").fetchone()
        assert row["password_hash"] != "SecurePassword123!"
        assert len(row["password_hash"]) == 64  # SHA-256 hex digest length
        assert len(row["salt"]) > 10

    # Successful authentication
    auth_user = user_mgr.authenticate_user("security_analyst", "SecurePassword123!")
    assert auth_user is not None
    assert auth_user["username"] == "security_analyst"

    # Failed authentication with incorrect password
    bad_auth = user_mgr.authenticate_user("security_analyst", "WrongPassword")
    assert bad_auth is None

    # Duplicate username rejection
    dup_ok, dup_msg, _ = user_mgr.register_user("security_analyst", "another_pwd")
    assert dup_ok is False
    assert "already exists" in dup_msg


# -------------------------------------------------------------
# 2. TAMPER-EVIDENT HASH CHAIN AUDIT TESTS
# -------------------------------------------------------------
def test_tamper_evident_hash_chain_integrity_and_detection(m4_env):
    logger: HashChainAuditLogger = m4_env["hash_logger"]

    # Log 3 events
    e1 = logger.log_event(
        event_id="EVT-001",
        user_id="USER-101",
        operation=Operation.READ_DOCUMENT,
        resource_id="DOC-001",
        decision=AuthorizationDecision.ALLOW,
        risk_level=RiskLevel.LOW,
        explanation="Authorized read",
        status=ExecutionStatus.SUCCESS,
    )

    e2 = logger.log_event(
        event_id="EVT-002",
        user_id="USER-201",
        operation=Operation.READ_DOCUMENT,
        resource_id="DOC-003",
        decision=AuthorizationDecision.BLOCK,
        risk_level=RiskLevel.CRITICAL,
        explanation="Restricted role denied",
        status=ExecutionStatus.BLOCKED,
    )

    # Initial integrity check must PASS
    res1 = logger.verify_chain_integrity()
    assert res1["is_valid"] is True
    assert res1["total_events"] == 2
    assert res1["error_message"] is None

    # Tampering Attack Simulation: An adversary illicitly modifies EVT-002 from BLOCK to ALLOW in the DB
    tampered = logger.simulate_tampering_for_demo(event_id="EVT-002", field="decision", new_value="ALLOW")
    assert tampered is True

    # Verification must now FAIL and pinpoint the exact tampered record
    res2 = logger.verify_chain_integrity()
    assert res2["is_valid"] is False
    assert res2["tampered_event_id"] == "EVT-002"
    assert "tampering detected" in res2["error_message"].lower()


# -------------------------------------------------------------
# 3. DOCUMENT INGESTION & AUTOMATED DLP SCANNING TESTS
# -------------------------------------------------------------
def test_document_ingestion_and_dlp_classification(m4_env):
    doc_service: DocumentService = m4_env["doc_service"]

    # Document containing sensitive financial and PII text
    sensitive_content = (
        "CONFIDENTIAL Executive Compensation Report\n"
        "Employee SSN: 123-45-6789\n"
        "Executive Salary: $250,000\n"
        "Contact: param@agentgate.internal"
    ).encode("utf-8")

    ok, msg, res = doc_service.upload_document(
        filename="ExecComp.txt",
        file_bytes=sensitive_content,
        uploaded_by="USER-001",
        user_role="ADMINISTRATOR",
        description="Salary report",
    )

    assert ok is True
    assert res["classification"] == "CONFIDENTIAL"
    assert len(res["dlp_findings"]) > 0  # DLP caught SSN / Email / markings

    # Test reading with authorization via ExecutionGateway
    # Admin (USER-001) is cleared for CONFIDENTIAL
    allowed, content, cls_val, dec = doc_service.get_document_content(res["document_id"], "USER-001")
    assert allowed is True
    assert "CONFIDENTIAL" in content

    # Restricted user (USER-201) is BLOCKED
    blocked, err_msg, _, b_dec = doc_service.get_document_content(res["document_id"], "USER-201")
    assert blocked is False
    assert b_dec == "BLOCK"
    assert "ACCESS DENIED" in err_msg


# -------------------------------------------------------------
# 4. APPROVAL WORKFLOW SERVICE TESTS
# -------------------------------------------------------------
def test_approval_workflow_authorization(m4_env):
    appr_service: ApprovalService = m4_env["appr_service"]
    gateway: ExecutionGateway = m4_env["gateway"]

    # Create a proposal that requires approval (e.g. SEND_REPORT on confidential)
    proposal = ActionProposal(
        proposal_id="PROP-APPR-01",
        user_id="USER-101",
        operation=Operation.SEND_REPORT,
        resource_id="CONF-REP-01",
        recipient_id="USER-101",
        parameters={"verified_classification": "confidential"},
    )
    res = gateway.execute_proposal(proposal, lambda: {"status": "DELIVERED"})
    assert res.authorization_response.decision == AuthorizationDecision.REQUIRE_APPROVAL
    assert res.status == ExecutionStatus.PENDING_APPROVAL

    appr_id = appr_service.queue_approval(res)
    assert appr_id.startswith("APPR-")

    # Non-admin cannot approve
    bad_ok, bad_msg, _ = appr_service.approve_request(appr_id, "USER-101", "AUTHORIZED_USER")
    assert bad_ok is False
    assert "Only users with ADMINISTRATOR clearance" in bad_msg

    # Admin CAN approve
    good_ok, good_msg, out = appr_service.approve_request(appr_id, "USER-001", "ADMINISTRATOR")
    assert good_ok is True
    assert "successfully APPROVED" in good_msg
