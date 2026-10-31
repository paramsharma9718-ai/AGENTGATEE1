"""Tests for AGENTGATE Rate Limiter & Agent Loop Breaker (Denial-of-Wallet Defense)."""

import time
import pytest

from models.action_request import Operation, AuthorizationDecision, RiskLevel
from models.workflow import ActionProposal, ExecutionStatus
from security.rate_limiter import RateLimiter
from tools.execution_gateway import ExecutionGateway
from storage.audit_logger import AuditLogger
from storage.document_registry import DocumentRegistry


def make_proposal(user_id: str, op: Operation, res_id: str, prop_id: str = "P-1") -> ActionProposal:
    return ActionProposal(
        proposal_id=prop_id,
        user_id=user_id,
        operation=op,
        resource_id=res_id,
    )


def test_sliding_window_rate_limiting():
    limiter = RateLimiter(max_requests_per_window=3, window_seconds=0.5)

    p1 = make_proposal("U1", Operation.READ_DOCUMENT, "DOC-001", "P-1")
    p2 = make_proposal("U1", Operation.READ_DOCUMENT, "DOC-002", "P-2")
    p3 = make_proposal("U1", Operation.READ_DOCUMENT, "DOC-003", "P-3")
    p4 = make_proposal("U1", Operation.READ_DOCUMENT, "DOC-004", "P-4")

    ok, msg, code = limiter.check_proposal(p1)
    assert ok is True
    assert code == "ALLOW"

    ok, msg, code = limiter.check_proposal(p2)
    assert ok is True

    ok, msg, code = limiter.check_proposal(p3)
    assert ok is True

    # 4th request exceeds max_requests=3
    ok, msg, code = limiter.check_proposal(p4)
    assert ok is False
    assert code == "RATE_LIMIT_EXCEEDED"
    assert "Rate limit exceeded" in msg

    # Different user should not be affected
    other_user_p = make_proposal("U2", Operation.READ_DOCUMENT, "DOC-001", "P-Other")
    ok, msg, code = limiter.check_proposal(other_user_p)
    assert ok is True

    # Wait for window to expire
    time.sleep(0.6)
    ok, msg, code = limiter.check_proposal(p4)
    assert ok is True
    assert code == "ALLOW"


def test_identical_call_loop_detection():
    limiter = RateLimiter(
        max_requests_per_window=100,
        loop_threshold=3,
        loop_window_seconds=2.0,
        circuit_cooldown_seconds=0.4,
    )

    prop = make_proposal("U-LOOP", Operation.READ_DOCUMENT, "DOC-001", "P-1")

    # 1st call
    ok, _, code = limiter.check_proposal(prop)
    assert ok is True
    assert code == "ALLOW"

    # 2nd call
    ok, _, code = limiter.check_proposal(prop)
    assert ok is True
    assert code == "ALLOW"

    # 3rd identical call -> Trips loop breaker!
    ok, msg, code = limiter.check_proposal(prop)
    assert ok is False
    assert code == "LOOP_DETECTED"
    assert "Agent execution loop detected" in msg
    assert "Circuit breaker tripped" in msg

    # Immediate subsequent call is blocked by open circuit breaker
    diff_prop = make_proposal("U-LOOP", Operation.SAVE_REPORT, "REP-01", "P-DIFF")
    ok, msg, code = limiter.check_proposal(diff_prop)
    assert ok is False
    assert code == "CIRCUIT_BREAKER_OPEN"

    # After cooldown period expires
    time.sleep(0.5)
    ok, msg, code = limiter.check_proposal(diff_prop)
    assert ok is True
    assert code == "ALLOW"


def test_ping_pong_loop_detection():
    limiter = RateLimiter(
        max_requests_per_window=100,
        loop_threshold=5,
        loop_window_seconds=2.0,
        circuit_cooldown_seconds=0.5,
    )

    pA = make_proposal("U-PP", Operation.READ_DOCUMENT, "DOC-001", "P-A")
    pB = make_proposal("U-PP", Operation.SAVE_REPORT, "REP-001", "P-B")

    # Pattern: A -> B -> A -> B
    assert limiter.check_proposal(pA)[0] is True
    assert limiter.check_proposal(pB)[0] is True
    assert limiter.check_proposal(pA)[0] is True

    # 4th call completes ping-pong pattern A-B-A-B
    ok, msg, code = limiter.check_proposal(pB)
    assert ok is False
    assert code == "LOOP_DETECTED"
    assert "Ping-pong agent loop detected" in msg


def test_gateway_enforces_loop_breaker_fail_closed(tmp_path):
    db_file = tmp_path / "test_gateway.db"
    logger = AuditLogger(db_path=str(db_file))
    registry = DocumentRegistry(storage_dir=str(tmp_path / "docs"))
    limiter = RateLimiter(loop_threshold=2, loop_window_seconds=2.0, circuit_cooldown_seconds=1.0)

    gateway = ExecutionGateway(audit_logger=logger, document_registry=registry, rate_limiter=limiter)

    tool_called_count = 0

    def mock_tool():
        nonlocal tool_called_count
        tool_called_count += 1
        return {"data": "executed"}

    prop = make_proposal("USER-001", Operation.READ_DOCUMENT, "DOC-001", "P-GATE-1")

    # Call 1 -> allowed
    res1 = gateway.execute_proposal(prop, mock_tool)
    assert res1.status == ExecutionStatus.SUCCESS
    assert tool_called_count == 1

    # Call 2 -> identical repeat trips loop breaker!
    res2 = gateway.execute_proposal(prop, mock_tool)
    assert res2.status == ExecutionStatus.BLOCKED
    assert "Agent execution loop detected" in res2.error_message
    # Critical guarantee: protected tool was NEVER called
    assert tool_called_count == 1

    # Check audit log contains record of blocked loop
    events = logger.get_events(limit=5)
    assert len(events) >= 2
    loop_event = events[0]
    assert loop_event["decision"] == AuthorizationDecision.BLOCK.value
    assert loop_event["status"] == ExecutionStatus.BLOCKED.value
    assert "Denial-of-Wallet" in loop_event["explanation"]
