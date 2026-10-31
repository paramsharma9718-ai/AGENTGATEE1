"""Shared deterministic test helpers (no network, no real credentials)."""
from datetime import datetime, timedelta, timezone

from models.document_security import DocumentSecurityMetadata, TrustedAuthorizationResult
from security.security_labels import DOWNGRADE_OPERATION, Classification

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


class FakeVerifier:
    """Stand-in for the central authorization engine's verifier."""

    def __init__(self, *results, error=False):
        self._by_id = {r.authorization_id: r for r in results}
        self._error = error

    def lookup(self, authorization_id):
        if self._error:
            raise RuntimeError("engine unavailable")
        return self._by_id.get(authorization_id)


def doc(document_id, classification):
    return DocumentSecurityMetadata(document_id=document_id, classification=classification, created_at=T0)


def auth(document_id="REPORT-X", frm=Classification.RESTRICTED, to=Classification.INTERNAL, *,
         authorization_id="AUTH-1", approval=True, policy=True, operation=DOWNGRADE_OPERATION,
         expires_at=None, issued_at=T0):
    return TrustedAuthorizationResult(
        authorization_id=authorization_id, operation=operation, document_id=document_id,
        from_classification=frm, to_classification=to, approval_granted=approval,
        policy_permits=policy, issued_at=issued_at, expires_at=expires_at,
    )


FUTURE = T0 + timedelta(days=3650)
