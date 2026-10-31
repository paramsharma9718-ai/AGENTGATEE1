"""Security classification levels and classification-change validation.

This module is the single trusted authority for:

* the four classification levels and their *explicit* ordering,
* computing the strictest classification of a set of sources,
* validating classification changes (assignments, upgrades, downgrades).

Design rules
------------
* Ordering comes from an explicit rank table. Enum declaration order, string
  comparison and alphabetical sorting are never used for security decisions.
* A downgrade is rejected unless a *trusted authorization result* obtained from
  a :class:`TrustedAuthorizationVerifier` (owned by the central authorization
  engine, not by this module) is bound to the exact document and the exact
  from/to levels, was granted, is policy-permitted and has not expired.
* Free-form strings such as "approved by admin" carry no authority; they are
  only looked up as opaque references.
* Everything here is deterministic and free of I/O. The optional ``now``
  argument exists so tests can pin time.

Circular imports: ``models.document_security`` imports :class:`Classification`
from this module, so model classes are imported lazily inside functions here.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Iterable, Optional, Protocol, runtime_checkable

if TYPE_CHECKING:  # pragma: no cover - typing only
    from models.document_security import (
        ClassificationChangeDecision,
        ClassificationChangeRequest,
        DocumentSecurityMetadata,
        TrustedAuthorizationResult,
    )

DOWNGRADE_OPERATION = "classification.downgrade"
"""Policy operation name a trusted authorization must carry to permit a downgrade."""


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class SecurityLabelError(Exception):
    """Base class for all classification / information-flow errors."""


class InvalidClassificationError(SecurityLabelError, ValueError):
    """A value is not one of the four valid classification levels."""


class EmptyClassificationSetError(SecurityLabelError, ValueError):
    """The strictest classification of an empty collection is undefined.

    An empty collection is deliberately NOT treated as PUBLIC.
    """


class UnauthorizedDowngradeError(SecurityLabelError, PermissionError):
    """A classification would become less restrictive without valid authorization."""

    def __init__(self, message: str, reason: "ChangeReason | None" = None) -> None:
        super().__init__(message)
        self.reason = reason


# --------------------------------------------------------------------------- #
# Classification levels
# --------------------------------------------------------------------------- #
class Classification(str, Enum):
    """Security classification: PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED.

    Rich comparisons are overridden to use the explicit rank table, because the
    ``str`` mixin would otherwise compare alphabetically.
    """

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"

    @property
    def rank(self) -> int:
        """Explicit security rank (higher = more restrictive)."""
        return _RANK[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Classification):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Classification):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Classification):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Classification):
            return NotImplemented
        return self.rank >= other.rank

    # Defining comparison operators must not remove hashability.
    __hash__ = str.__hash__


_RANK = {
    Classification.PUBLIC: 0,
    Classification.INTERNAL: 1,
    Classification.CONFIDENTIAL: 2,
    Classification.RESTRICTED: 3,
}


def parse_classification(value: Any) -> Classification:
    """Strictly convert ``value`` to a :class:`Classification`.

    Accepts a ``Classification`` member or the exact upper-case level name.
    Everything else (``None``, ints, booleans, lower-case or padded strings,
    unknown labels) raises :class:`InvalidClassificationError`.
    """
    if isinstance(value, Classification):
        return value
    if isinstance(value, str) and value in Classification.__members__:
        return Classification[value]
    shown = value[:40] if isinstance(value, str) else ""
    raise InvalidClassificationError(
        f"invalid classification (type={type(value).__name__}"
        + (f", value={shown!r}" if shown else "")
        + ")"
    )


def compare_classifications(a: Any, b: Any) -> int:
    """Return -1, 0 or 1 as ``a`` is less, equal or more restrictive than ``b``."""
    ra, rb = parse_classification(a).rank, parse_classification(b).rank
    return (ra > rb) - (ra < rb)


def strictest_classification(classifications: Iterable[Any]) -> Classification:
    """Return the most restrictive classification in ``classifications``.

    Raises:
        EmptyClassificationSetError: if the collection is empty.
        InvalidClassificationError: if any element is not a valid level.
    """
    if isinstance(classifications, (str, bytes)):
        raise InvalidClassificationError("expected a collection of classifications, got a string")
    parsed = [parse_classification(c) for c in classifications]
    if not parsed:
        raise EmptyClassificationSetError(
            "cannot compute the strictest classification of an empty collection"
        )
    return max(parsed, key=lambda c: c.rank)


def is_downgrade(current: Any, requested: Any) -> bool:
    """True if ``requested`` is strictly less restrictive than ``current``."""
    return compare_classifications(requested, current) < 0


def is_at_least_as_restrictive(candidate: Any, baseline: Any) -> bool:
    """True if ``candidate`` is at least as restrictive as ``baseline``."""
    return compare_classifications(candidate, baseline) >= 0


# --------------------------------------------------------------------------- #
# Trusted authorization boundary
# --------------------------------------------------------------------------- #
@runtime_checkable
class TrustedAuthorizationVerifier(Protocol):
    """Integration boundary implemented by the central authorization engine.

    ``lookup`` must return the authorization result the *trusted* engine issued
    for ``authorization_id`` (or ``None`` if unknown). This module never mints,
    caches or infers authorizations. It never treats LLM output as one.
    """

    def lookup(self, authorization_id: str) -> Optional["TrustedAuthorizationResult"]:  # pragma: no cover
        ...


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def verify_downgrade_authorization(
    *,
    document_id: str,
    current: Classification,
    requested: Classification,
    authorization_id: Optional[str],
    verifier: Optional[TrustedAuthorizationVerifier],
    now: Optional[datetime] = None,
) -> "ChangeReason":
    """Check a downgrade against a trusted authorization. Never raises.

    Returns ``ChangeReason.DOWNGRADE_AUTHORIZED`` only if the verifier returns a
    result that is bound to this document and this exact from/to pair, carries
    the downgrade operation, was granted AND is permitted by policy (approval
    alone never overrides a policy prohibition), and has not expired.
    Any other outcome, including verifier errors, fails closed.
    """
    from models.document_security import ChangeReason, TrustedAuthorizationResult

    if not authorization_id:
        return ChangeReason.DOWNGRADE_NO_AUTHORIZATION
    if verifier is None:
        return ChangeReason.NO_VERIFIER_CONFIGURED
    try:
        result = verifier.lookup(authorization_id)
    except Exception:  # noqa: BLE001 - fail closed; do not leak details
        return ChangeReason.VERIFIER_ERROR
    if result is None:
        return ChangeReason.AUTHORIZATION_NOT_FOUND
    if not isinstance(result, TrustedAuthorizationResult):
        return ChangeReason.VERIFIER_ERROR
    if (
        result.authorization_id != authorization_id
        or result.operation != DOWNGRADE_OPERATION
        or result.document_id != document_id
        or result.from_classification != current
        or result.to_classification != requested
    ):
        return ChangeReason.AUTHORIZATION_MISMATCH
    if not result.policy_permits:
        return ChangeReason.POLICY_PROHIBITS_DOWNGRADE
    if not result.approval_granted:
        return ChangeReason.AUTHORIZATION_NOT_GRANTED
    if result.expires_at is not None and result.expires_at <= (now or _utc_now()):
        return ChangeReason.AUTHORIZATION_EXPIRED
    return ChangeReason.DOWNGRADE_AUTHORIZED


# --------------------------------------------------------------------------- #
# Classification change validation
# --------------------------------------------------------------------------- #
def evaluate_classification_change(
    request: "ClassificationChangeRequest",
    current: "DocumentSecurityMetadata",
    verifier: Optional[TrustedAuthorizationVerifier] = None,
    *,
    now: Optional[datetime] = None,
) -> "ClassificationChangeDecision":
    """Evaluate a proposed classification change. Returns a structured decision.

    ``current`` MUST be the trusted stored metadata, not caller-supplied data.
    The request's own ``current_classification`` is only checked against it, so
    a requester cannot misstate a document's level to make a downgrade look
    like an upgrade. The request's ``status`` is never trusted.

    * Increase in restriction -> accepted (never loses protection).
    * Downgrade -> accepted only with a valid trusted authorization.
    * Everything else -> rejected with a machine-readable reason.
    """
    from models.document_security import (
        ChangeReason,
        ChangeStatus,
        ClassificationChangeDecision,
    )

    def decide(status: ChangeStatus, reason: ChangeReason, auth_id: Optional[str] = None):
        return ClassificationChangeDecision(
            document_id=request.document_id,
            from_classification=current.classification,
            to_classification=request.requested_classification,
            status=status,
            reason=reason,
            is_downgrade=is_downgrade(current.classification, request.requested_classification),
            authorization_id=auth_id,
            decided_at=now or _utc_now(),
        )

    rejected = ChangeStatus.REJECTED
    if request.status != ChangeStatus.PENDING:
        return decide(rejected, ChangeReason.REQUEST_NOT_PENDING)
    if request.document_id != current.document_id:
        return decide(rejected, ChangeReason.DOCUMENT_MISMATCH)
    if request.current_classification != current.classification:
        return decide(rejected, ChangeReason.STALE_CURRENT_CLASSIFICATION)

    if not is_downgrade(current.classification, request.requested_classification):
        return decide(ChangeStatus.ACCEPTED, ChangeReason.RESTRICTION_INCREASED)

    reason = verify_downgrade_authorization(
        document_id=request.document_id,
        current=current.classification,
        requested=request.requested_classification,
        authorization_id=request.authorization_reference,
        verifier=verifier,
        now=now,
    )
    if reason == ChangeReason.DOWNGRADE_AUTHORIZED:
        return decide(ChangeStatus.ACCEPTED, reason, request.authorization_reference)
    return decide(rejected, reason)


def validate_classification_change(
    request: "ClassificationChangeRequest",
    current: "DocumentSecurityMetadata",
    verifier: Optional[TrustedAuthorizationVerifier] = None,
    *,
    now: Optional[datetime] = None,
) -> "ClassificationChangeDecision":
    """Like :func:`evaluate_classification_change` but raises on rejection.

    Raises:
        UnauthorizedDowngradeError: if the change is rejected for any reason.
    """
    decision = evaluate_classification_change(request, current, verifier, now=now)
    if decision.status.value != "ACCEPTED":
        raise UnauthorizedDowngradeError(
            f"classification change {decision.from_classification.value} -> "
            f"{decision.to_classification.value} rejected: {decision.reason.value}",
            reason=decision.reason,
        )
    return decision


def apply_classification_change(
    request: "ClassificationChangeRequest",
    current: "DocumentSecurityMetadata",
    verifier: Optional[TrustedAuthorizationVerifier] = None,
    *,
    now: Optional[datetime] = None,
) -> "DocumentSecurityMetadata":
    """Validate a change and return NEW metadata carrying the new label.

    The input metadata is immutable and is never modified in place.
    """
    from models.document_security import LabelOrigin

    decision = validate_classification_change(request, current, verifier, now=now)
    update: dict[str, Any] = {"classification": decision.to_classification}
    if decision.is_downgrade:
        update["label_origin"] = LabelOrigin.DECLASSIFIED
        update["declassification_authorization_id"] = decision.authorization_id
    # Re-validate (model_copy would skip validators).
    return type(current).model_validate({**dict(current), **update})
