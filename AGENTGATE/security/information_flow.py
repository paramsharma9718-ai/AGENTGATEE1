"""Information-flow control: trusted derivation of classifications.

Rules enforced (default policy, deterministic):

* A derived artifact inherits the strictest classification among its sources.
* No transformation type (summarisation, aggregation, ...) lowers a label.
* Zero sources, missing metadata, malformed or duplicate sources are rejected.
  There is no implicit PUBLIC default.
* A classification *requested* by an untrusted party (e.g. an LLM) can never
  lower the result. A lower request raises ``UnauthorizedDowngradeError``
  unless a trusted authorization, verified through
  :class:`~security.security_labels.TrustedAuthorizationVerifier` and bound to
  this report and these exact levels, permits it. A higher request is ignored
  (see ``DerivationResult.requested_classification_ignored``); raising the label
  is done by trusted callers through ``minimum_classification``.

This module computes labels only. It makes no access/delivery decisions; those
belong to the central authorization engine.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError

from models.document_security import (
    ChangeReason,
    DocumentSecurityMetadata,
    SecurityId,
    SourceReference,
    TransformationType,
)
from security.security_labels import (
    Classification,
    SecurityLabelError,
    TrustedAuthorizationVerifier,
    UnauthorizedDowngradeError,
    parse_classification,
    strictest_classification,
    verify_downgrade_authorization,
)


class InformationFlowError(SecurityLabelError):
    """Base class for derivation errors."""


class EmptySourcesError(InformationFlowError, ValueError):
    """A derivation had no sources; its classification would be undefined."""


class MissingSourceMetadataError(InformationFlowError, ValueError):
    """A source (or the whole source collection) has no security metadata."""


class InvalidSourceMetadataError(InformationFlowError, ValueError):
    """A source has malformed security metadata."""


class DuplicateSourceError(InformationFlowError, ValueError):
    """The same source document id appears more than once."""


_ID_ADAPTER = TypeAdapter(SecurityId)

SourceInput = Any
"""``DocumentSecurityMetadata``, ``SourceReference`` or a mapping with
``document_id`` and ``classification``."""


class DerivationResult(BaseModel):
    """Trusted outcome of a derivation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    report_id: SecurityId
    sources: Tuple[SourceReference, ...]
    transformation_type: TransformationType
    inherited_classification: Classification
    derived_classification: Classification
    declassified: bool = False
    authorization_id: Optional[SecurityId] = None
    requested_classification_ignored: bool = False


def coerce_sources(sources: Optional[Sequence[SourceInput]]) -> Tuple[SourceReference, ...]:
    """Validate and normalise sources into ``SourceReference`` objects.

    Raises:
        MissingSourceMetadataError: ``sources`` or an element is ``None``.
        EmptySourcesError: the collection is empty.
        InvalidSourceMetadataError: malformed element or invalid collection type.
        DuplicateSourceError: the same document id appears more than once.
    """
    if sources is None:
        raise MissingSourceMetadataError("source metadata is missing")
    if isinstance(sources, (str, bytes, Mapping)) or not hasattr(sources, "__iter__"):
        raise InvalidSourceMetadataError("sources must be a sequence of source metadata objects")
    items = list(sources)
    if not items:
        raise EmptySourcesError("a derived artifact requires at least one source")

    refs = []
    for index, item in enumerate(items):
        if item is None:
            raise MissingSourceMetadataError(f"source #{index} has no security metadata")
        refs.append(_coerce_one(item, index))

    seen = set()
    for ref in refs:
        if ref.document_id in seen:
            raise DuplicateSourceError(f"duplicate source document id {ref.document_id!r}")
        seen.add(ref.document_id)
    return tuple(refs)


def _coerce_one(item: SourceInput, index: int) -> SourceReference:
    if isinstance(item, SourceReference):
        return item
    if isinstance(item, DocumentSecurityMetadata):
        return SourceReference(document_id=item.document_id, classification=item.classification)
    if isinstance(item, Mapping):
        try:
            return SourceReference.model_validate(
                {"document_id": item.get("document_id"), "classification": item.get("classification")}
            )
        except ValidationError as exc:
            raise InvalidSourceMetadataError(f"source #{index} has invalid security metadata") from exc
    raise InvalidSourceMetadataError(
        f"source #{index} has unsupported type {type(item).__name__}"
    )


def derive_classification(
    report_id: str,
    sources: Optional[Sequence[SourceInput]],
    transformation_type: TransformationType,
    *,
    minimum_classification: Optional[Classification] = None,
    requested_classification: Any = None,
    authorization_id: Optional[str] = None,
    verifier: Optional[TrustedAuthorizationVerifier] = None,
) -> DerivationResult:
    """Compute the trusted classification of a derived report.

    Args:
        report_id: ID of the generated artifact (also binds any authorization).
        sources: Source metadata; see :func:`coerce_sources`.
        transformation_type: How the report was produced (validated enum).
        minimum_classification: Trusted floor (e.g. from DLP policy) that can
            only raise the result.
        requested_classification: UNTRUSTED requested label (e.g. from an LLM).
            Lower than the trusted result -> rejected unless authorized.
        authorization_id / verifier: Trusted downgrade authorization for the
            exact (report_id, inherited -> requested) transition.

    Raises:
        UnauthorizedDowngradeError: a lower classification was requested
            without a valid trusted authorization.
        EmptySourcesError, MissingSourceMetadataError, InvalidSourceMetadataError,
        DuplicateSourceError, ValueError: invalid input.
    """
    try:
        report_id = _ID_ADAPTER.validate_python(report_id)
    except ValidationError as exc:
        raise InformationFlowError("invalid report_id") from exc
    try:
        transformation = TransformationType(transformation_type)
    except ValueError as exc:
        raise InformationFlowError(f"invalid transformation type: {str(transformation_type)[:40]!r}") from exc

    refs = coerce_sources(sources)
    if report_id in {r.document_id for r in refs}:
        raise InvalidSourceMetadataError("a report cannot be derived from itself")

    inherited = strictest_classification(r.classification for r in refs)
    if minimum_classification is not None:
        inherited = max(inherited, parse_classification(minimum_classification), key=lambda c: c.rank)

    derived = inherited
    declassified = False
    ignored = False
    auth_used: Optional[str] = None

    if requested_classification is not None:
        requested = parse_classification(requested_classification)
        if requested < inherited:
            reason = verify_downgrade_authorization(
                document_id=report_id,
                current=inherited,
                requested=requested,
                authorization_id=authorization_id,
                verifier=verifier,
            )
            if reason != ChangeReason.DOWNGRADE_AUTHORIZED:
                raise UnauthorizedDowngradeError(
                    f"derived classification {requested.value} is less restrictive than "
                    f"{inherited.value}: {reason.value}",
                    reason=reason,
                )
            derived, declassified, auth_used = requested, True, authorization_id
        elif requested > inherited:
            ignored = True  # untrusted escalation requests are not applied

    return DerivationResult(
        report_id=report_id,
        sources=refs,
        transformation_type=transformation,
        inherited_classification=inherited,
        derived_classification=derived,
        declassified=declassified,
        authorization_id=auth_used,
        requested_classification_ignored=ignored,
    )


def verify_report_classification(
    report: DocumentSecurityMetadata,
    sources: Optional[Sequence[SourceInput]],
    verifier: Optional[TrustedAuthorizationVerifier] = None,
) -> None:
    """Check an existing report's label against its sources (e.g. before saving).

    Passes if the report is at least as restrictive as the strictest source.
    A report below that floor passes only if it is labelled DECLASSIFIED AND
    ``verifier`` confirms a trusted authorization bound to this report and the
    exact (strictest source -> report label) transition. A DECLASSIFIED label
    with an authorization id alone is not trusted.

    Raises:
        UnauthorizedDowngradeError: the label is below the strictest source.
        EmptySourcesError / MissingSourceMetadataError / ...: invalid sources.
    """
    refs = coerce_sources(sources)
    floor = strictest_classification(r.classification for r in refs)
    if report.classification >= floor:
        return
    reason = ChangeReason.DOWNGRADE_NO_AUTHORIZATION
    if report.label_origin.value == "DECLASSIFIED":
        reason = verify_downgrade_authorization(
            document_id=report.document_id,
            current=floor,
            requested=report.classification,
            authorization_id=report.declassification_authorization_id,
            verifier=verifier,
        )
        if reason == ChangeReason.DOWNGRADE_AUTHORIZED:
            return
    raise UnauthorizedDowngradeError(
        f"report {report.document_id!r} is {report.classification.value} but its sources "
        f"require at least {floor.value}: {reason.value}",
        reason=reason,
    )
