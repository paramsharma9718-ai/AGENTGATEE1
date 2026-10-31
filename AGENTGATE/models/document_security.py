"""Validated security metadata models for AGENTGATE Module 02.

All models are immutable (``frozen``) and reject unknown fields so malformed or
tampered metadata fails loudly. Identifiers and timestamps follow these
conventions (no shared project contract existed when this module was written):

* IDs: 1-128 chars, ``[A-Za-z0-9._:-]``, starting with an alphanumeric.
* Timestamps: timezone-aware, normalised to UTC. Naive datetimes are rejected.

Import direction: this module imports :class:`Classification` from
``security.security_labels``; that module imports these models lazily.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Dict, List, Optional, Tuple

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from security.security_labels import Classification, parse_classification, strictest_classification

# --------------------------------------------------------------------------- #
# Shared field types
# --------------------------------------------------------------------------- #
_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
SecurityId = Annotated[str, StringConstraints(pattern=_ID_PATTERN)]
"""Identifier for documents, reports, provenance records and authorizations."""


def utc_now() -> datetime:
    """Current time as an aware UTC datetime."""
    return datetime.now(timezone.utc)


def _require_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


UtcDatetime = Annotated[datetime, AfterValidator(_require_aware_utc)]
ClassificationField = Annotated[Classification, BeforeValidator(parse_classification)]
"""A classification parsed strictly (exact upper-case name or enum member)."""


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class LabelOrigin(str, Enum):
    """How a document's current label was established."""

    ASSIGNED = "ASSIGNED"  # set directly by trusted code/policy for original content
    INHERITED = "INHERITED"  # computed from source documents
    DECLASSIFIED = "DECLASSIFIED"  # lowered through an authorized downgrade


class TransformationType(str, Enum):
    """Kinds of derivation. All of them inherit; none lowers a classification."""

    SUMMARIZATION = "SUMMARIZATION"
    TRANSFORMATION = "TRANSFORMATION"
    AGGREGATION = "AGGREGATION"
    REPORT_GENERATION = "REPORT_GENERATION"
    COMBINATION = "COMBINATION"


class Severity(str, Enum):
    """DLP finding severity. Ordering is explicit via :attr:`rank`."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[self.value]


class DLPCategory(str, Enum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    PII = "PII"
    FINANCIAL = "FINANCIAL"
    CREDENTIAL = "CREDENTIAL"
    CONFIDENTIAL_PATTERN = "CONFIDENTIAL_PATTERN"


class InspectionStatus(str, Enum):
    """Three distinct outcomes. NOT_DETECTED is *not* proof content is safe."""

    DETECTED = "DETECTED"
    NOT_DETECTED = "NOT_DETECTED"
    FAILED = "FAILED"


class DLPErrorCode(str, Enum):
    INVALID_INPUT_TYPE = "INVALID_INPUT_TYPE"
    CONTENT_TOO_LARGE = "CONTENT_TOO_LARGE"
    RULE_EXECUTION_ERROR = "RULE_EXECUTION_ERROR"


class ChangeStatus(str, Enum):
    PENDING = "PENDING"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


class RequestOrigin(str, Enum):
    """Who proposed a change. Recorded for audit; never grants authority."""

    USER = "USER"
    AI_AGENT = "AI_AGENT"
    SYSTEM = "SYSTEM"


class ChangeReason(str, Enum):
    """Machine-readable outcome reasons for classification changes."""

    RESTRICTION_INCREASED = "RESTRICTION_INCREASED"
    DOWNGRADE_AUTHORIZED = "DOWNGRADE_AUTHORIZED"
    DOWNGRADE_NO_AUTHORIZATION = "DOWNGRADE_NO_AUTHORIZATION"
    NO_VERIFIER_CONFIGURED = "NO_VERIFIER_CONFIGURED"
    AUTHORIZATION_NOT_FOUND = "AUTHORIZATION_NOT_FOUND"
    AUTHORIZATION_MISMATCH = "AUTHORIZATION_MISMATCH"
    AUTHORIZATION_NOT_GRANTED = "AUTHORIZATION_NOT_GRANTED"
    POLICY_PROHIBITS_DOWNGRADE = "POLICY_PROHIBITS_DOWNGRADE"
    AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
    VERIFIER_ERROR = "VERIFIER_ERROR"
    DOCUMENT_MISMATCH = "DOCUMENT_MISMATCH"
    STALE_CURRENT_CLASSIFICATION = "STALE_CURRENT_CLASSIFICATION"
    REQUEST_NOT_PENDING = "REQUEST_NOT_PENDING"


# --------------------------------------------------------------------------- #
# Document security metadata
# --------------------------------------------------------------------------- #
class DocumentSecurityMetadata(_Model):
    """Security label and provenance pointers for a document or generated report.

    Attributes:
        document_id: Unique document/report identifier.
        classification: Current trusted classification.
        content_id: Optional content identifier (e.g. ``sha256-<hex>``) tying the
            label to specific content.
        created_at: Creation timestamp (UTC).
        label_origin: How the label was established.
        provenance_refs: IDs of provenance records describing this artifact.
            Required for INHERITED labels so derived content cannot silently
            lose its lineage.
        declassification_authorization_id: Trusted authorization that permitted
            a downgrade. Required for (and only valid with) DECLASSIFIED.
        metadata: Small free-form string map. Never used for security decisions.
    """

    document_id: SecurityId
    classification: ClassificationField
    content_id: Optional[SecurityId] = None
    created_at: UtcDatetime = Field(default_factory=utc_now)
    label_origin: LabelOrigin = LabelOrigin.ASSIGNED
    provenance_refs: Tuple[SecurityId, ...] = ()
    declassification_authorization_id: Optional[SecurityId] = None
    metadata: Dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_consistency(self) -> "DocumentSecurityMetadata":
        if len(set(self.provenance_refs)) != len(self.provenance_refs):
            raise ValueError("provenance_refs contains duplicates")
        if self.label_origin == LabelOrigin.INHERITED and not self.provenance_refs:
            raise ValueError("an INHERITED label requires provenance_refs")
        if self.label_origin == LabelOrigin.DECLASSIFIED:
            if self.declassification_authorization_id is None:
                raise ValueError("a DECLASSIFIED label requires declassification_authorization_id")
        elif self.declassification_authorization_id is not None:
            raise ValueError("declassification_authorization_id is only valid for DECLASSIFIED labels")
        if len(self.metadata) > 50 or any(
            len(k) > 256 or len(v) > 256 for k, v in self.metadata.items()
        ):
            raise ValueError("metadata exceeds size limits (50 keys, 256 chars each)")
        return self


# --------------------------------------------------------------------------- #
# DLP inspection results
# --------------------------------------------------------------------------- #
class DLPFinding(_Model):
    """One detected sensitive item. Never contains the sensitive value itself."""

    rule_id: str = Field(min_length=1, max_length=64)
    category: DLPCategory
    severity: Severity
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    line: int = Field(ge=1)
    confidence: float = Field(ge=0.0, le=1.0)
    redacted_preview: str = Field(max_length=128)

    @model_validator(mode="after")
    def _check_span(self) -> "DLPFinding":
        if self.end <= self.start:
            raise ValueError("finding span must have end > start")
        return self

    @property
    def length(self) -> int:
        return self.end - self.start


class DLPInspectionResult(_Model):
    """Structured DLP output for the authorization engine and protected tools.

    Consumers must branch on ``status``:

    * ``DETECTED``: sensitive patterns were found (see ``findings``).
    * ``NOT_DETECTED``: no configured rule matched. This is **not** proof the
      content is free of sensitive data (regex DLP is incomplete).
    * ``FAILED``: inspection did not complete; nothing is known about the content.

    Use :attr:`treat_as_sensitive` for fail-closed decisions: it is ``True`` for
    both DETECTED and FAILED.
    """

    status: InspectionStatus
    sensitive_content_detected: bool
    findings: Tuple[DLPFinding, ...] = ()
    categories: Tuple[DLPCategory, ...] = ()
    highest_severity: Optional[Severity] = None
    findings_truncated: bool = False
    content_length: int = Field(ge=0, default=0)
    rules_evaluated: int = Field(ge=0, default=0)
    error_code: Optional[DLPErrorCode] = None
    summary: str = Field(max_length=512)
    inspected_at: UtcDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _check_consistency(self) -> "DLPInspectionResult":
        cats = {f.category for f in self.findings}
        if self.status == InspectionStatus.DETECTED:
            if not self.findings or not self.sensitive_content_detected or self.error_code:
                raise ValueError("DETECTED requires findings, detected=True and no error_code")
            if set(self.categories) != cats:
                raise ValueError("categories must match findings")
            top = max(self.findings, key=lambda f: f.severity.rank).severity
            if self.highest_severity != top:
                raise ValueError("highest_severity must match findings")
        elif self.status == InspectionStatus.NOT_DETECTED:
            if self.findings or self.sensitive_content_detected or self.error_code or self.categories:
                raise ValueError("NOT_DETECTED must have no findings, categories or error_code")
            if self.highest_severity is not None:
                raise ValueError("NOT_DETECTED must not have a highest_severity")
        else:  # FAILED
            if self.error_code is None:
                raise ValueError("FAILED requires an error_code")
            if self.findings or self.sensitive_content_detected or self.categories:
                raise ValueError("FAILED must not report findings")
        return self

    @property
    def inspection_succeeded(self) -> bool:
        return self.status != InspectionStatus.FAILED

    @property
    def no_findings(self) -> bool:
        """True only if inspection completed and no rule matched (not proof of safety)."""
        return self.status == InspectionStatus.NOT_DETECTED

    @property
    def treat_as_sensitive(self) -> bool:
        """Fail-closed flag: True if sensitive data was found OR inspection failed."""
        return self.status != InspectionStatus.NOT_DETECTED


# --------------------------------------------------------------------------- #
# Provenance
# --------------------------------------------------------------------------- #
class SourceReference(_Model):
    """A source document and the classification it had when the derivation happened."""

    document_id: SecurityId
    classification: ClassificationField


class LineageLink(_Model):
    """One parent -> child edge in the lineage graph."""

    parent_id: SecurityId
    child_id: SecurityId


class ProvenanceRecord(_Model):
    """Immutable lineage record: source documents -> generated report.

    Self-consistency is validated on construction and on deserialisation: the
    parent/child links must match the sources and report exactly, and the
    derived classification may not be below the strictest source unless a
    declassification authorization id is recorded. (Authenticity of that id is
    verified at derivation time by ``information_flow``; persistence layers
    should store records as written and treat them as append-only.)
    """

    record_id: SecurityId
    report_id: SecurityId
    sources: Tuple[SourceReference, ...] = Field(min_length=1)
    derived_classification: ClassificationField
    transformation_type: TransformationType
    created_at: UtcDatetime
    parent_child_links: Tuple[LineageLink, ...]
    declassification_authorization_id: Optional[SecurityId] = None

    @model_validator(mode="after")
    def _check_consistency(self) -> "ProvenanceRecord":
        ids = [s.document_id for s in self.sources]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate source document ids")
        if self.report_id in ids:
            raise ValueError("a report cannot be its own source")
        expected = [(i, self.report_id) for i in ids]
        actual = [(l.parent_id, l.child_id) for l in self.parent_child_links]
        if actual != expected:
            raise ValueError("parent_child_links do not match sources and report_id")
        lowered = self.derived_classification < self.strictest_source_classification
        if lowered and self.declassification_authorization_id is None:
            raise ValueError("derived classification is below the strictest source without authorization")
        if not lowered and self.declassification_authorization_id is not None:
            raise ValueError("declassification authorization recorded but classification was not lowered")
        return self

    @property
    def source_ids(self) -> List[str]:
        return [s.document_id for s in self.sources]

    @property
    def original_classifications(self) -> Dict[str, Classification]:
        return {s.document_id: s.classification for s in self.sources}

    @property
    def strictest_source_classification(self) -> Classification:
        return strictest_classification(s.classification for s in self.sources)

    @property
    def was_declassified(self) -> bool:
        return self.declassification_authorization_id is not None


# --------------------------------------------------------------------------- #
# Classification change request / authorization / decision
# --------------------------------------------------------------------------- #
class ClassificationChangeRequest(_Model):
    """A *proposal* to change a document's classification. Carries no authority.

    ``authorization_reference`` is an opaque id resolved by a trusted
    verifier; the string itself proves nothing.
    """

    document_id: SecurityId
    current_classification: ClassificationField
    requested_classification: ClassificationField
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1000)]
    authorization_reference: Optional[SecurityId] = None
    origin: RequestOrigin = RequestOrigin.AI_AGENT
    status: ChangeStatus = ChangeStatus.PENDING
    requested_at: UtcDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _check_change(self) -> "ClassificationChangeRequest":
        if self.current_classification == self.requested_classification:
            raise ValueError("requested classification equals the current classification")
        return self


class TrustedAuthorizationResult(_Model):
    """Authorization outcome issued by the central authorization engine.

    Must be produced only by trusted code (via a ``TrustedAuthorizationVerifier``),
    never parsed from LLM or user-supplied content.

    Both flags are required: ``policy_permits`` says the policy allows this
    downgrade at all; ``approval_granted`` says an authorized approver agreed.
    An approval cannot override a policy that prohibits the downgrade.
    """

    authorization_id: SecurityId
    operation: str = Field(min_length=1, max_length=128)
    document_id: SecurityId
    from_classification: ClassificationField
    to_classification: ClassificationField
    approval_granted: bool
    policy_permits: bool
    issued_at: UtcDatetime = Field(default_factory=utc_now)
    expires_at: Optional[UtcDatetime] = None

    @model_validator(mode="after")
    def _check_expiry(self) -> "TrustedAuthorizationResult":
        if self.expires_at is not None and self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self


class ClassificationChangeDecision(_Model):
    """Structured outcome of evaluating a classification change."""

    document_id: SecurityId
    from_classification: ClassificationField
    to_classification: ClassificationField
    status: ChangeStatus
    reason: ChangeReason
    is_downgrade: bool
    authorization_id: Optional[SecurityId] = None
    decided_at: UtcDatetime

    @model_validator(mode="after")
    def _check(self) -> "ClassificationChangeDecision":
        if self.status == ChangeStatus.PENDING:
            raise ValueError("a decision cannot be PENDING")
        return self
