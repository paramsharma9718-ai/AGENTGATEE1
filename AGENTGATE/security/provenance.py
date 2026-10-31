"""Information lineage and provenance.

Provides:

* :func:`register_derivation`: the single recommended entry point. It computes
  the trusted classification (via ``information_flow``) and returns the report's
  security metadata together with its provenance record, so labels and lineage
  are created together and cannot drift apart.
* :class:`ProvenanceGraph`: an in-memory validator/index over records. It is
  NOT a storage layer; the persistence module stores ``record.model_dump(mode="json")``
  and may rebuild a graph with :meth:`ProvenanceGraph.from_records`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from pydantic import BaseModel, ConfigDict

from models.document_security import (
    DocumentSecurityMetadata,
    LabelOrigin,
    LineageLink,
    ProvenanceRecord,
    TransformationType,
    utc_now,
)
from security.information_flow import DerivationResult, SourceInput, derive_classification
from security.security_labels import Classification, SecurityLabelError, TrustedAuthorizationVerifier


class ProvenanceError(SecurityLabelError, ValueError):
    """Inconsistent lineage (cycles, duplicate reports, label mismatches)."""


class DerivedArtifact(BaseModel):
    """Everything a save/delivery tool needs about a generated report."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    security: DocumentSecurityMetadata
    provenance: ProvenanceRecord
    derivation: DerivationResult


def new_record_id() -> str:
    return f"PROV-{uuid.uuid4().hex}"


def register_derivation(
    report_id: str,
    sources: Optional[Sequence[SourceInput]],
    transformation_type: TransformationType,
    *,
    created_at: Optional[datetime] = None,
    record_id: Optional[str] = None,
    content_id: Optional[str] = None,
    metadata: Optional[Dict[str, str]] = None,
    minimum_classification: Optional[Classification] = None,
    requested_classification: Any = None,
    authorization_id: Optional[str] = None,
    verifier: Optional[TrustedAuthorizationVerifier] = None,
) -> DerivedArtifact:
    """Derive a report's trusted label and create its provenance record.

    ``requested_classification`` is untrusted (e.g. LLM-proposed); see
    :func:`security.information_flow.derive_classification` for how it is handled.
    Pass ``created_at`` / ``record_id`` for deterministic output in tests.
    """
    derivation = derive_classification(
        report_id,
        sources,
        transformation_type,
        minimum_classification=minimum_classification,
        requested_classification=requested_classification,
        authorization_id=authorization_id,
        verifier=verifier,
    )
    ts = created_at or utc_now()
    rid = record_id or new_record_id()

    record = ProvenanceRecord(
        record_id=rid,
        report_id=derivation.report_id,
        sources=derivation.sources,
        derived_classification=derivation.derived_classification,
        transformation_type=derivation.transformation_type,
        created_at=ts,
        parent_child_links=tuple(
            LineageLink(parent_id=s.document_id, child_id=derivation.report_id)
            for s in derivation.sources
        ),
        declassification_authorization_id=derivation.authorization_id,
    )
    security = DocumentSecurityMetadata(
        document_id=derivation.report_id,
        classification=derivation.derived_classification,
        content_id=content_id,
        created_at=ts,
        label_origin=LabelOrigin.DECLASSIFIED if derivation.declassified else LabelOrigin.INHERITED,
        provenance_refs=(rid,),
        declassification_authorization_id=derivation.authorization_id,
        metadata=metadata or {},
    )
    return DerivedArtifact(security=security, provenance=record, derivation=derivation)


class ProvenanceGraph:
    """In-memory lineage index with integrity checks.

    On :meth:`add` it rejects: duplicate record ids, a second record for the
    same report (no silent overwrite of lineage), cycles, a source whose
    recorded classification differs from that source's own derived label, and a
    child created before its parent.
    """

    def __init__(self, records: Iterable[ProvenanceRecord] = ()) -> None:
        self._by_report: Dict[str, ProvenanceRecord] = {}
        self._record_ids: set[str] = set()
        self._children: Dict[str, List[str]] = {}
        for record in records:
            self.add(record)

    @classmethod
    def from_records(cls, records: Iterable[Mapping[str, Any] | ProvenanceRecord]) -> "ProvenanceGraph":
        """Rebuild from persisted dicts/records. Order is irrelevant."""
        parsed = [
            r if isinstance(r, ProvenanceRecord) else ProvenanceRecord.model_validate(r)
            for r in records
        ]
        graph = cls()
        pending = list(parsed)
        while pending:
            progressed = False
            for rec in list(pending):
                if all(s.document_id not in {p.report_id for p in pending if p is not rec} for s in rec.sources):
                    graph.add(rec)
                    pending.remove(rec)
                    progressed = True
            if not progressed:
                raise ProvenanceError("cycle detected among provenance records")
        return graph

    def add(self, record: ProvenanceRecord) -> None:
        if record.record_id in self._record_ids:
            raise ProvenanceError(f"duplicate provenance record id {record.record_id!r}")
        if record.report_id in self._by_report:
            raise ProvenanceError(f"report {record.report_id!r} already has a provenance record")
        for src in record.sources:
            parent = self._by_report.get(src.document_id)
            if parent is None:
                continue  # root document: no record, nothing to cross-check
            if parent.derived_classification != src.classification:
                raise ProvenanceError(
                    f"source {src.document_id!r} recorded as {src.classification.value} but its "
                    f"own label is {parent.derived_classification.value}"
                )
            if record.created_at < parent.created_at:
                raise ProvenanceError(f"report {record.report_id!r} predates its source {src.document_id!r}")
        if self._creates_cycle(record):
            raise ProvenanceError(f"record for {record.report_id!r} would create a cycle")
        self._record_ids.add(record.record_id)
        self._by_report[record.report_id] = record
        for src in record.sources:
            self._children.setdefault(src.document_id, []).append(record.report_id)

    def _creates_cycle(self, record: ProvenanceRecord) -> bool:
        # A cycle exists if the new report is an ancestor of any of its sources.
        stack = [s.document_id for s in record.sources]
        seen: set[str] = set()
        while stack:
            node = stack.pop()
            if node == record.report_id:
                return True
            if node in seen:
                continue
            seen.add(node)
            rec = self._by_report.get(node)
            if rec:
                stack.extend(rec.source_ids)
        return False

    def get(self, report_id: str) -> Optional[ProvenanceRecord]:
        return self._by_report.get(report_id)

    def parents_of(self, document_id: str) -> List[str]:
        rec = self._by_report.get(document_id)
        return rec.source_ids if rec else []

    def children_of(self, document_id: str) -> List[str]:
        return list(self._children.get(document_id, []))

    def ancestors_of(self, document_id: str) -> List[str]:
        """All transitive sources of ``document_id`` (deterministic order)."""
        out: List[str] = []
        stack = list(reversed(self.parents_of(document_id)))
        seen: set[str] = set()
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            out.append(node)
            stack.extend(reversed(self.parents_of(node)))
        return out

    def root_sources_of(self, document_id: str) -> List[str]:
        """Ancestors that have no provenance record of their own (original documents)."""
        return [a for a in self.ancestors_of(document_id) if a not in self._by_report]

    def records(self) -> List[ProvenanceRecord]:
        return list(self._by_report.values())

    def to_serializable(self) -> List[Dict[str, Any]]:
        """JSON-compatible records for the persistence layer."""
        return [r.model_dump(mode="json") for r in self._by_report.values()]
