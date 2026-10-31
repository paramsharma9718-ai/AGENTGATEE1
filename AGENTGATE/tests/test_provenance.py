import json
from datetime import timedelta

import pytest
from pydantic import ValidationError

from models.document_security import (
    LabelOrigin, LineageLink, ProvenanceRecord, SourceReference, TransformationType as T,
)
from security.provenance import ProvenanceError, ProvenanceGraph, register_derivation
from security.information_flow import EmptySourcesError
from security.security_labels import Classification as C
from tests.helpers import FakeVerifier, T0, auth, doc


def make(report, sources, t=T.REPORT_GENERATION, ts=T0, rid=None, **kw):
    return register_derivation(report, sources, t, created_at=ts, record_id=rid or f"PROV-{report}", **kw)


def test_single_source_derivation():
    a = make("REPORT-1", [doc("DOC-A", C.CONFIDENTIAL)], T.SUMMARIZATION)
    p = a.provenance
    assert p.report_id == "REPORT-1" and p.source_ids == ["DOC-A"]
    assert p.original_classifications == {"DOC-A": C.CONFIDENTIAL}
    assert p.derived_classification is C.CONFIDENTIAL and p.transformation_type is T.SUMMARIZATION
    assert p.parent_child_links == (LineageLink(parent_id="DOC-A", child_id="REPORT-1"),)
    assert p.created_at == T0 and not p.was_declassified


def test_multi_source_derivation_example_from_spec():
    a = make("REPORT-X", [doc("DOC-A", C.CONFIDENTIAL), doc("DOC-B", C.RESTRICTED)], T.COMBINATION)
    p = a.provenance
    assert p.source_ids == ["DOC-A", "DOC-B"]
    assert p.original_classifications == {"DOC-A": C.CONFIDENTIAL, "DOC-B": C.RESTRICTED}
    assert p.derived_classification is C.RESTRICTED
    assert [(l.parent_id, l.child_id) for l in p.parent_child_links] == [("DOC-A", "REPORT-X"), ("DOC-B", "REPORT-X")]
    s = a.security
    assert s.document_id == "REPORT-X" and s.classification is C.RESTRICTED
    assert s.label_origin == LabelOrigin.INHERITED and s.provenance_refs == (p.record_id,)
    assert a.derivation.derived_classification is C.RESTRICTED


def test_record_is_deterministic_with_injected_ids_and_time():
    s = [doc("DOC-A", C.INTERNAL)]
    assert make("R", s).model_dump() == make("R", s).model_dump()


def test_default_record_ids_are_unique_and_valid():
    a = register_derivation("R1", [doc("A", C.PUBLIC)], T.SUMMARIZATION)
    b = register_derivation("R2", [doc("A", C.PUBLIC)], T.SUMMARIZATION)
    assert a.provenance.record_id != b.provenance.record_id


def test_empty_sources_and_bad_transformation_rejected():
    with pytest.raises(EmptySourcesError):
        make("R", [])
    with pytest.raises(Exception):
        make("R", [doc("A", C.PUBLIC)], "REDACTION")


def test_authorized_declassification_is_recorded():
    a = make("REPORT-X", [doc("A", C.RESTRICTED)], requested_classification=C.INTERNAL,
             authorization_id="AUTH-1", verifier=FakeVerifier(auth("REPORT-X", C.RESTRICTED, C.INTERNAL)))
    assert a.provenance.was_declassified and a.provenance.original_classifications["A"] is C.RESTRICTED
    assert a.security.label_origin == LabelOrigin.DECLASSIFIED


# ---- serialisation -------------------------------------------------------------------------------
def test_json_round_trip():
    a = make("REPORT-X", [doc("DOC-A", C.CONFIDENTIAL), doc("DOC-B", C.RESTRICTED)], T.AGGREGATION)
    text = json.dumps(a.provenance.model_dump(mode="json"))
    assert "RESTRICTED" in text and "AGGREGATION" in text
    assert ProvenanceRecord.model_validate(json.loads(text)) == a.provenance
    assert ProvenanceRecord.model_validate_json(a.provenance.model_dump_json()) == a.provenance


# ---- inconsistent metadata rejected --------------------------------------------------------------
def base_fields(**over):
    d = dict(record_id="PROV-1", report_id="R", sources=[SourceReference(document_id="A", classification=C.CONFIDENTIAL)],
             derived_classification=C.CONFIDENTIAL, transformation_type=T.SUMMARIZATION, created_at=T0,
             parent_child_links=[LineageLink(parent_id="A", child_id="R")])
    d.update(over)
    return d


@pytest.mark.parametrize("over", [
    dict(derived_classification=C.PUBLIC),                                   # lowered, no authorization
    dict(declassification_authorization_id="AUTH-1"),                        # auth but not lowered
    dict(sources=[]),                                                        # no sources
    dict(parent_child_links=[]),                                             # link lost
    dict(parent_child_links=[LineageLink(parent_id="A", child_id="OTHER")]), # wrong child
    dict(parent_child_links=[LineageLink(parent_id="Z", child_id="R")]),     # wrong parent
    dict(report_id="A"),                                                     # self-derived
    dict(created_at="2026-01-01T00:00:00"),                                  # naive timestamp
    dict(transformation_type="REDACTION"),
    dict(derived_classification="secret"),
    dict(extra_field=1),
    dict(sources=[SourceReference(document_id="A", classification=C.PUBLIC)] * 2,
         parent_child_links=[LineageLink(parent_id="A", child_id="R")] * 2),  # duplicate source
])
def test_inconsistent_records_rejected(over):
    with pytest.raises(ValidationError):
        ProvenanceRecord(**base_fields(**over))


def test_tampered_serialised_record_rejected():
    data = make("R", [doc("A", C.RESTRICTED)]).provenance.model_dump(mode="json")
    data["derived_classification"] = "PUBLIC"
    with pytest.raises(ValidationError):
        ProvenanceRecord.model_validate(data)


# ---- graph ------------------------------------------------------------------------------------------
def test_graph_lineage_queries():
    r1 = make("R1", [doc("A", C.CONFIDENTIAL), doc("B", C.INTERNAL)], T.COMBINATION)
    r2 = make("R2", [r1.security, doc("C", C.PUBLIC)], T.SUMMARIZATION, ts=T0 + timedelta(minutes=1))
    g = ProvenanceGraph([r1.provenance, r2.provenance])
    assert r2.security.classification is C.CONFIDENTIAL
    assert g.parents_of("R2") == ["R1", "C"] and g.children_of("A") == ["R1"]
    assert g.ancestors_of("R2") == ["R1", "A", "B", "C"]
    assert g.root_sources_of("R2") == ["A", "B", "C"]
    assert g.get("R1") == r1.provenance and g.get("A") is None


def test_graph_rejects_duplicates_cycles_and_label_mismatch():
    r1 = make("R1", [doc("A", C.RESTRICTED)])
    g = ProvenanceGraph([r1.provenance])
    with pytest.raises(ProvenanceError):                       # same record id
        g.add(r1.provenance)
    with pytest.raises(ProvenanceError):                       # second record for the same report
        g.add(make("R1", [doc("B", C.PUBLIC)], rid="PROV-OTHER").provenance)
    stale = make("R2", [doc("R1", C.INTERNAL)], ts=T0 + timedelta(minutes=1))   # claims R1 was INTERNAL
    with pytest.raises(ProvenanceError):
        g.add(stale.provenance)
    early = make("R3", [r1.security], ts=T0 - timedelta(days=1))
    with pytest.raises(ProvenanceError):
        g.add(early.provenance)
    cyc = make("A", [r1.security], ts=T0 + timedelta(minutes=2))                # A -> R1 -> A
    with pytest.raises(ProvenanceError):
        g.add(cyc.provenance)


def test_graph_from_persisted_records_any_order():
    r1 = make("R1", [doc("A", C.INTERNAL)])
    r2 = make("R2", [r1.security], ts=T0 + timedelta(minutes=1))
    g = ProvenanceGraph.from_records(reversed(ProvenanceGraph([r1.provenance, r2.provenance]).to_serializable()))
    assert g.ancestors_of("R2") == ["R1", "A"]
