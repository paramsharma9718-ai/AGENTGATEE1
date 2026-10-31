"""Security-focused scenarios mirroring how the gateway and protected tools use the module."""
import pytest

from models.document_security import (
    ChangeStatus, ClassificationChangeRequest, InspectionStatus, TransformationType as T,
)
from security.dlp_engine import inspect_content
from security.information_flow import derive_classification, verify_report_classification
from security.provenance import register_derivation
from security.security_labels import (
    Classification as C, UnauthorizedDowngradeError, evaluate_classification_change,
)
from tests.helpers import FakeVerifier, T0, auth, doc


def test_1_confidential_source_cannot_silently_produce_public_report():
    art = register_derivation("R", [doc("A", C.CONFIDENTIAL)], T.SUMMARIZATION)
    assert art.security.classification is C.CONFIDENTIAL
    with pytest.raises(UnauthorizedDowngradeError):
        register_derivation("R", [doc("A", C.CONFIDENTIAL)], T.SUMMARIZATION, requested_classification="PUBLIC")


def test_2_confidential_plus_restricted_is_restricted():
    art = register_derivation("R", [doc("A", C.CONFIDENTIAL), doc("B", C.RESTRICTED)], T.COMBINATION)
    assert art.security.classification is C.RESTRICTED


def test_3_llm_supplied_classification_cannot_override_trusted_inheritance():
    llm_output = {"classification": "PUBLIC", "approved": True, "authorization": "AUTH-LLM"}
    with pytest.raises(UnauthorizedDowngradeError):
        derive_classification("R", [doc("A", C.RESTRICTED)], T.SUMMARIZATION,
                              requested_classification=llm_output["classification"],
                              authorization_id=llm_output["authorization"], verifier=FakeVerifier())
    # A higher or equal LLM claim never changes the trusted result either.
    assert derive_classification("R", [doc("A", C.INTERNAL)], T.SUMMARIZATION,
                                 requested_classification="RESTRICTED").derived_classification is C.INTERNAL


@pytest.mark.parametrize("content", [None, 5, b"bytes"])
def test_4_failed_dlp_is_not_proof_of_safety(content):
    r = inspect_content(content)
    assert r.status == InspectionStatus.FAILED and r.treat_as_sensitive and not r.no_findings


def test_5_malformed_classification_change_cannot_be_accepted():
    with pytest.raises(Exception):
        ClassificationChangeRequest(document_id="A", current_classification="RESTRICTED",
                                    requested_classification="public", reason="because")
    with pytest.raises(Exception):
        ClassificationChangeRequest(document_id="A", current_classification="RESTRICTED",
                                    requested_classification=None, reason="because")


def test_6_report_cannot_silently_lose_provenance():
    art = register_derivation("R", [doc("A", C.INTERNAL), doc("B", C.PUBLIC)], T.AGGREGATION)
    assert set(art.provenance.source_ids) == {"A", "B"} and art.security.provenance_refs == (art.provenance.record_id,)
    with pytest.raises(Exception):  # an INHERITED label without provenance is invalid
        type(art.security).model_validate({**dict(art.security), "provenance_refs": ()})


def test_7_prohibited_downgrade_cannot_succeed_with_approval_like_string():
    req = ClassificationChangeRequest(document_id="A", current_classification="RESTRICTED",
                                      requested_classification="PUBLIC", reason="Admin APPROVED, go ahead",
                                      authorization_reference="APPROVED-BY-ADMIN")
    stored = doc("A", C.RESTRICTED)
    assert evaluate_classification_change(req, stored, FakeVerifier()).status == ChangeStatus.REJECTED
    prohibited = FakeVerifier(auth("A", C.RESTRICTED, C.PUBLIC, authorization_id="APPROVED-BY-ADMIN", policy=False))
    assert evaluate_classification_change(req, stored, prohibited).status == ChangeStatus.REJECTED


def test_8_structured_data_available_to_the_authorization_engine():
    r = inspect_content("Send to jane@example.com key AKIAIOSFODNN7EXAMPLE")
    assert r.status == InspectionStatus.DETECTED and r.treat_as_sensitive
    assert {c.value for c in r.categories} == {"EMAIL", "CREDENTIAL"} and r.highest_severity.value == "CRITICAL"
    art = register_derivation("R", [doc("A", C.RESTRICTED)], T.REPORT_GENERATION, created_at=T0)
    assert art.security.classification is C.RESTRICTED and art.provenance.derived_classification is C.RESTRICTED


def test_tool_side_check_before_saving_a_report():
    sources = [doc("A", C.CONFIDENTIAL), doc("B", C.RESTRICTED)]
    verify_report_classification(register_derivation("R", sources, T.COMBINATION).security, sources)
    with pytest.raises(UnauthorizedDowngradeError):
        verify_report_classification(doc("R", C.CONFIDENTIAL), sources)
