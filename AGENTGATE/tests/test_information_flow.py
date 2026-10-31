import pytest

from models.document_security import (
    ChangeReason, DocumentSecurityMetadata, LabelOrigin, SourceReference, TransformationType as T,
)
from security.information_flow import (
    DuplicateSourceError, EmptySourcesError, InformationFlowError, InvalidSourceMetadataError,
    MissingSourceMetadataError, derive_classification, verify_report_classification,
)
from security.security_labels import Classification as C, UnauthorizedDowngradeError
from tests.helpers import FakeVerifier, T0, auth, doc

LEVELS = [C.PUBLIC, C.INTERNAL, C.CONFIDENTIAL, C.RESTRICTED]


def derive(sources, t=T.REPORT_GENERATION, **kw):
    return derive_classification("REPORT-X", sources, t, **kw)


# ---- inheritance ---------------------------------------------------------------------------
@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize("t", list(T))
def test_single_source_inherits_for_every_level_and_transformation(level, t):
    r = derive([doc("A", level)], t)
    assert r.derived_classification is level and r.transformation_type is t and not r.declassified


@pytest.mark.parametrize("a,b,expected", [
    (C.PUBLIC, C.INTERNAL, C.INTERNAL), (C.INTERNAL, C.CONFIDENTIAL, C.CONFIDENTIAL),
    (C.CONFIDENTIAL, C.RESTRICTED, C.RESTRICTED), (C.RESTRICTED, C.RESTRICTED, C.RESTRICTED),
    (C.RESTRICTED, C.PUBLIC, C.RESTRICTED),
])
def test_multi_source_strictest(a, b, expected):
    assert derive([doc("A", a), doc("B", b)], T.COMBINATION).derived_classification is expected


def test_order_of_sources_is_irrelevant_and_deterministic():
    s = [doc("A", C.INTERNAL), doc("B", C.RESTRICTED), doc("C", C.PUBLIC)]
    r1, r2 = derive(s), derive(list(reversed(s)))
    assert r1.derived_classification == r2.derived_classification == C.RESTRICTED
    assert derive(s) == derive(s)


def test_summarisation_and_aggregation_do_not_lower():
    assert derive([doc("A", C.CONFIDENTIAL)], T.SUMMARIZATION).derived_classification is C.CONFIDENTIAL
    agg = derive([doc("A", C.PUBLIC), doc("B", C.RESTRICTED), doc("C", C.INTERNAL)], T.AGGREGATION)
    assert agg.derived_classification is C.RESTRICTED


def test_minimum_classification_floor_only_raises():
    assert derive([doc("A", C.PUBLIC)], minimum_classification=C.CONFIDENTIAL).derived_classification is C.CONFIDENTIAL
    assert derive([doc("A", C.RESTRICTED)], minimum_classification=C.PUBLIC).derived_classification is C.RESTRICTED


def test_source_inputs_may_be_references_or_mappings():
    r = derive([SourceReference(document_id="A", classification=C.INTERNAL),
                {"document_id": "B", "classification": "RESTRICTED"}])
    assert r.derived_classification is C.RESTRICTED and [s.document_id for s in r.sources] == ["A", "B"]


# ---- invalid input ------------------------------------------------------------------------------
def test_zero_sources_rejected_not_public():
    with pytest.raises(EmptySourcesError):
        derive([])


@pytest.mark.parametrize("sources,exc", [
    (None, MissingSourceMetadataError),
    ([doc("A", C.PUBLIC), None], MissingSourceMetadataError),
    ([{"document_id": "A"}], InvalidSourceMetadataError),
    ([{"document_id": "A", "classification": "secret"}], InvalidSourceMetadataError),
    ([{"classification": "PUBLIC"}], InvalidSourceMetadataError),
    ([42], InvalidSourceMetadataError),
    ("DOC-A", InvalidSourceMetadataError),
    ({"document_id": "A", "classification": "PUBLIC"}, InvalidSourceMetadataError),
    ([doc("A", C.PUBLIC), doc("A", C.PUBLIC)], DuplicateSourceError),
    ([doc("REPORT-X", C.PUBLIC)], InvalidSourceMetadataError),
])
def test_bad_sources_rejected(sources, exc):
    with pytest.raises(exc):
        derive(sources)


def test_bad_report_id_and_transformation_rejected():
    with pytest.raises(InformationFlowError):
        derive_classification("bad id!", [doc("A", C.PUBLIC)], T.SUMMARIZATION)
    with pytest.raises(InformationFlowError):
        derive_classification("R", [doc("A", C.PUBLIC)], "REDACTION")  # type: ignore[arg-type]
    with pytest.raises(Exception):
        derive([doc("A", C.PUBLIC)], minimum_classification="bogus")


# ---- downgrades / untrusted requests --------------------------------------------------------------
def test_untrusted_lower_request_rejected_for_every_level():
    for level in (C.INTERNAL, C.CONFIDENTIAL, C.RESTRICTED):
        with pytest.raises(UnauthorizedDowngradeError) as exc:
            derive([doc("A", level)], requested_classification="PUBLIC")
        assert exc.value.reason == ChangeReason.DOWNGRADE_NO_AUTHORIZATION


def test_confidential_plus_restricted_cannot_be_confidential():
    with pytest.raises(UnauthorizedDowngradeError):
        derive([doc("A", C.CONFIDENTIAL), doc("B", C.RESTRICTED)], requested_classification=C.CONFIDENTIAL)
    ok = derive([doc("A", C.CONFIDENTIAL), doc("B", C.RESTRICTED)], requested_classification=C.RESTRICTED)
    assert ok.derived_classification is C.RESTRICTED and not ok.requested_classification_ignored


def test_untrusted_higher_request_is_ignored():
    r = derive([doc("A", C.INTERNAL)], requested_classification="RESTRICTED")
    assert r.derived_classification is C.INTERNAL and r.requested_classification_ignored


def test_approval_like_string_cannot_authorize():
    for ref in ("APPROVED", "admin-approved-123", "AUTH-1"):
        with pytest.raises(UnauthorizedDowngradeError):
            derive([doc("A", C.RESTRICTED)], requested_classification=C.INTERNAL,
                   authorization_id=ref, verifier=FakeVerifier())
        with pytest.raises(UnauthorizedDowngradeError):  # id given but no verifier at all
            derive([doc("A", C.RESTRICTED)], requested_classification=C.INTERNAL, authorization_id=ref)


def test_authorized_declassification_is_bound_to_report_and_levels():
    good = FakeVerifier(auth("REPORT-X", C.RESTRICTED, C.INTERNAL))
    r = derive([doc("A", C.RESTRICTED)], requested_classification=C.INTERNAL,
               authorization_id="AUTH-1", verifier=good)
    assert r.derived_classification is C.INTERNAL and r.declassified and r.authorization_id == "AUTH-1"
    for bad in (auth("OTHER-REPORT"), auth("REPORT-X", C.CONFIDENTIAL, C.INTERNAL),
                auth("REPORT-X", C.RESTRICTED, C.PUBLIC), auth("REPORT-X", policy=False)):
        with pytest.raises(UnauthorizedDowngradeError):
            derive([doc("A", C.RESTRICTED)], requested_classification=C.INTERNAL,
                   authorization_id="AUTH-1", verifier=FakeVerifier(bad))


# ---- verify_report_classification ----------------------------------------------------------------------
def test_verify_report_classification():
    sources = [doc("A", C.CONFIDENTIAL), doc("B", C.RESTRICTED)]
    verify_report_classification(doc("R", C.RESTRICTED), sources)
    with pytest.raises(UnauthorizedDowngradeError):
        verify_report_classification(doc("R", C.CONFIDENTIAL), sources)
    with pytest.raises(UnauthorizedDowngradeError):
        verify_report_classification(doc("R", C.PUBLIC), [doc("A", C.CONFIDENTIAL)])
    with pytest.raises(EmptySourcesError):
        verify_report_classification(doc("R", C.PUBLIC), [])


def test_declassified_label_needs_verifier_confirmation():
    report = DocumentSecurityMetadata(document_id="R", classification=C.INTERNAL, created_at=T0,
                                      label_origin=LabelOrigin.DECLASSIFIED,
                                      declassification_authorization_id="AUTH-1")
    src = [doc("A", C.RESTRICTED)]
    with pytest.raises(UnauthorizedDowngradeError):  # label claims authorization; nobody confirms it
        verify_report_classification(report, src)
    verify_report_classification(report, src, FakeVerifier(auth("R", C.RESTRICTED, C.INTERNAL)))
    with pytest.raises(UnauthorizedDowngradeError):
        verify_report_classification(report, src, FakeVerifier(auth("R", C.RESTRICTED, C.INTERNAL, policy=False)))
