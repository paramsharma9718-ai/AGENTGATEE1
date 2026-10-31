from datetime import timedelta

import pytest
from pydantic import ValidationError

from models.document_security import (
    ChangeReason, ChangeStatus, ClassificationChangeRequest, DocumentSecurityMetadata, LabelOrigin,
)
from security.security_labels import (
    Classification as C, EmptyClassificationSetError, InvalidClassificationError,
    UnauthorizedDowngradeError, apply_classification_change, compare_classifications,
    evaluate_classification_change, is_downgrade, parse_classification, strictest_classification,
    validate_classification_change,
)
from tests.helpers import FUTURE, T0, FakeVerifier, auth, doc

LEVELS = [C.PUBLIC, C.INTERNAL, C.CONFIDENTIAL, C.RESTRICTED]


@pytest.mark.parametrize("level", LEVELS)
def test_each_level_parses(level):
    assert parse_classification(level) is level and parse_classification(level.value) is level


def test_explicit_ordering_not_alphabetical():
    assert sorted(["RESTRICTED", "PUBLIC", "CONFIDENTIAL", "INTERNAL"], key=lambda s: C[s].rank) == \
        ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
    # Alphabetically CONFIDENTIAL < INTERNAL, but security order says otherwise.
    assert C.INTERNAL < C.CONFIDENTIAL and C.CONFIDENTIAL < C.RESTRICTED and C.PUBLIC < C.INTERNAL
    assert C.RESTRICTED > C.INTERNAL and C.PUBLIC <= C.PUBLIC and C.RESTRICTED >= C.CONFIDENTIAL
    assert max(C.INTERNAL, C.CONFIDENTIAL) is C.CONFIDENTIAL


@pytest.mark.parametrize("bad", [None, "", "public", " PUBLIC", "SECRET", 1, True, 2.5, [], "PUBLIC\n"])
def test_invalid_classifications_rejected(bad):
    with pytest.raises(InvalidClassificationError):
        parse_classification(bad)


def test_strictest_and_empty():
    assert strictest_classification([C.PUBLIC, C.INTERNAL]) is C.INTERNAL
    assert strictest_classification(["CONFIDENTIAL", "RESTRICTED"]) is C.RESTRICTED
    assert strictest_classification([C.PUBLIC]) is C.PUBLIC
    with pytest.raises(EmptyClassificationSetError):
        strictest_classification([])
    with pytest.raises(InvalidClassificationError):
        strictest_classification([C.PUBLIC, "bogus"])
    with pytest.raises(InvalidClassificationError):
        strictest_classification("PUBLIC")


def test_compare_and_is_downgrade():
    assert compare_classifications(C.PUBLIC, C.RESTRICTED) == -1
    assert compare_classifications("INTERNAL", C.INTERNAL) == 0
    assert is_downgrade(C.RESTRICTED, C.INTERNAL) and not is_downgrade(C.INTERNAL, C.RESTRICTED)


# ---- metadata model validation ---------------------------------------------------------
def test_metadata_rejects_malformed():
    for kwargs in [
        dict(document_id="bad id", classification="PUBLIC"),
        dict(document_id="A", classification="public"),
        dict(document_id="A", classification="PUBLIC", unknown_field=1),
        dict(document_id="A", classification="PUBLIC", created_at="2026-01-01T00:00:00"),  # naive
        dict(document_id="A", classification="PUBLIC", label_origin="INHERITED"),  # no provenance
        dict(document_id="A", classification="PUBLIC", label_origin="DECLASSIFIED"),  # no auth id
        dict(document_id="A", classification="PUBLIC", declassification_authorization_id="AUTH-1"),
        dict(document_id="A", classification="PUBLIC", provenance_refs=("P1", "P1")),
    ]:
        with pytest.raises(ValidationError):
            DocumentSecurityMetadata(**kwargs)


def test_metadata_is_immutable_and_normalises_to_utc():
    d = doc("A", C.PUBLIC)
    with pytest.raises(ValidationError):
        d.classification = C.RESTRICTED
    assert d.created_at.utcoffset() == timedelta(0)


# ---- classification change validation ----------------------------------------------------
def req(doc_id="A", cur=C.CONFIDENTIAL, new=C.PUBLIC, **kw):
    return ClassificationChangeRequest(document_id=doc_id, current_classification=cur,
                                       requested_classification=new, reason="needs sharing", **kw)


def test_request_model_validation():
    with pytest.raises(ValidationError):
        req(cur=C.PUBLIC, new=C.PUBLIC)
    with pytest.raises(ValidationError):
        ClassificationChangeRequest(document_id="A", current_classification="PUBLIC",
                                    requested_classification="SECRET", reason="x")
    with pytest.raises(ValidationError):
        req().__class__(document_id="A", current_classification="PUBLIC",
                        requested_classification="INTERNAL", reason="   ")


@pytest.mark.parametrize("cur,new", [(C.CONFIDENTIAL, C.PUBLIC), (C.RESTRICTED, C.INTERNAL)])
def test_unauthorized_downgrades_rejected(cur, new):
    d = evaluate_classification_change(req(cur=cur, new=new), doc("A", cur))
    assert d.status == ChangeStatus.REJECTED and d.is_downgrade
    assert d.reason == ChangeReason.DOWNGRADE_NO_AUTHORIZATION
    with pytest.raises(UnauthorizedDowngradeError) as exc:
        validate_classification_change(req(cur=cur, new=new), doc("A", cur))
    assert exc.value.reason == ChangeReason.DOWNGRADE_NO_AUTHORIZATION


def test_upgrade_accepted_without_authorization():
    d = validate_classification_change(req(cur=C.INTERNAL, new=C.RESTRICTED), doc("A", C.INTERNAL))
    assert d.status == ChangeStatus.ACCEPTED and not d.is_downgrade


def test_authorized_downgrade_accepted_and_applied():
    current = doc("A", C.RESTRICTED)
    v = FakeVerifier(auth("A", C.RESTRICTED, C.INTERNAL, expires_at=FUTURE))
    r = req(cur=C.RESTRICTED, new=C.INTERNAL, authorization_reference="AUTH-1")
    updated = apply_classification_change(r, current, v, now=T0)
    assert updated.classification is C.INTERNAL and updated.label_origin == LabelOrigin.DECLASSIFIED
    assert updated.declassification_authorization_id == "AUTH-1"
    assert current.classification is C.RESTRICTED  # original untouched


@pytest.mark.parametrize("label,verifier,reason", [
    ("approval-like string without verifier", None, ChangeReason.NO_VERIFIER_CONFIGURED),
    ("unknown id", FakeVerifier(), ChangeReason.AUTHORIZATION_NOT_FOUND),
    ("wrong doc", FakeVerifier(auth("OTHER")), ChangeReason.AUTHORIZATION_MISMATCH),
    ("wrong target", FakeVerifier(auth("A", C.RESTRICTED, C.CONFIDENTIAL)), ChangeReason.AUTHORIZATION_MISMATCH),
    ("wrong source", FakeVerifier(auth("A", C.CONFIDENTIAL, C.INTERNAL)), ChangeReason.AUTHORIZATION_MISMATCH),
    ("wrong operation", FakeVerifier(auth("A", operation="document.read")), ChangeReason.AUTHORIZATION_MISMATCH),
    ("not approved", FakeVerifier(auth("A", approval=False)), ChangeReason.AUTHORIZATION_NOT_GRANTED),
    ("policy prohibits", FakeVerifier(auth("A", policy=False)), ChangeReason.POLICY_PROHIBITS_DOWNGRADE),
    ("expired", FakeVerifier(auth("A", expires_at=T0 + timedelta(seconds=1))), ChangeReason.AUTHORIZATION_EXPIRED),
    ("verifier crashes", FakeVerifier(error=True), ChangeReason.VERIFIER_ERROR),
])
def test_invalid_authorizations_rejected(label, verifier, reason):
    r = req(cur=C.RESTRICTED, new=C.INTERNAL, authorization_reference="AUTH-1")
    d = evaluate_classification_change(r, doc("A", C.RESTRICTED), verifier, now=T0 + timedelta(days=1))
    assert d.status == ChangeStatus.REJECTED and d.reason == reason, label


def test_approval_cannot_override_prohibiting_policy():
    v = FakeVerifier(auth("A", policy=False, approval=True))
    d = evaluate_classification_change(req(cur=C.RESTRICTED, new=C.INTERNAL, authorization_reference="AUTH-1"),
                                       doc("A", C.RESTRICTED), v)
    assert d.status == ChangeStatus.REJECTED and d.reason == ChangeReason.POLICY_PROHIBITS_DOWNGRADE


def test_forged_current_classification_and_status_rejected():
    stored = doc("A", C.RESTRICTED)
    # Requester claims the doc is INTERNAL so RESTRICTED->PUBLIC looks like INTERNAL->PUBLIC.
    forged = req(cur=C.INTERNAL, new=C.PUBLIC, authorization_reference="AUTH-1")
    v = FakeVerifier(auth("A", C.INTERNAL, C.PUBLIC))
    assert evaluate_classification_change(forged, stored, v).reason == ChangeReason.STALE_CURRENT_CLASSIFICATION
    pre_accepted = req(cur=C.RESTRICTED, new=C.PUBLIC, status=ChangeStatus.ACCEPTED)
    assert evaluate_classification_change(pre_accepted, stored).reason == ChangeReason.REQUEST_NOT_PENDING
    assert evaluate_classification_change(req(doc_id="B", cur=C.RESTRICTED, new=C.PUBLIC), stored).reason \
        == ChangeReason.DOCUMENT_MISMATCH
