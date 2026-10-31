import pytest

from models.document_security import DLPCategory, DLPErrorCode, InspectionStatus, Severity
from security import dlp_engine
from security.dlp_engine import (
    DLPConfigurationError, DLPEngine, DLPRule, inspect_content, load_rules, make_keyword_rule,
    redact_text, verhoeff_valid,
)


def categories(text, engine=None):
    return {f.category for f in inspect_content(text, engine).findings}


def rule_ids(text, engine=None):
    return {f.rule_id for f in inspect_content(text, engine).findings}


# ---- individual categories ------------------------------------------------------
def test_email_detected():
    r = inspect_content("write to jane.doe+tag@mail.example.co.uk today")
    assert r.status == InspectionStatus.DETECTED and DLPCategory.EMAIL in r.categories


@pytest.mark.parametrize("text", [
    "call +1 (415) 555-2671", "call 415-555-2671", "call +44 20 7946 0958", "call +91 98765 43210",
    "call 9876543210",
])
def test_phone_detected(text):
    assert DLPCategory.PHONE in categories(text)


def _aadhaar():
    base = "23456789012"
    return next(base + str(d) for d in range(10) if verhoeff_valid(base + str(d)))


def test_pii_detected():
    assert "pii.us_ssn" in rule_ids("SSN: 123-45-6789")
    assert "pii.india_pan" in rule_ids("PAN ABCPE1234F on file")
    assert "pii.aadhaar" in rule_ids(f"Aadhaar {_aadhaar()}")


@pytest.mark.parametrize("text,rule", [
    ("card 4111 1111 1111 1111", "financial.card_number"),
    ("card 4111-1111-1111-1111", "financial.card_number"),
    ("iban GB82 WEST 1234 5698 7654 32", "financial.iban"),
    ("Account number: 123456789012", "financial.bank_account_context"),
])
def test_financial_detected(text, rule):
    assert rule in rule_ids(text)


@pytest.mark.parametrize("text,rule", [
    ("AKIAIOSFODNN7EXAMPLE", "credential.aws_access_key"),
    ("ghp_" + "Ab1" * 12, "credential.github_token"),
    ("sk-ant-" + "a1B2" * 8, "credential.anthropic_key"),
    ("sk-" + "a1B2c3D4" * 4, "credential.openai_style_key"),
    ("AIza" + "A1b2C3d4" * 4 + "xyz", "credential.google_api_key"),
    ("-----BEGIN RSA PRIVATE KEY-----", "credential.private_key_block"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdEFGH1234", "credential.jwt"),
    ("Authorization: Bearer abcdefghij0123456789ABCDEF", "credential.bearer_token"),
    ("db_password = 'Sup3rS3cret!x'", "credential.assignment"),
    ("API_KEY: 9f8e7d6c5b4a", "credential.assignment"),
])
def test_credentials_detected(text, rule):
    assert rule in rule_ids(text)


def test_default_confidential_marking():
    assert DLPCategory.CONFIDENTIAL_PATTERN in categories("CONFIDENTIAL - board only")


# ---- false positives -------------------------------------------------------------
@pytest.mark.parametrize("text", [
    "The quarterly meeting is on 2024-01-15 at 10:30.",
    "Order 1234567890123 shipped; version 1.2.3.4; build 20240115.",
    "card 4111 1111 1111 1112",            # fails Luhn
    "iban GB82 WEST 1234 5698 7654 33",    # fails mod 97
    "SSN 000-12-3456 and 666-12-3456",     # invalid SSN areas
    "password: ********",
    "password=<your-password>",
    "api_key=${API_KEY}",
    "max_tokens=100000",
    "restricted access to the lobby",       # lower-case, not a marking
    "contact me at user@ or @handle",
])
def test_ordinary_or_placeholder_text_not_flagged(text):
    r = inspect_content(text)
    assert r.status == InspectionStatus.NOT_DETECTED, [f.rule_id for f in r.findings]


# ---- empty / ordinary --------------------------------------------------------------
@pytest.mark.parametrize("text", ["", "   \n\t ", "Hello world, nothing here."])
def test_empty_and_ordinary_text_not_detected(text):
    r = inspect_content(text)
    assert r.status == InspectionStatus.NOT_DETECTED
    assert r.no_findings and not r.sensitive_content_detected
    assert "not proof" in r.summary


# ---- multiple findings, locations, overlaps ----------------------------------------
def test_multiple_categories_and_locations():
    text = "a@b.com\nssn 123-45-6789\nkey AKIAIOSFODNN7EXAMPLE"
    r = inspect_content(text)
    assert {DLPCategory.EMAIL, DLPCategory.PII, DLPCategory.CREDENTIAL} <= set(r.categories)
    assert r.highest_severity == Severity.CRITICAL
    by_rule = {f.rule_id: f for f in r.findings}
    f = by_rule["pii.us_ssn"]
    assert text[f.start:f.end] == "123-45-6789" and f.line == 2
    assert by_rule["credential.aws_access_key"].line == 3


def test_same_category_overlap_collapses_to_one():
    r = inspect_content("+1 415-555-2671")  # matches phone.international and phone.us
    assert len([f for f in r.findings if f.category == DLPCategory.PHONE]) == 1


def test_cross_category_overlap_keeps_both_and_is_deterministic():
    text = "postgres://admin:hunter22@db.example.com/x"
    r1, r2 = inspect_content(text), inspect_content(text)
    assert {DLPCategory.CREDENTIAL, DLPCategory.EMAIL} <= set(r1.categories)
    assert [f.model_dump() for f in r1.findings] == [f.model_dump() for f in r2.findings]


def test_duplicate_values_reported_per_occurrence():
    r = inspect_content("a@b.com and a@b.com")
    assert len(r.findings) == 2


# ---- redaction ---------------------------------------------------------------------
def test_results_never_contain_raw_values():
    secret = "AKIAIOSFODNN7EXAMPLE"
    email = "jane.doe@example.com"
    r = inspect_content(f"{secret} {email}")
    dumped = r.model_dump_json()
    assert secret not in dumped and email not in dumped and secret not in repr(r)


def test_redact_text():
    text = "mail jane@example.com key AKIAIOSFODNN7EXAMPLE"
    out = redact_text(text, inspect_content(text))
    assert "jane@example.com" not in out and "AKIA" not in out and "[REDACTED:EMAIL]" in out


def test_redact_rejects_failed_or_mismatched_results():
    with pytest.raises(ValueError):
        redact_text("x", inspect_content(None))
    with pytest.raises(ValueError):
        redact_text("different content", inspect_content("a@b.com"))


# ---- malformed input / failure -----------------------------------------------------
@pytest.mark.parametrize("bad", [None, 123, b"bytes a@b.com", ["a@b.com"], {"k": "v"}])
def test_malformed_input_is_failed_not_safe(bad):
    r = inspect_content(bad)
    assert r.status == InspectionStatus.FAILED
    assert r.error_code == DLPErrorCode.INVALID_INPUT_TYPE
    assert r.inspection_succeeded is False and r.no_findings is False
    assert r.treat_as_sensitive is True


def test_oversized_content_fails_closed():
    r = DLPEngine(max_content_chars=10).inspect("a" * 11)
    assert r.status == InspectionStatus.FAILED and r.error_code == DLPErrorCode.CONTENT_TOO_LARGE


def test_rule_execution_error_fails_closed_without_leaking(monkeypatch):
    def boom(_value):
        raise RuntimeError("card 4111111111111111")
    monkeypatch.setitem(dlp_engine.VALIDATORS, "luhn", boom)
    r = inspect_content("pay with 4111 1111 1111 1111")
    assert r.status == InspectionStatus.FAILED and r.error_code == DLPErrorCode.RULE_EXECUTION_ERROR
    assert "4111" not in r.summary and r.findings == ()


def test_treat_as_sensitive_flags():
    assert inspect_content("a@b.com").treat_as_sensitive
    assert not inspect_content("plain").treat_as_sensitive


# ---- configurable rules --------------------------------------------------------------
def test_keyword_rule_configurable():
    engine = DLPEngine([make_keyword_rule("biz.codename", ["Project Falcon", "Orion"])])
    assert rule_ids("Budget for project falcon and ORION.", engine) == {"biz.codename"}
    assert inspect_content("Orionic", engine).status == InspectionStatus.NOT_DETECTED


def test_with_rules_extends_defaults():
    engine = DLPEngine().with_rules([make_keyword_rule("biz.codename", ["Falcon"])])
    ids = rule_ids("Falcon contact a@b.com", engine)
    assert {"biz.codename", "email.address"} <= ids


def test_load_rules_from_dicts():
    rules = load_rules([{"rule_id": "emp.id", "category": "CONFIDENTIAL_PATTERN", "severity": "LOW",
                         "pattern": r"\bEMP-\d{5}\b"}])
    assert rule_ids("see EMP-12345", DLPEngine(rules)) == {"emp.id"}


def test_disabled_rule_skipped():
    rule = DLPRule(rule_id="x.r", category=DLPCategory.EMAIL, severity=Severity.LOW, pattern="foo", enabled=False)
    assert DLPEngine([rule]).inspect("foo").status == InspectionStatus.NOT_DETECTED


@pytest.mark.parametrize("cfg", [
    {"rule_id": "bad", "category": "EMAIL", "severity": "LOW", "pattern": "("},
    {"rule_id": "bad", "category": "EMAIL", "severity": "LOW", "pattern": "a", "value_group": 2},
    {"rule_id": "bad", "category": "EMAIL", "severity": "LOW", "pattern": "a", "validator": "nope"},
    {"rule_id": "Bad Id", "category": "EMAIL", "severity": "LOW", "pattern": "a"},
    {"rule_id": "ok", "category": "NOPE", "severity": "LOW", "pattern": "a"},
])
def test_invalid_rule_configuration_rejected(cfg):
    with pytest.raises(DLPConfigurationError):
        load_rules([cfg])


def test_duplicate_rule_ids_and_bad_rules_rejected():
    r = make_keyword_rule("dup.id", ["a"])
    with pytest.raises(DLPConfigurationError):
        DLPEngine([r, r])
    with pytest.raises(DLPConfigurationError):
        DLPEngine(["not a rule"])  # type: ignore[list-item]
    with pytest.raises(DLPConfigurationError):
        make_keyword_rule("kw.empty", ["", "  "])


def test_findings_truncation_is_flagged():
    r = DLPEngine(max_findings=2).inspect("a@b.com c@d.com e@f.com")
    assert r.status == InspectionStatus.DETECTED and len(r.findings) == 2 and r.findings_truncated


# --------------------------------------------------------------------------- #
# Unicode evasion hardening (normalised-view scan)
# --------------------------------------------------------------------------- #
class TestUnicodeEvasion:
    def test_zero_width_char_inside_email_is_detected(self):
        text = "reach bob@exa\u200bmple.com today"
        result = inspect_content(text)
        assert result.status.value == "DETECTED"
        assert any(f.rule_id == "email.address" for f in result.findings)

    def test_fullwidth_at_sign_is_detected_and_span_points_into_original(self):
        text = "mail: bob\uff20example.com"
        result = inspect_content(text)
        finding = next(f for f in result.findings if f.rule_id == "email.address")
        assert finding.start >= len("mail: ") and finding.end <= len(text)

    def test_evasion_does_not_duplicate_plain_findings(self):
        result = inspect_content("bob@example.com")
        assert len([f for f in result.findings if f.rule_id == "email.address"]) == 1

    def test_normalised_matches_do_not_leak_value_in_result(self):
        result = inspect_content("bob@exa\u200bmple.com")
        assert "example" not in result.model_dump_json()
