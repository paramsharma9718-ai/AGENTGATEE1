# Module 02: Information Security & Data Protection

## A. Overview

Identifies sensitive content, maintains security classifications, preserves them across summarisation / aggregation / combination, and records lineage from sources to generated reports.

**In scope:** classification model, DLP, information-flow control, label inheritance, classification-change validation, provenance, structured inspection results.
**Out of scope (integration boundaries only):** central authorization decisions, LLM/agent logic, protected tool execution, dashboard, authentication, workflow DB, audit logging.

No shared contracts (`docs/claude-team-contract.md`, `architecture.md`, `api-contracts.md`) existed when this was written. The conventions below are therefore *proposals* that need team confirmation (see section H).

## B. File structure

| File | Purpose |
|---|---|
| `security/security_labels.py` | `Classification` enum with an explicit rank table, `strictest_classification`, downgrade detection, trusted-authorization verification, classification-change evaluation/validation/application |
| `security/dlp_engine.py` | `DLPRule`, `DLPEngine`, default rules, `inspect_content`, `redact_text`, `make_keyword_rule`, `load_rules` |
| `security/information_flow.py` | `derive_classification`, `verify_report_classification`, source validation, `DerivationResult` |
| `security/provenance.py` | `register_derivation` (label + provenance together), `ProvenanceGraph` |
| `models/document_security.py` | Pydantic models: `DocumentSecurityMetadata`, `DLPFinding`, `DLPInspectionResult`, `SourceReference`, `ProvenanceRecord`, `ClassificationChangeRequest`, `TrustedAuthorizationResult`, `ClassificationChangeDecision`, enums |

Import direction: `models` → `security.security_labels`; `security_labels` imports models lazily inside functions (no cycle).

## C. Public API

```python
from security.security_labels import (Classification, parse_classification, strictest_classification,
    evaluate_classification_change, validate_classification_change, apply_classification_change)
from security.dlp_engine import inspect_content, redact_text, DLPEngine, make_keyword_rule
from security.information_flow import derive_classification, verify_report_classification
from security.provenance import register_derivation, ProvenanceGraph
```

| Function | Returns | Fails with |
|---|---|---|
| `parse_classification(v)` | `Classification` | `InvalidClassificationError` for anything but a member or exact upper-case name |
| `strictest_classification(items)` | strictest level | `EmptyClassificationSetError` (empty is **not** PUBLIC), `InvalidClassificationError` |
| `evaluate_classification_change(request, current, verifier)` | `ClassificationChangeDecision` (never raises on policy rejection) | n/a |
| `validate_classification_change(...)` | decision if accepted | `UnauthorizedDowngradeError` (has `.reason`) |
| `apply_classification_change(...)` | **new** `DocumentSecurityMetadata` | `UnauthorizedDowngradeError` |
| `inspect_content(text, engine=None)` | `DLPInspectionResult` | never raises; failures are `status=FAILED` |
| `redact_text(text, result)` | redacted string | `ValueError` for FAILED/mismatched results |
| `derive_classification(report_id, sources, type, ...)` | `DerivationResult` | `EmptySourcesError`, `MissingSourceMetadataError`, `InvalidSourceMetadataError`, `DuplicateSourceError`, `UnauthorizedDowngradeError` |
| `verify_report_classification(report, sources, verifier=None)` | `None` | `UnauthorizedDowngradeError` |
| `register_derivation(report_id, sources, type, ...)` | `DerivedArtifact(security, provenance, derivation)` | as `derive_classification` |

Identifiers: `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`. Timestamps: timezone-aware, normalised to UTC (naive rejected). All models are frozen and reject unknown fields. Pass `created_at=` / `record_id=` / `now=` for deterministic tests.

## D. Classification rules

`PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED`, via an explicit rank table. Enum order, string comparison and alphabetical sorting are never used.

* Derived classification = strictest source (`CONFIDENTIAL + RESTRICTED → RESTRICTED`).
* No transformation type (`SUMMARIZATION`, `TRANSFORMATION`, `AGGREGATION`, `REPORT_GENERATION`, `COMBINATION`) lowers a label.
* Zero sources, missing/malformed/duplicate sources, and self-derivation are rejected.
* `minimum_classification` (trusted callers only) can only raise the result.
* `requested_classification` is **untrusted** input (e.g. from an LLM): lower than the inherited level → rejected unless a verified authorization exists; higher → ignored and flagged (`requested_classification_ignored`).

## E. DLP limitations

Detected: email; phone (E.164-style, North American, Indian mobile); PII (US SSN, Aadhaar with Verhoeff check, Indian PAN); financial (Luhn-checked card numbers, mod-97 IBAN, labelled bank-account numbers); credentials (private-key headers, AWS/GitHub/Slack/Google/Anthropic/`sk-` keys, JWT, bearer tokens, URL passwords, `password=`-style assignments, with placeholder filtering); configurable patterns (upper-case classification markings by default, plus keyword/regex rules you add).

Rules are evaluated on the original text and on an NFKC-normalised copy with zero-width/soft-hyphen characters removed, so trivial evasion (e.g. a zero-width character inside an email, a full-width `@`) is still caught; finding spans always refer to the ORIGINAL text. Other evasion (encoding such as base64, split values, homoglyphs from other scripts, translation) is NOT covered.

Regex DLP is **best-effort**. It misses obfuscated, encoded, split, translated or unknown-format data and produces false positives. Three outcomes are kept distinct:

* `DETECTED`: findings present.
* `NOT_DETECTED`: no rule matched; **not** proof of safety.
* `FAILED`: bad input type, oversize content, or a rule error; nothing is known. Never treat as safe.

Use `result.treat_as_sensitive` for fail-closed policy (True for DETECTED and FAILED). Findings contain offsets, line, severity, confidence and `[REDACTED:<rule>:<len>]`, never raw values; error text never includes content. Same-category overlaps collapse deterministically (severity, length, start, rule id); cross-category overlaps are all kept. Python `re` has no timeout, so keep custom patterns simple; input is capped at 2,000,000 characters by default.

## F. Classification changes

Distinguished cases: valid assignment (`DocumentSecurityMetadata`), derived classification (`derive_classification`), proposed change (`ClassificationChangeRequest`, which carries no authority), authorized downgrade, unauthorized downgrade.

A downgrade is accepted only if all of these hold:

1. The request matches the **trusted stored metadata** (document id and current level; the requester cannot misstate it) and is `PENDING`.
2. A `TrustedAuthorizationVerifier.lookup(authorization_id)` returns a `TrustedAuthorizationResult` that is bound to the same document, operation `classification.downgrade`, and the exact from/to levels.
3. `policy_permits` **and** `approval_granted` are both true. An approval cannot override a policy that prohibits the downgrade.
4. It has not expired. Verifier errors, unknown ids, or no verifier all reject (fail closed).

Increasing restriction needs no authorization. The `authorization_reference` string has no meaning by itself.

## G. Provenance

`register_derivation` computes the trusted label and builds both `DocumentSecurityMetadata` (label origin `INHERITED`, with `provenance_refs`) and a `ProvenanceRecord` (sources with their classifications **at derivation time**, derived classification, transformation type, timestamp, parent→child links) together. `ProvenanceRecord` validates self-consistency on construction/deserialisation (links match sources, no self-derivation, no unauthorized lowering), so tampered JSON is rejected. `ProvenanceGraph` is an in-memory validator/index (duplicate reports, cycles, stale source labels, child-before-parent). It is not storage: persist `record.model_dump(mode="json")` in the main DB and rebuild with `ProvenanceGraph.from_records(...)`.

## H. Integration instructions

**Authorization engine** (must implement the verifier and consume results):

```python
class EngineVerifier:                       # owned by the authorization engine
    def lookup(self, authorization_id): ... # return TrustedAuthorizationResult issued by policy/approval flow, else None

dlp = inspect_content(document_text)        # structured: dlp.status, dlp.categories, dlp.highest_severity, dlp.treat_as_sensitive
# Combine dlp + DocumentSecurityMetadata.classification + recipient clearance in the policy decision.
```

**Report saver tool**

```python
art = register_derivation(report_id, sources=[meta_a, meta_b], transformation_type=T.SUMMARIZATION)
# Persist art.security (label) and art.provenance (lineage) with the report.
# On any save/reload of an existing report: verify_report_classification(report_meta, sources, verifier)
```

**Delivery tool:** read `report_meta.classification`, run `inspect_content` on the body, and pass both to the authorization engine. Do not parse `summary` strings; use enum/struct fields.

Coordination items for the team: (1) confirm the ID and UTC timestamp conventions; (2) the authorization engine must provide the `lookup` verifier and issue `TrustedAuthorizationResult` with operation `classification.downgrade`; (3) the persistence layer stores serialised metadata/provenance; (4) nothing in this module touches a database, LLM or UI.

## I. Testing

```bash
pip install -r requirements.txt
python -m pytest                          # all tests
python -m pytest tests/test_dlp.py tests/test_information_flow.py -v
python -m pytest tests/test_security_labels.py tests/test_provenance.py tests/test_security_integration.py
```
