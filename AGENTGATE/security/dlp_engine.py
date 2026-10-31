"""Deterministic, rule-based Data Loss Prevention (DLP) engine.

IMPORTANT LIMITATIONS
---------------------
Regular-expression inspection is best-effort. A ``NOT_DETECTED`` result means
"no configured rule matched", never "this content is safe". Obfuscated,
encoded (base64, URL-encoding), split, translated or novel-format secrets and
personal data will be missed, and some benign text will match (false
positives). Callers that must fail closed should use
``DLPInspectionResult.treat_as_sensitive``, which is True for DETECTED *and*
FAILED inspections.

Behaviour
---------
* ``inspect`` never raises on bad input or rule failure; it returns a
  ``FAILED`` result with an error code. Findings never contain raw values;
  only offsets, a line number and a ``[REDACTED:<rule>:<len>]`` preview.
* Overlaps: findings of the *same category* that overlap collapse to one,
  chosen by (highest severity, longest span, earliest start, rule_id).
  Overlapping findings of *different* categories are all kept (e.g. an e-mail
  address inside a credential-bearing URL is both EMAIL and CREDENTIAL).
* Python's ``re`` has no timeout, so custom patterns must avoid catastrophic
  backtracking. Input size is capped (``max_content_chars``) as a mitigation.
"""

from __future__ import annotations

import re
import unicodedata
from bisect import bisect_right
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, ValidationError, field_validator, model_validator

from models.document_security import (
    DLPCategory,
    DLPErrorCode,
    DLPFinding,
    DLPInspectionResult,
    InspectionStatus,
    Severity,
    utc_now,
)

DEFAULT_MAX_CONTENT_CHARS = 2_000_000
DEFAULT_MAX_FINDINGS = 5_000


class DLPConfigurationError(ValueError):
    """Invalid DLP rule or engine configuration (raised at configuration time)."""


# --------------------------------------------------------------------------- #
# Value validators (reduce false positives for numeric identifiers)
# --------------------------------------------------------------------------- #
def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def luhn_valid(value: str) -> bool:
    d = _digits(value)
    if not 13 <= len(d) <= 19 or len(set(d)) == 1:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2 == 1:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        total += n
    return total % 10 == 0


_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5), (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7), (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3), (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4), (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7), (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_valid(value: str) -> bool:
    """Checksum used by Aadhaar numbers (12 digits)."""
    d = _digits(value)
    if len(d) != 12:
        return False
    c = 0
    for i, ch in enumerate(reversed(d)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def iban_valid(value: str) -> bool:
    s = re.sub(r"\s", "", value).upper()
    if not 15 <= len(s) <= 34 or not s.isalnum():
        return False
    rearranged = s[4:] + s[:4]
    return int("".join(str(int(ch, 36)) for ch in rearranged)) % 97 == 1


def phone_digits_valid(value: str) -> bool:
    return 10 <= len(_digits(value)) <= 15


_PLACEHOLDER_WORDS = {"changeme", "example", "password", "secret", "redacted", "placeholder", "yourpassword"}


def not_placeholder(value: str) -> bool:
    v = value.strip("\"'")
    if v.startswith(("<", "${", "{{", "%", "$(")) or v.lower() in _PLACEHOLDER_WORDS:
        return False
    return len(set(v)) > 1  # rejects "******", "xxxxxxxx"


VALIDATORS: Dict[str, Callable[[str], bool]] = {
    "luhn": luhn_valid,
    "verhoeff": verhoeff_valid,
    "iban": iban_valid,
    "phone_digits": phone_digits_valid,
    "not_placeholder": not_placeholder,
}


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
class DLPRule(BaseModel):
    """A configurable detection rule.

    Attributes:
        rule_id: Stable lowercase identifier, e.g. ``credential.aws_access_key``.
        category: Detection category.
        severity: Severity of a match.
        pattern: Python regular expression (compiled with ``re.ASCII``).
        value_group: Capture group that holds the sensitive value (0 = whole match).
        validator: Optional name from :data:`VALIDATORS` applied to the value.
        ignore_case: Compile case-insensitively.
        confidence: 0-1 estimate of how likely a match is a true positive.
        enabled: Disabled rules are skipped.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")
    category: DLPCategory
    severity: Severity
    pattern: str = Field(min_length=1, max_length=4000)
    description: str = Field(default="", max_length=300)
    value_group: int = Field(default=0, ge=0)
    validator: Optional[str] = None
    ignore_case: bool = False
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    enabled: bool = True

    _compiled: "re.Pattern[str]" = PrivateAttr()

    @field_validator("validator")
    @classmethod
    def _known_validator(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VALIDATORS:
            raise ValueError(f"unknown validator {v!r}")
        return v

    @model_validator(mode="after")
    def _compile(self) -> "DLPRule":
        flags = re.ASCII | (re.IGNORECASE if self.ignore_case else 0)
        try:
            compiled = re.compile(self.pattern, flags)
        except re.error as exc:
            raise ValueError(f"invalid regular expression: {exc}") from exc
        if self.value_group > compiled.groups:
            raise ValueError("value_group exceeds the number of capture groups")
        self._compiled = compiled
        return self

    def find(self, content: str) -> Iterator[Tuple[int, int]]:
        """Yield ``(start, end)`` spans of validated sensitive values."""
        check = VALIDATORS[self.validator] if self.validator else None
        for match in self._compiled.finditer(content):
            start, end = match.span(self.value_group)
            if start < 0 or end <= start:
                continue
            if check is not None and not check(content[start:end]):
                continue
            yield start, end


def make_keyword_rule(
    rule_id: str,
    terms: Sequence[str],
    *,
    severity: Severity = Severity.MEDIUM,
    category: DLPCategory = DLPCategory.CONFIDENTIAL_PATTERN,
    ignore_case: bool = True,
    description: str = "",
    confidence: float = 0.8,
) -> DLPRule:
    """Build a rule matching any of ``terms`` as whole words (e.g. project code names)."""
    cleaned = [t.strip() for t in terms if isinstance(t, str) and t.strip()]
    if not cleaned:
        raise DLPConfigurationError("keyword rule requires at least one non-empty term")
    alternation = "|".join(re.escape(t) for t in sorted(set(cleaned), key=lambda t: (-len(t), t)))
    try:
        return DLPRule(
            rule_id=rule_id,
            category=category,
            severity=severity,
            pattern=rf"(?<!\w)(?:{alternation})(?!\w)",
            ignore_case=ignore_case,
            description=description or "Configured confidential keyword",
            confidence=confidence,
        )
    except ValidationError as exc:
        raise DLPConfigurationError(f"invalid keyword rule {rule_id!r}") from exc


def load_rules(config: Iterable[Mapping[str, Any]]) -> List[DLPRule]:
    """Build rules from plain dicts (e.g. parsed JSON/YAML configuration)."""
    rules: List[DLPRule] = []
    for index, item in enumerate(config):
        try:
            rules.append(DLPRule.model_validate(dict(item)))
        except (ValidationError, TypeError) as exc:
            raise DLPConfigurationError(f"invalid DLP rule at index {index}: {exc}") from exc
    return rules


def _r(rule_id, category, severity, pattern, **kw) -> DLPRule:
    return DLPRule(rule_id=rule_id, category=category, severity=severity, pattern=pattern, **kw)


_C, _S = DLPCategory, Severity

DEFAULT_RULES: Tuple[DLPRule, ...] = (
    # --- Email ---------------------------------------------------------------
    _r("email.address", _C.EMAIL, _S.MEDIUM,
       r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![\w-])",
       description="Email address"),
    # --- Phone ---------------------------------------------------------------
    _r("phone.international", _C.PHONE, _S.MEDIUM,
       r"(?<![\w+])\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d{1,4}(?:[ .-]?\d{2,4}){1,4}(?![\w])",
       validator="phone_digits", confidence=0.9, description="E.164-style international number"),
    _r("phone.us", _C.PHONE, _S.MEDIUM,
       r"(?<![\w+])(?:\+?1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}(?!\w)",
       validator="phone_digits", confidence=0.85, description="North American number"),
    _r("phone.india_mobile", _C.PHONE, _S.MEDIUM,
       r"(?<![\w+])(?:(?:\+91|91|0)[ -]?)?[6-9]\d{4}[ -]?\d{5}(?![\w-])",
       validator="phone_digits", confidence=0.7, description="Indian mobile number"),
    # --- Personal identification ---------------------------------------------
    _r("pii.us_ssn", _C.PII, _S.HIGH,
       r"(?<![\w-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\w-])",
       confidence=0.9, description="US Social Security Number"),
    _r("pii.aadhaar", _C.PII, _S.HIGH,
       r"(?<![\w-])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![\w-])",
       validator="verhoeff", confidence=0.85, description="Indian Aadhaar number (Verhoeff-checked)"),
    _r("pii.india_pan", _C.PII, _S.HIGH,
       r"(?<!\w)[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z](?!\w)",
       confidence=0.85, description="Indian PAN"),
    # --- Financial -----------------------------------------------------------
    _r("financial.card_number", _C.FINANCIAL, _S.HIGH,
       r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])",
       validator="luhn", confidence=0.9, description="Payment card number (Luhn-checked)"),
    _r("financial.iban", _C.FINANCIAL, _S.HIGH,
       r"(?<!\w)[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?!\w)",
       validator="iban", confidence=0.9, description="IBAN (mod-97 checked)"),
    _r("financial.bank_account_context", _C.FINANCIAL, _S.HIGH,
       r"\b(?:a/c|acct|account)(?:[ \t]*(?:no|number|num|#))?\.?[ \t]*[:=#-]?[ \t]*(\d{9,18})(?!\d)",
       value_group=1, ignore_case=True, confidence=0.75, description="Bank account number given with a label"),
    # --- API keys and credentials ---------------------------------------------
    _r("credential.private_key_block", _C.CREDENTIAL, _S.CRITICAL,
       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----",
       description="PEM/PGP private key header"),
    _r("credential.aws_access_key", _C.CREDENTIAL, _S.CRITICAL,
       r"(?<![\w])(?:AKIA|ASIA)[0-9A-Z]{16}(?!\w)", description="AWS access key id"),
    _r("credential.github_token", _C.CREDENTIAL, _S.CRITICAL,
       r"(?<![\w])gh[pousr]_[A-Za-z0-9]{36,255}(?!\w)", description="GitHub token"),
    _r("credential.slack_token", _C.CREDENTIAL, _S.CRITICAL,
       r"(?<![\w])xox[baprs]-[A-Za-z0-9-]{10,200}(?![\w-])", description="Slack token"),
    _r("credential.anthropic_key", _C.CREDENTIAL, _S.CRITICAL,
       r"(?<![\w])sk-ant-[A-Za-z0-9_-]{20,200}(?![\w-])", description="Anthropic-style API key"),
    _r("credential.openai_style_key", _C.CREDENTIAL, _S.CRITICAL,
       r"(?<![\w])sk-(?!ant-)[A-Za-z0-9]{20,200}(?!\w)", confidence=0.9, description="sk- prefixed API key"),
    _r("credential.google_api_key", _C.CREDENTIAL, _S.CRITICAL,
       r"(?<![\w])AIza[0-9A-Za-z_-]{35}(?![\w-])", description="Google API key"),
    _r("credential.jwt", _C.CREDENTIAL, _S.HIGH,
       r"(?<![\w-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![\w-])",
       confidence=0.9, description="JSON Web Token"),
    _r("credential.bearer_token", _C.CREDENTIAL, _S.HIGH,
       r"\bbearer[ \t]+([A-Za-z0-9._~+/-]{20,}=*)", value_group=1, ignore_case=True,
       confidence=0.85, description="Bearer token in an Authorization header"),
    _r("credential.url_password", _C.CREDENTIAL, _S.HIGH,
       r"\b[A-Za-z][A-Za-z0-9+.-]{1,20}://[^\s:@/]{1,64}:([^\s@/]{3,128})@",
       value_group=1, validator="not_placeholder", description="Password embedded in a URL"),
    _r("credential.assignment", _C.CREDENTIAL, _S.HIGH,
       r"\b[\w-]{0,32}(?:password|passwd|secret|api[_-]?key|access[_-]?key|(?:auth|access|refresh)[_-]?token)"
       r"[\w-]{0,32}[ \t]*[:=][ \t]*[\"']?([^\s\"']{6,200})",
       value_group=1, ignore_case=True, validator="not_placeholder", confidence=0.8,
       description="Credential-like name assigned a literal value"),
    # --- Configurable confidential patterns ------------------------------------
    _r("confidential.marking", _C.CONFIDENTIAL_PATTERN, _S.MEDIUM,
       r"\b(?:TOP SECRET|STRICTLY CONFIDENTIAL|CONFIDENTIAL|RESTRICTED|INTERNAL USE ONLY|DO NOT DISTRIBUTE)\b",
       confidence=0.6, description="Upper-case classification marking in text"),
)


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
_INVISIBLE = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"}


def _normalized_view(content: str) -> Tuple[str, List[int]]:
    """Return an NFKC-normalised copy without invisible characters, plus a map.

    ``index_map[i]`` is the offset in ``content`` of the character that produced
    ``view[i]``. This lets rules also see through trivial evasion (zero-width
    characters, full-width ``@``/digits) while findings still point into the
    ORIGINAL text.
    """
    chars: List[str] = []
    index_map: List[int] = []
    for pos, ch in enumerate(content):
        if ch in _INVISIBLE:
            continue
        for out in unicodedata.normalize("NFKC", ch):
            chars.append(out)
            index_map.append(pos)
    return "".join(chars), index_map


class _Candidate:
    __slots__ = ("rule", "start", "end")

    def __init__(self, rule: DLPRule, start: int, end: int) -> None:
        self.rule, self.start, self.end = rule, start, end


def _priority(c: _Candidate) -> Tuple[int, int, int, str]:
    return (-c.rule.severity.rank, -(c.end - c.start), c.start, c.rule.rule_id)


def _resolve_overlaps(candidates: List[_Candidate]) -> List[_Candidate]:
    """Collapse overlapping same-category candidates; keep cross-category ones."""
    kept: List[_Candidate] = []
    for category in DLPCategory:
        group = sorted((c for c in candidates if c.rule.category == category), key=_priority)
        chosen: List[_Candidate] = []
        for cand in group:
            if all(cand.end <= k.start or cand.start >= k.end for k in chosen):
                chosen.append(cand)
        kept.extend(chosen)
    return sorted(kept, key=lambda c: (c.start, c.end, c.rule.rule_id))


class DLPEngine:
    """Rule-based content inspector. Immutable and safe to share."""

    def __init__(
        self,
        rules: Optional[Sequence[DLPRule]] = None,
        *,
        max_content_chars: int = DEFAULT_MAX_CONTENT_CHARS,
        max_findings: int = DEFAULT_MAX_FINDINGS,
    ) -> None:
        selected = tuple(DEFAULT_RULES if rules is None else rules)
        if not all(isinstance(r, DLPRule) for r in selected):
            raise DLPConfigurationError("rules must be DLPRule instances")
        ids = [r.rule_id for r in selected]
        if len(set(ids)) != len(ids):
            raise DLPConfigurationError("duplicate rule_id in DLP configuration")
        if max_content_chars < 1 or max_findings < 1:
            raise DLPConfigurationError("limits must be positive")
        self._rules = selected
        self._max_chars = max_content_chars
        self._max_findings = max_findings

    @property
    def rules(self) -> Tuple[DLPRule, ...]:
        return self._rules

    def with_rules(self, extra: Iterable[DLPRule]) -> "DLPEngine":
        """Return a new engine with ``extra`` rules appended."""
        return DLPEngine(
            [*self._rules, *extra],
            max_content_chars=self._max_chars,
            max_findings=self._max_findings,
        )

    def inspect(self, content: Any, *, inspected_at: Optional[datetime] = None) -> DLPInspectionResult:
        """Inspect text. Never raises; failures are returned as ``FAILED`` results."""
        ts = inspected_at or utc_now()
        if not isinstance(content, str):
            return self._failed(DLPErrorCode.INVALID_INPUT_TYPE, 0, 0, ts,
                                f"content must be str, got {type(content).__name__}")
        if len(content) > self._max_chars:
            return self._failed(DLPErrorCode.CONTENT_TOO_LARGE, len(content), 0, ts,
                                "content exceeds the configured inspection size limit")

        candidates: List[_Candidate] = []
        evaluated = 0
        view, index_map = _normalized_view(content)
        if view == content:
            view = None  # nothing to see through; avoid duplicate work
        for rule in self._rules:
            if not rule.enabled:
                continue
            evaluated += 1
            try:
                candidates.extend(_Candidate(rule, s, e) for s, e in rule.find(content))
                if view is not None:
                    for s, e in rule.find(view):
                        candidates.append(_Candidate(rule, index_map[s], index_map[e - 1] + 1))
            except Exception as exc:  # noqa: BLE001 - fail closed, no content in message
                return self._failed(DLPErrorCode.RULE_EXECUTION_ERROR, len(content), evaluated, ts,
                                    f"rule {rule.rule_id} failed ({type(exc).__name__})")

        resolved = _resolve_overlaps(candidates)
        if not resolved:
            return DLPInspectionResult(
                status=InspectionStatus.NOT_DETECTED,
                sensitive_content_detected=False,
                content_length=len(content),
                rules_evaluated=evaluated,
                summary="No configured rule matched. This is not proof the content is free of "
                        "sensitive information.",
                inspected_at=ts,
            )
        truncated = len(resolved) > self._max_findings
        resolved = resolved[: self._max_findings]
        findings = self._build_findings(content, resolved)
        categories = tuple(c for c in DLPCategory if any(f.category == c for f in findings))
        counts = ", ".join(f"{c.value}({sum(1 for f in findings if f.category == c)})" for c in categories)
        return DLPInspectionResult(
            status=InspectionStatus.DETECTED,
            sensitive_content_detected=True,
            findings=tuple(findings),
            categories=categories,
            highest_severity=max(findings, key=lambda f: f.severity.rank).severity,
            findings_truncated=truncated,
            content_length=len(content),
            rules_evaluated=evaluated,
            summary=f"{len(findings)} finding(s){' (truncated)' if truncated else ''}: {counts}. "
                    "Rule-based detection is not exhaustive.",
            inspected_at=ts,
        )

    @staticmethod
    def _build_findings(content: str, resolved: List[_Candidate]) -> List[DLPFinding]:
        newlines = [i for i, ch in enumerate(content) if ch == "\n"]
        return [
            DLPFinding(
                rule_id=c.rule.rule_id,
                category=c.rule.category,
                severity=c.rule.severity,
                start=c.start,
                end=c.end,
                line=bisect_right(newlines, c.start - 1) + 1,
                confidence=c.rule.confidence,
                redacted_preview=f"[REDACTED:{c.rule.rule_id}:{c.end - c.start}]",
            )
            for c in resolved
        ]

    @staticmethod
    def _failed(code: DLPErrorCode, length: int, evaluated: int, ts: datetime, detail: str) -> DLPInspectionResult:
        return DLPInspectionResult(
            status=InspectionStatus.FAILED,
            sensitive_content_detected=False,
            content_length=length,
            rules_evaluated=evaluated,
            error_code=code,
            summary=f"Inspection failed: {detail}. Content must not be treated as verified safe.",
            inspected_at=ts,
        )


DEFAULT_ENGINE = DLPEngine()


def inspect_content(content: Any, engine: Optional[DLPEngine] = None) -> DLPInspectionResult:
    """Inspect ``content`` with ``engine`` (default: built-in rules)."""
    return (engine or DEFAULT_ENGINE).inspect(content)


def redact_text(content: str, result: DLPInspectionResult) -> str:
    """Return ``content`` with every finding span replaced by ``[REDACTED:<category>]``.

    Overlapping spans from different categories are merged into one redaction.

    Raises:
        ValueError: if ``result`` is FAILED or its spans do not fit ``content``.
    """
    if result.status == InspectionStatus.FAILED:
        raise ValueError("cannot redact using a failed inspection result")
    if result.content_length != len(content) or any(f.end > len(content) for f in result.findings):
        raise ValueError("inspection result does not correspond to this content")
    merged: List[List[Any]] = []
    for f in sorted(result.findings, key=lambda f: (f.start, f.end)):
        if merged and f.start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], f.end)
        else:
            merged.append([f.start, f.end, f.category.value])
    out, pos = [], 0
    for start, end, label in merged:
        out.append(content[pos:start])
        out.append(f"[REDACTED:{label}]")
        pos = end
    out.append(content[pos:])
    return "".join(out)
