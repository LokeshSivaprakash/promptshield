"""
PII detection for inbound prompts and outbound completions.

Regex-based by default (no heavy dependency required to run this project).
If Microsoft Presidio is installed, it's used as an additional layer whose
findings are merged in -- see README for why that's optional rather than
required: Presidio's model download is a multi-hundred-MB dependency that
would make `pip install -r requirements.txt` fail in exactly the kind of
locked-down environment this proxy is meant to run in, so the regex layer
has to stand on its own.

Each finding records the byte span so enforcement.py can redact precisely,
not just flag the whole message.
"""
import re
from dataclasses import dataclass, field

try:
    from presidio_analyzer import AnalyzerEngine  # type: ignore
    _PRESIDIO_AVAILABLE = True
    _analyzer = None  # lazy-initialized, it's slow to construct
except ImportError:
    _PRESIDIO_AVAILABLE = False
    _analyzer = None


@dataclass
class Span:
    pii_type: str
    start: int
    end: int
    text: str


@dataclass
class Finding:
    detector: str
    confidence: float
    matches: list = field(default_factory=list)  # list of Span
    spans: list = field(default_factory=list)     # alias kept for enforcement.py clarity

    @property
    def triggered(self) -> bool:
        return self.confidence > 0.0


EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")


def _luhn_valid(digits: str) -> bool:
    """Standard Luhn checksum -- used to cut credit-card false positives on
    arbitrary 13-19 digit strings (order numbers, phone-like sequences)."""
    digits = [int(d) for d in digits]
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _find_regex(pattern: re.Pattern, text: str, pii_type: str, validator=None):
    spans = []
    for m in pattern.finditer(text):
        matched = m.group(0)
        if validator is not None:
            digits_only = re.sub(r"[ -]", "", matched)
            if len(digits_only) < 13 or not _luhn_valid(digits_only):
                continue
        spans.append(Span(pii_type, m.start(), m.end(), matched))
    return spans


def _run_presidio(text: str):
    global _analyzer
    if _analyzer is None:
        _analyzer = AnalyzerEngine()
    results = _analyzer.analyze(text=text, language="en")
    return [Span(r.entity_type, r.start, r.end, text[r.start:r.end]) for r in results]


def detect(text: str) -> Finding:
    if not text:
        return Finding(detector="pii", confidence=0.0)

    spans = []
    spans += _find_regex(EMAIL_RE, text, "EMAIL")
    spans += _find_regex(PHONE_RE, text, "PHONE")
    spans += _find_regex(SSN_RE, text, "SSN")
    spans += _find_regex(CREDIT_CARD_RE, text, "CREDIT_CARD", validator=_luhn_valid)
    spans += _find_regex(IPV4_RE, text, "IP_ADDRESS")

    if _PRESIDIO_AVAILABLE:
        try:
            spans += _run_presidio(text)
        except Exception:
            # Presidio is best-effort enrichment; never let it take the
            # whole detector down if its model files aren't available.
            pass

    if not spans:
        return Finding(detector="pii", confidence=0.0)

    # Confidence scales with how many distinct PII types were found, not
    # just count -- three emails is one kind of leak, an email + SSN +
    # credit card together is a much bigger one.
    distinct_types = {s.pii_type for s in spans}
    confidence = min(0.4 + 0.2 * len(distinct_types), 0.95)
    matches = [(s.pii_type, s.text) for s in spans]
    return Finding(detector="pii", confidence=confidence, matches=matches, spans=spans)
