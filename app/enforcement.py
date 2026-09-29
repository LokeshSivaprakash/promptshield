"""
Turns a policy decision into an actual change to the text flowing through
the proxy: redact replaces matched spans in place, block short-circuits the
whole request, flag passes the text through unchanged but logs at elevated
severity for human review. allow is a no-op.

This is separate from policy.py on purpose -- policy.py decides *what*
action a finding warrants, this module carries out *how* that action
changes the actual request/response text. Keeping them separate means the
policy engine can be unit-tested against confidence scores alone, with no
string-manipulation edge cases involved.
"""
from dataclasses import dataclass


@dataclass
class EnforcementResult:
    action: str
    text: str              # possibly redacted text; unchanged for allow/flag/block
    blocked: bool
    rule_id: str | None
    detector: str
    confidence: float


def redact_spans(text: str, spans) -> str:
    """Replace each span with a [REDACTED:<TYPE>] marker. Spans are
    processed back-to-front so earlier offsets stay valid as later ones
    are replaced (redaction changes string length)."""
    if not spans:
        return text
    ordered = sorted(spans, key=lambda s: s.start, reverse=True)
    result = text
    for span in ordered:
        marker = f"[REDACTED:{span.pii_type}]"
        result = result[: span.start] + marker + result[span.end:]
    return result


def apply(side: str, detector_name: str, confidence: float, action: str, rule_id: str | None,
          text: str, spans=None) -> EnforcementResult:
    if action == "block":
        return EnforcementResult(action="block", text=text, blocked=True,
                                  rule_id=rule_id, detector=detector_name, confidence=confidence)

    if action == "redact":
        if spans:
            redacted = redact_spans(text, spans)
        else:
            # A detector without span-level output (e.g. injection, secrets)
            # can still be configured for "redact" in a policy, but there's
            # nothing precise to redact -- fail toward the safer behavior
            # (block) rather than silently letting the original text through.
            return EnforcementResult(action="block", text=text, blocked=True,
                                      rule_id=rule_id, detector=detector_name, confidence=confidence)
        return EnforcementResult(action="redact", text=redacted, blocked=False,
                                  rule_id=rule_id, detector=detector_name, confidence=confidence)

    if action == "flag":
        return EnforcementResult(action="flag", text=text, blocked=False,
                                  rule_id=rule_id, detector=detector_name, confidence=confidence)

    return EnforcementResult(action="allow", text=text, blocked=False,
                              rule_id=rule_id, detector=detector_name, confidence=confidence)
