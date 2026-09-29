"""
The actual guardrail pipeline -- inbound detection -> policy -> enforcement,
then (if not blocked) the upstream call, then outbound detection -> policy
-> enforcement. Pulled out of main.py so it can be unit- and
integration-tested as plain Python without spinning up FastAPI's TestClient
for every case; main.py is a thin HTTP wrapper around this module.
"""
import uuid
from dataclasses import dataclass, field

from app import enforcement
from app.audit_log import AuditLogger
from app.detectors import injection, obfuscation, pii, secrets
from app.policy import Policy

INBOUND_DETECTORS = ["injection", "obfuscation", "pii"]
OUTBOUND_DETECTORS = ["secrets", "system_prompt_leak", "pii"]


@dataclass
class SideResult:
    text: str
    blocked: bool
    blocked_reason: str | None = None
    events: list = field(default_factory=list)  # list of enforcement.EnforcementResult


def _run_inbound_detectors(text: str) -> dict:
    return {
        "injection": injection.detect(text),
        "obfuscation": obfuscation.detect(text),
        "pii": pii.detect(text),
    }


def _run_outbound_detectors(text: str, system_prompt: str | None) -> dict:
    findings = {
        "secrets": secrets.detect_secrets(text),
        "pii": pii.detect(text),
    }
    if system_prompt:
        findings["system_prompt_leak"] = secrets.detect_system_prompt_leak(text, system_prompt)
    else:
        findings["system_prompt_leak"] = secrets.Finding(detector="system_prompt_leak", confidence=0.0)
    return findings


def evaluate(side: str, text: str, policy: Policy, request_id: str, audit: AuditLogger,
             system_prompt: str | None = None) -> SideResult:
    findings = _run_inbound_detectors(text) if side == "inbound" else _run_outbound_detectors(text, system_prompt)

    current_text = text
    blocked = False
    blocked_reason = None
    events = []

    # Deterministic order so "which rule fired first" is reproducible and
    # testable, rather than depending on dict iteration order by accident.
    detector_order = INBOUND_DETECTORS if side == "inbound" else OUTBOUND_DETECTORS

    for detector_name in detector_order:
        finding = findings[detector_name]
        action, rule = policy.decide(side, detector_name, finding.confidence)

        audit.log(
            request_id=request_id,
            side=side,
            detector=detector_name,
            confidence=finding.confidence,
            action=action,
            rule_id=rule.id if rule else None,
            blocked=(action == "block"),
            matched_patterns=finding.matches,
        )

        if action == "allow":
            continue

        spans = getattr(finding, "spans", None)
        result = enforcement.apply(side, detector_name, finding.confidence, action,
                                    rule.id if rule else None, current_text, spans=spans)
        events.append(result)

        if result.blocked:
            blocked = True
            blocked_reason = f"{detector_name} ({rule.id if rule else 'no rule'}): confidence {finding.confidence:.2f}"
            break  # no point evaluating further detectors once we're blocking

        current_text = result.text  # carry forward any redaction to the next detector

    return SideResult(text=current_text, blocked=blocked, blocked_reason=blocked_reason, events=events)


def run_pipeline(messages: list[dict], policy: Policy, audit: AuditLogger, backend, request_id: str = None) -> dict:
    """End-to-end: inbound gate -> upstream call -> outbound gate.

    Returns a dict shaped like a trimmed OpenAI chat completion response,
    plus a `promptshield` block describing what the gate did -- callers
    that don't care can ignore it, and it's exactly what the demo app and
    tests inspect to verify enforcement actually happened.
    """
    request_id = request_id or str(uuid.uuid4())
    system_prompt = next((m["content"] for m in messages if m.get("role") == "system"), None)
    user_messages = [m for m in messages if m.get("role") == "user"]
    last_user_text = user_messages[-1]["content"] if user_messages else ""

    inbound = evaluate("inbound", last_user_text, policy, request_id, audit, system_prompt)
    if inbound.blocked:
        return {
            "id": request_id,
            "blocked": True,
            "stage": "inbound",
            "reason": inbound.blocked_reason,
            "choices": [],
            "promptshield": {"inbound_events": [vars(e) for e in inbound.events], "outbound_events": []},
        }

    # Forward the (possibly redacted) messages upstream.
    outgoing_messages = [dict(m) for m in messages]
    for m in outgoing_messages:
        if m.get("role") == "user" and m.get("content") == last_user_text:
            m["content"] = inbound.text

    completion_text = backend.complete(outgoing_messages)

    outbound = evaluate("outbound", completion_text, policy, request_id, audit, system_prompt)
    if outbound.blocked:
        return {
            "id": request_id,
            "blocked": True,
            "stage": "outbound",
            "reason": outbound.blocked_reason,
            "choices": [],
            "promptshield": {"inbound_events": [vars(e) for e in inbound.events],
                              "outbound_events": [vars(e) for e in outbound.events]},
        }

    return {
        "id": request_id,
        "blocked": False,
        "choices": [{"message": {"role": "assistant", "content": outbound.text}}],
        "promptshield": {"inbound_events": [vars(e) for e in inbound.events],
                          "outbound_events": [vars(e) for e in outbound.events]},
    }
