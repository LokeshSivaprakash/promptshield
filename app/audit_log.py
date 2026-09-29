"""
Structured audit logging for every policy decision PromptShield makes.

Each event is one JSON line (JSONL), written to stdout and optionally to a
file -- either works as a collection source for Sentinel's Log Analytics
custom table ingestion (Data Collection Rule / Logs Ingestion API), or for
the Log Analytics agent tailing a file. Field names deliberately mirror the
MeridianLogs_CL convention from this author's Meridian project so the two
data sources can be queried with a consistent shape in the same workspace
-- see queries/promptshield_detections.kql for example KQL against this
schema once it's landed in Sentinel.
"""
import json
import os
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field


@dataclass
class AuditEvent:
    event_id: str
    timestamp: str
    request_id: str
    side: str                  # 'inbound' | 'outbound'
    detector: str
    confidence: float
    action: str                # 'allow' | 'redact' | 'block' | 'flag'
    rule_id: str | None
    blocked: bool
    matched_patterns: list = field(default_factory=list)


class AuditLogger:
    def __init__(self, log_path: str | None = None):
        self.log_path = log_path
        self._fh = open(log_path, "a", encoding="utf-8") if log_path else None

    def log(self, request_id: str, side: str, detector: str, confidence: float,
            action: str, rule_id, blocked: bool, matched_patterns=None) -> AuditEvent:
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            request_id=request_id,
            side=side,
            detector=detector,
            confidence=round(confidence, 3),
            action=action,
            rule_id=rule_id,
            blocked=blocked,
            matched_patterns=[str(m) for m in (matched_patterns or [])],
        )
        line = json.dumps(asdict(event))
        print(line, file=sys.stdout, flush=True)
        if self._fh:
            self._fh.write(line + "\n")
            self._fh.flush()
        return event

    def close(self):
        if self._fh:
            self._fh.close()


_default_logger: AuditLogger | None = None


def get_logger() -> AuditLogger:
    global _default_logger
    if _default_logger is None:
        log_path = os.environ.get("PROMPTSHIELD_AUDIT_LOG_PATH")
        _default_logger = AuditLogger(log_path)
    return _default_logger
