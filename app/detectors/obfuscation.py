"""
Detects encoded-payload obfuscation -- an attacker base64/hex/rot13-encodes
an injection attempt so it slips past plain-text pattern matching, then asks
the model to decode and follow it. This detector doesn't just flag "there's
a base64 blob here" (way too noisy -- base64 shows up in legitimate
requests constantly); it decodes candidate blobs and re-runs the injection
detector against the decoded text, only flagging when the *decoded* content
itself looks like an injection attempt.
"""
import base64
import codecs
import re
from dataclasses import dataclass, field

from app.detectors.injection import detect as detect_injection

BASE64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
HEX_CANDIDATE = re.compile(r"(?:[0-9a-fA-F]{2}){10,}")


@dataclass
class Finding:
    detector: str
    confidence: float
    matches: list = field(default_factory=list)

    @property
    def triggered(self) -> bool:
        return self.confidence > 0.0


def _try_base64(candidate: str):
    try:
        decoded = base64.b64decode(candidate, validate=True)
        return decoded.decode("utf-8", errors="strict")
    except Exception:
        return None


def _try_hex(candidate: str):
    try:
        decoded = bytes.fromhex(candidate)
        return decoded.decode("utf-8", errors="strict")
    except Exception:
        return None


def _try_rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


def detect(text: str) -> Finding:
    if not text:
        return Finding(detector="obfuscation", confidence=0.0)

    matches = []
    best_confidence = 0.0

    # rot13 is applied to the whole text since it's a 1:1 character
    # substitution cipher with no delimiters to search for.
    rot13_decoded = _try_rot13(text)
    inner = detect_injection(rot13_decoded)
    if inner.triggered:
        matches.append(("rot13_injection", f"decoded: {rot13_decoded[:80]}"))
        best_confidence = max(best_confidence, inner.confidence * 0.9)

    for candidate in BASE64_CANDIDATE.findall(text):
        decoded = _try_base64(candidate)
        if decoded is None or len(decoded) < 8:
            continue
        inner = detect_injection(decoded)
        if inner.triggered:
            matches.append(("base64_injection", f"decoded: {decoded[:80]}"))
            best_confidence = max(best_confidence, inner.confidence * 0.95)

    for candidate in HEX_CANDIDATE.findall(text):
        decoded = _try_hex(candidate)
        if decoded is None or len(decoded) < 8:
            continue
        inner = detect_injection(decoded)
        if inner.triggered:
            matches.append(("hex_injection", f"decoded: {decoded[:80]}"))
            best_confidence = max(best_confidence, inner.confidence * 0.95)

    return Finding(detector="obfuscation", confidence=best_confidence, matches=matches)
