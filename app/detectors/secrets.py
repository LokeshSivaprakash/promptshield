"""
Detects leaked secrets and system-prompt leakage in OUTBOUND completions --
the failure mode where the model itself hands back an API key it was given
in context, or recites its system prompt when asked cleverly enough. This
is the outbound half of the guardrail; app/detectors/injection.py and
pii.py run on inbound prompts, this runs on what comes back.
"""
import difflib
import re
from dataclasses import dataclass, field


@dataclass
class Finding:
    detector: str
    confidence: float
    matches: list = field(default_factory=list)

    @property
    def triggered(self) -> bool:
        return self.confidence > 0.0


# (pattern, label) -- key formats for major providers plus generic
# assignment patterns ("api_key = ...", "Authorization: Bearer ...").
SECRET_PATTERNS = [
    (r"\bsk-[A-Za-z0-9]{20,}\b", "openai_api_key"),
    (r"\bAKIA[0-9A-Z]{16}\b", "aws_access_key_id"),
    (r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "github_token"),
    (r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "slack_token"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "private_key_block"),
    (r"\b[Aa]uthorization:\s*Bearer\s+[A-Za-z0-9._-]{15,}", "bearer_token"),
    (r"\b(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}", "generic_secret_assignment"),
]


def detect_secrets(text: str) -> Finding:
    if not text:
        return Finding(detector="secrets", confidence=0.0)

    matches = []
    for pattern, label in SECRET_PATTERNS:
        for m in re.finditer(pattern, text):
            matches.append((label, m.group(0)))

    confidence = min(0.6 + 0.15 * len(matches), 0.98) if matches else 0.0
    return Finding(detector="secrets", confidence=confidence, matches=matches)


def detect_system_prompt_leak(completion: str, system_prompt: str, threshold: float = 0.5) -> Finding:
    """Flag when a completion reproduces a large contiguous chunk of the
    configured system prompt. Uses difflib's longest-matching-block ratio
    rather than naive substring containment, since a model reciting the
    system prompt rarely reproduces it byte-for-byte (it paraphrases
    slightly, or the proxy only has the prompt in a slightly different
    form than what actually got sent upstream).
    """
    if not completion or not system_prompt:
        return Finding(detector="system_prompt_leak", confidence=0.0)

    matcher = difflib.SequenceMatcher(None, system_prompt.lower(), completion.lower())
    ratio = matcher.ratio()
    if ratio < threshold:
        return Finding(detector="system_prompt_leak", confidence=0.0)

    confidence = min(ratio, 0.97)
    return Finding(
        detector="system_prompt_leak",
        confidence=confidence,
        matches=[("similarity_ratio", f"{ratio:.2f}")],
    )
