"""
Heuristic prompt-injection / jailbreak detection.

This is deliberately NOT a machine-learning classifier for the MVP -- see
the README roadmap for why that's a stretch goal rather than a claimed
feature. It's a transparent, auditable rule set: a curated phrase library
(the patterns real jailbreak attempts actually use -- DAN-style roleplay
overrides, instruction-override framing, delimiter injection) plus a small
set of structural heuristics, combined into a single confidence score.

Every detector in this package returns the same shape -- a Finding with a
0.0-1.0 confidence and a list of (pattern, matched_text) pairs -- so the
policy engine can treat injection/pii/secrets/obfuscation detectors
uniformly.
"""
import re
from dataclasses import dataclass, field


@dataclass
class Finding:
    detector: str
    confidence: float
    matches: list = field(default_factory=list)  # list of (pattern_id, matched_text)

    @property
    def triggered(self) -> bool:
        return self.confidence > 0.0


# Phrases drawn from documented jailbreak techniques (DAN and its variants,
# instruction-override framing, delimiter/role injection). Grouped by how
# strong a signal each one is on its own -- a single weak-signal phrase
# shouldn't block a request; several together should.
STRONG_PATTERNS = [
    # Proximity-based rather than a rigid word list -- "ignore all previous
    # instructions", "ignore the instructions above", "ignore your prior
    # system instructions" all need to match, not just single-modifier
    # phrasing. Bounded window (.{0,25}) keeps it from matching across
    # unrelated sentences.
    (r"\bignore\b.{0,25}\binstructions?\b", "ignore_instructions"),
    (r"\bdisregard\b.{0,25}\binstructions?\b", "disregard_instructions"),
    (r"\byou are (now|no longer) (in )?(dan|developer mode|jailbreak)", "persona_override"),
    (r"\bpretend (you have|to have) no (restrictions|rules|guidelines|limits)", "pretend_unrestricted"),
    (r"\breveal (your|the) system prompt\b", "reveal_system_prompt"),
    (r"\bprint (your|the) (system prompt|instructions)\b", "print_instructions"),
    (r"\brepeat (the words|everything) above\b", "repeat_above"),
    (r"\bact as if you have no (guidelines|restrictions|filters)\b", "act_unrestricted"),
    (r"\bdo anything now\b", "dan_phrase"),
    (r"\byou must (now )?(obey|comply)\b", "must_obey"),
    (r"\bthis is a hypothetical (scenario|world) where you have no rules\b", "hypothetical_norules"),
]

WEAK_PATTERNS = [
    (r"^\s*(system|assistant)\s*:\s*", "role_prefix_injection"),
    (r"###\s*(instruction|system|override)", "delimiter_injection"),
    (r"\bnew instructions?\s*:", "new_instructions_marker"),
    (r"\bfrom now on\b", "from_now_on"),
    (r"\byour (real|true|actual) (purpose|goal|instructions) (is|are)\b", "true_purpose_claim"),
    (r"\bignore (that|what) (i|I) (just )?said\b", "retract_and_override"),
]

STRONG_WEIGHT = 0.55
WEAK_WEIGHT = 0.25
MAX_CONFIDENCE = 0.98


def detect(text: str) -> Finding:
    if not text:
        return Finding(detector="injection", confidence=0.0)

    lowered = text.lower()
    matches = []
    score = 0.0

    for pattern, pattern_id in STRONG_PATTERNS:
        if re.search(pattern, lowered):
            score += STRONG_WEIGHT
            matches.append((pattern_id, pattern))

    for pattern, pattern_id in WEAK_PATTERNS:
        if re.search(pattern, lowered):
            score += WEAK_WEIGHT
            matches.append((pattern_id, pattern))

    confidence = min(score, MAX_CONFIDENCE) if matches else 0.0
    return Finding(detector="injection", confidence=confidence, matches=matches)
