"""
Policy-as-code engine for PromptShield -- a small YAML DSL, evaluated the
same way RiskWeave's Kyverno policy and CI gate are: rules are data, not
buried in Python conditionals, so a security engineer can change what gets
blocked without touching the proxy's code.

A rule fires when its detector's confidence crosses min_confidence on the
matching side (inbound prompt / outbound completion). The first matching
rule for a given (side, detector) wins -- rules are evaluated in file
order, so put your strictest rules first.

Example policies/default.yaml:

    rules:
      - id: block-direct-injection
        match: inbound
        detector: injection
        min_confidence: 0.5
        action: block

      - id: redact-inbound-pii
        match: inbound
        detector: pii
        min_confidence: 0.4
        action: redact

      - id: block-secret-leak
        match: outbound
        detector: secrets
        min_confidence: 0.5
        action: block
"""
import os
from dataclasses import dataclass

import yaml

VALID_ACTIONS = {"allow", "redact", "block", "flag"}
VALID_SIDES = {"inbound", "outbound"}


@dataclass
class Rule:
    id: str
    match: str
    detector: str
    min_confidence: float
    action: str

    def __post_init__(self):
        if self.match not in VALID_SIDES:
            raise ValueError(f"Rule '{self.id}': match must be one of {VALID_SIDES}, got '{self.match}'")
        if self.action not in VALID_ACTIONS:
            raise ValueError(f"Rule '{self.id}': action must be one of {VALID_ACTIONS}, got '{self.action}'")
        if not 0.0 <= self.min_confidence <= 1.0:
            raise ValueError(f"Rule '{self.id}': min_confidence must be in [0, 1]")


class Policy:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    @classmethod
    def from_yaml(cls, path: str) -> "Policy":
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        rules = [Rule(**r) for r in data.get("rules", [])]
        return cls(rules)

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        rules = [Rule(**r) for r in data.get("rules", [])]
        return cls(rules)

    def rules_for(self, side: str, detector: str) -> list[Rule]:
        return [r for r in self.rules if r.match == side and r.detector == detector]

    def decide(self, side: str, detector: str, confidence: float) -> tuple[str, "Rule | None"]:
        """Return (action, matched_rule). Defaults to 'allow' with no rule
        if nothing in the policy governs this (side, detector) pair, or if
        confidence never crosses any rule's threshold."""
        for rule in self.rules_for(side, detector):
            if confidence >= rule.min_confidence:
                return rule.action, rule
        return "allow", None


DEFAULT_POLICY_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                    "policies", "default.yaml")


def load_default_policy() -> Policy:
    return Policy.from_yaml(DEFAULT_POLICY_PATH)
