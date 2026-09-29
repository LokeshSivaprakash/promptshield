import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.policy import Policy, Rule


def test_rule_validates_action():
    with pytest.raises(ValueError):
        Rule(id="bad", match="inbound", detector="injection", min_confidence=0.5, action="delete")


def test_rule_validates_match_side():
    with pytest.raises(ValueError):
        Rule(id="bad", match="sideways", detector="injection", min_confidence=0.5, action="block")


def test_rule_validates_confidence_range():
    with pytest.raises(ValueError):
        Rule(id="bad", match="inbound", detector="injection", min_confidence=1.5, action="block")


def test_decide_returns_first_matching_rule_in_order():
    policy = Policy.from_dict({
        "rules": [
            {"id": "strict", "match": "inbound", "detector": "injection", "min_confidence": 0.3, "action": "block"},
            {"id": "loose", "match": "inbound", "detector": "injection", "min_confidence": 0.1, "action": "flag"},
        ]
    })
    action, rule = policy.decide("inbound", "injection", 0.5)
    assert action == "block"
    assert rule.id == "strict"


def test_decide_falls_through_to_second_rule_when_first_threshold_not_met():
    policy = Policy.from_dict({
        "rules": [
            {"id": "strict", "match": "inbound", "detector": "injection", "min_confidence": 0.9, "action": "block"},
            {"id": "loose", "match": "inbound", "detector": "injection", "min_confidence": 0.1, "action": "flag"},
        ]
    })
    action, rule = policy.decide("inbound", "injection", 0.5)
    assert action == "flag"
    assert rule.id == "loose"


def test_decide_defaults_to_allow_with_no_matching_rule():
    policy = Policy.from_dict({"rules": []})
    action, rule = policy.decide("inbound", "injection", 0.9)
    assert action == "allow"
    assert rule is None


def test_default_policy_loads_and_is_well_formed():
    from app.policy import load_default_policy
    policy = load_default_policy()
    assert len(policy.rules) > 0
    for rule in policy.rules:
        assert rule.match in ("inbound", "outbound")
        assert rule.action in ("allow", "redact", "block", "flag")
