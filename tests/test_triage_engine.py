"""
Unit tests for soar-automation/triage/triage_engine.py
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "soar-automation"))

import pytest
from triage.triage_engine import TriageEngine, Priority


@pytest.fixture
def engine():
    return TriageEngine()


def make_alert(rule_level=10, mitre_tactic_ids=None):
    return {
        "id": "test-alert-001",
        "rule": {
            "level": rule_level,
            "description": "Test alert",
            "mitre": {
                "tactic_id": mitre_tactic_ids or [],
            },
        },
    }


class TestTriageEngine:
    def test_triage_returns_result(self, engine):
        result = engine.triage(alert=make_alert(), ioc_score=0.0)
        assert result is not None
        assert hasattr(result, "priority")
        assert hasattr(result, "score")
        assert hasattr(result, "rationale")

    def test_high_ioc_score_raises_priority(self, engine):
        result = engine.triage(alert=make_alert(rule_level=10), ioc_score=95.0)
        assert result.priority in [Priority.CRITICAL, Priority.HIGH]

    def test_low_score_gives_low_priority(self, engine):
        result = engine.triage(alert=make_alert(rule_level=1), ioc_score=0.0)
        assert result.priority in [Priority.LOW, Priority.INFO, Priority.MEDIUM]

    def test_mitre_high_impact_tactic_boosts_score(self, engine):
        result_with = engine.triage(
            alert=make_alert(rule_level=5, mitre_tactic_ids=["TA0006"]),
            ioc_score=50.0
        )
        result_without = engine.triage(
            alert=make_alert(rule_level=5, mitre_tactic_ids=[]),
            ioc_score=50.0
        )
        assert result_with.score >= result_without.score

    def test_rationale_is_list(self, engine):
        result = engine.triage(alert=make_alert(), ioc_score=30.0)
        assert isinstance(result.rationale, list)
        assert len(result.rationale) > 0

    def test_playbook_recommended_for_malicious_ip(self, engine):
        alert = make_alert(rule_level=12)
        alert["ioc_verdict"] = "MALICIOUS"
        alert["ioc_type"] = "ip"
        result = engine.triage(alert=alert, ioc_score=90.0)
        assert result.recommended_playbook is not None
