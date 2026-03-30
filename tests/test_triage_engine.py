"""
Unit tests for soar_automation/triage/triage_engine.py
"""
import pytest
from soar_automation.triage.triage_engine import TriageEngine, Priority


@pytest.fixture
def engine():
    return TriageEngine()


def make_alert(rule_level=10, mitre_tactic_ids=None):
    return {
        "id": "test-001",
        "rule": {"level": rule_level, "mitre": {"tactic_id": mitre_tactic_ids or []}},
    }


class TestTriageEngine:
    def test_returns_result(self, engine):
        r = engine.triage(alert=make_alert(), ioc_score=0.0)
        assert hasattr(r, "priority") and hasattr(r, "score") and hasattr(r, "rationale")

    def test_high_ioc_raises_priority(self, engine):
        r = engine.triage(alert=make_alert(rule_level=10), ioc_score=95.0)
        assert r.priority in [Priority.CRITICAL, Priority.HIGH]

    def test_low_score_low_priority(self, engine):
        r = engine.triage(alert=make_alert(rule_level=1), ioc_score=0.0)
        assert r.priority in [Priority.LOW, Priority.INFO, Priority.MEDIUM]

    def test_mitre_tactic_boosts_score(self, engine):
        with_tactic    = engine.triage(make_alert(rule_level=5, mitre_tactic_ids=["TA0006"]), ioc_score=50.0)
        without_tactic = engine.triage(make_alert(rule_level=5), ioc_score=50.0)
        assert with_tactic.score >= without_tactic.score

    def test_rationale_is_list(self, engine):
        r = engine.triage(alert=make_alert(), ioc_score=30.0)
        assert isinstance(r.rationale, list) and len(r.rationale) > 0

    def test_playbook_for_malicious_ip(self, engine):
        alert = make_alert(rule_level=12)
        alert["ioc_verdict"] = "MALICIOUS"
        alert["ioc_type"]    = "ip"
        r = engine.triage(alert=alert, ioc_score=90.0)
        assert r.recommended_playbook == "malicious_ip"
