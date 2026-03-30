"""
Unit tests for ioc_pipeline/verdict_engine.py
"""
import pytest
from ioc_pipeline.verdict_engine import VerdictEngine


@pytest.fixture
def engine():
    return VerdictEngine()


def make_enrichment(vt_malicious=0, vt_total=70, abuse_score=0, vulns=None, tags=None):
    harmless = vt_total - vt_malicious
    return {
        "virustotal": {"malicious": vt_malicious, "suspicious": 0,
                       "harmless": harmless, "undetected": 0, "reputation": -vt_malicious * 5},
        "abuseipdb":  {"abuse_confidence_score": abuse_score, "is_whitelisted": False},
        "shodan":     {"open_ports": [], "vulns": vulns or [], "tags": tags or []},
    }


class TestVerdictEngine:
    def test_clean_verdict(self, engine):
        r = engine.compute(make_enrichment())
        assert r["verdict"] == "CLEAN"
        assert 0 <= r["confidence"] <= 100

    def test_malicious_verdict(self, engine):
        r = engine.compute(make_enrichment(vt_malicious=50, abuse_score=90))
        assert r["verdict"] == "MALICIOUS"

    def test_suspicious_verdict(self, engine):
        r = engine.compute(make_enrichment(vt_malicious=5, abuse_score=30))
        assert r["verdict"] in ["SUSPICIOUS", "MALICIOUS"]

    def test_confidence_range(self, engine):
        r = engine.compute(make_enrichment(vt_malicious=2, abuse_score=20))
        assert 0 <= r["confidence"] <= 100

    def test_vulns_not_clean(self, engine):
        r = engine.compute(make_enrichment(vulns=["CVE-2021-44228"]))
        assert r["verdict"] in ["SUSPICIOUS", "MALICIOUS"]

    def test_error_source_graceful(self, engine):
        r = engine.compute({"virustotal": {"error": "not_found"},
                             "abuseipdb": {"abuse_confidence_score": 0, "is_whitelisted": False},
                             "shodan": {"open_ports": [], "vulns": [], "tags": []}})
        assert "verdict" in r

    def test_component_scores_present(self, engine):
        r = engine.compute(make_enrichment(vt_malicious=10, abuse_score=50))
        assert all(k in r["component_scores"] for k in ["virustotal", "abuseipdb", "shodan"])
