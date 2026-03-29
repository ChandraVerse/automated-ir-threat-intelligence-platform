"""
Unit tests for ioc-pipeline/verdict_engine.py
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from ioc_pipeline.verdict_engine import VerdictEngine


@pytest.fixture
def engine():
    return VerdictEngine()


def make_vt_result(malicious=0, total=70):
    return {
        "source": "virustotal",
        "malicious_votes": malicious,
        "total_engines": total,
        "reputation": -malicious * 5,
    }


def make_abuse_result(score=0):
    return {
        "source": "abuseipdb",
        "abuse_confidence_score": score,
        "total_reports": score // 10,
    }


def make_shodan_result(ports=None, vulns=None):
    return {
        "source": "shodan",
        "open_ports": ports or [],
        "vulns": vulns or [],
    }


class TestVerdictEngine:
    def test_clean_verdict(self, engine):
        result = engine.compute(
            vt_result=make_vt_result(malicious=0),
            abuse_result=make_abuse_result(score=0),
            shodan_result=make_shodan_result(),
        )
        assert result["verdict"] == "CLEAN"
        assert result["confidence"] >= 0

    def test_malicious_verdict_high_vt(self, engine):
        result = engine.compute(
            vt_result=make_vt_result(malicious=40),
            abuse_result=make_abuse_result(score=90),
            shodan_result=make_shodan_result(),
        )
        assert result["verdict"] == "MALICIOUS"

    def test_suspicious_verdict(self, engine):
        result = engine.compute(
            vt_result=make_vt_result(malicious=5),
            abuse_result=make_abuse_result(score=30),
            shodan_result=make_shodan_result(),
        )
        assert result["verdict"] in ["SUSPICIOUS", "MALICIOUS"]

    def test_confidence_is_percentage(self, engine):
        result = engine.compute(
            vt_result=make_vt_result(malicious=2),
            abuse_result=make_abuse_result(score=20),
            shodan_result=make_shodan_result(),
        )
        assert 0 <= result["confidence"] <= 100

    def test_verdict_with_vulns(self, engine):
        result = engine.compute(
            vt_result=make_vt_result(malicious=0),
            abuse_result=make_abuse_result(score=0),
            shodan_result=make_shodan_result(vulns=["CVE-2021-44228"]),
        )
        # Should not be clean when known vulns are present
        assert result["verdict"] in ["SUSPICIOUS", "MALICIOUS"]

    def test_error_source_handled_gracefully(self, engine):
        result = engine.compute(
            vt_result={"source": "virustotal", "error": "not_found"},
            abuse_result=make_abuse_result(score=0),
            shodan_result=make_shodan_result(),
        )
        assert "verdict" in result
