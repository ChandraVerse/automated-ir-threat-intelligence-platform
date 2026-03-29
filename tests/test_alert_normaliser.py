"""
Unit tests for wazuh-integration/parsers/alert_normaliser.py
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
import json
from wazuh_integration.parsers.alert_normaliser import AlertNormaliser


@pytest.fixture
def normaliser():
    return AlertNormaliser()


@pytest.fixture
def sample_alert():
    with open(Path(__file__).resolve().parents[1] / "samples" / "sample_alert.json") as f:
        return json.load(f)


class TestAlertNormaliser:
    def test_normalise_returns_dict(self, normaliser, sample_alert):
        result = normaliser.normalise(sample_alert)
        assert isinstance(result, dict)

    def test_normalised_has_required_fields(self, normaliser, sample_alert):
        result = normaliser.normalise(sample_alert)
        required = ["id", "timestamp", "severity", "description", "src_ip", "agent"]
        for field in required:
            assert field in result, f"Missing field: {field}"

    def test_severity_is_integer(self, normaliser, sample_alert):
        result = normaliser.normalise(sample_alert)
        assert isinstance(result["severity"], int)

    def test_src_ip_extracted(self, normaliser, sample_alert):
        result = normaliser.normalise(sample_alert)
        assert result["src_ip"] == "185.220.101.45"

    def test_description_populated(self, normaliser, sample_alert):
        result = normaliser.normalise(sample_alert)
        assert len(result["description"]) > 0

    def test_malformed_alert_raises(self, normaliser):
        with pytest.raises(Exception):
            normaliser.normalise(None)

    def test_empty_alert_returns_defaults(self, normaliser):
        result = normaliser.normalise({})
        assert "severity" in result
