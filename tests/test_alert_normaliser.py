"""
Unit tests for wazuh_integration/parsers/alert_normaliser.py
"""
import pytest
import json
from pathlib import Path
from wazuh_integration.parsers.alert_normaliser import normalise_alert, NormalisedAlert


@pytest.fixture
def sample_alert():
    with open(Path(__file__).resolve().parents[1] / "samples" / "sample_alert.json") as f:
        return json.load(f)


class TestAlertNormaliser:
    def test_normalise_returns_normalised_alert(self, sample_alert):
        result = normalise_alert(sample_alert)
        assert isinstance(result, NormalisedAlert)

    def test_normalised_has_alert_id(self, sample_alert):
        result = normalise_alert(sample_alert)
        assert result.alert_id and len(result.alert_id) > 0

    def test_severity_is_string(self, sample_alert):
        result = normalise_alert(sample_alert)
        assert result.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def test_rule_level_extracted(self, sample_alert):
        result = normalise_alert(sample_alert)
        assert result.rule_level == 10

    def test_agent_name_extracted(self, sample_alert):
        result = normalise_alert(sample_alert)
        assert result.agent_name == "prod-web-01"

    def test_description_populated(self, sample_alert):
        result = normalise_alert(sample_alert)
        assert len(result.rule_name) > 0

    def test_malformed_alert_returns_none(self):
        assert normalise_alert(None) is None

    def test_empty_alert_returns_normalised_alert(self):
        result = normalise_alert({})
        assert isinstance(result, NormalisedAlert)

    def test_src_ip_extracted_as_ioc(self, sample_alert):
        result = normalise_alert(sample_alert)
        ioc_values = [ioc.value for ioc in result.iocs]
        assert "185.220.101.45" in ioc_values

    def test_source_is_wazuh(self, sample_alert):
        result = normalise_alert(sample_alert)
        assert result.source == "wazuh"
