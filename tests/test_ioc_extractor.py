"""
Unit tests for wazuh_integration/parsers/ioc_extractor.py
"""
import pytest
from wazuh_integration.parsers.ioc_extractor import extract_iocs_from_text, extract_iocs_from_alert


class TestIoCExtractor:
    def test_extract_returns_list(self):
        assert isinstance(extract_iocs_from_text("Traffic from 185.220.101.45"), list)

    def test_extract_public_ip(self):
        result = extract_iocs_from_text("Traffic from 185.220.101.45")
        assert "185.220.101.45" in [i["value"] for i in result]

    def test_private_ip_excluded(self):
        result = extract_iocs_from_text("Traffic from 192.168.1.1")
        assert "192.168.1.1" not in [i["value"] for i in result]

    def test_extract_url(self):
        result = extract_iocs_from_text("Request to http://malicious.com/payload")
        assert "url" in [i["type"] for i in result]

    def test_extract_sha256(self):
        result = extract_iocs_from_text(f"Hash: {'a' * 64}")
        assert "sha256" in [i["type"] for i in result]

    def test_extract_md5(self):
        result = extract_iocs_from_text(f"MD5: {'b' * 32}")
        assert "md5" in [i["type"] for i in result]

    def test_empty_string_returns_empty(self):
        assert extract_iocs_from_text("") == []

    def test_extract_from_alert_dict(self):
        result = extract_iocs_from_alert({"src_ip": "185.220.101.45"})
        assert "185.220.101.45" in [i["value"] for i in result]

    def test_ioc_has_type_and_value(self):
        for ioc in extract_iocs_from_text("IP: 8.8.8.8"):
            assert "type" in ioc and "value" in ioc
