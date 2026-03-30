"""
Unit tests for wazuh-integration/parsers/ioc_extractor.py
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "wazuh-integration"))

import pytest
from parsers.ioc_extractor import extract_iocs_from_text, extract_iocs_from_alert


class TestIoCExtractor:
    def test_extract_returns_list(self):
        result = extract_iocs_from_text("Suspicious traffic from 185.220.101.45")
        assert isinstance(result, list)

    def test_extract_public_ip(self):
        result = extract_iocs_from_text("Suspicious traffic from 185.220.101.45")
        values = [item["value"] for item in result]
        assert "185.220.101.45" in values

    def test_private_ip_excluded(self):
        result = extract_iocs_from_text("Traffic from 192.168.1.1")
        values = [item["value"] for item in result]
        assert "192.168.1.1" not in values

    def test_extract_url(self):
        result = extract_iocs_from_text("Request to http://malicious.com/payload")
        types = [item["type"] for item in result]
        assert "url" in types

    def test_extract_sha256(self):
        sha = "a" * 64
        result = extract_iocs_from_text(f"File hash: {sha}")
        types = [item["type"] for item in result]
        assert "sha256" in types

    def test_extract_md5(self):
        md5 = "b" * 32
        result = extract_iocs_from_text(f"MD5: {md5}")
        types = [item["type"] for item in result]
        assert "md5" in types

    def test_empty_string_returns_empty_list(self):
        result = extract_iocs_from_text("")
        assert result == []

    def test_extract_from_alert_dict(self):
        alert = {
            "src_ip": "185.220.101.45",
            "description": "Brute force attempt",
        }
        result = extract_iocs_from_alert(alert)
        assert isinstance(result, list)
        values = [item["value"] for item in result]
        assert "185.220.101.45" in values

    def test_ioc_has_type_and_value_keys(self):
        result = extract_iocs_from_text("IP: 8.8.8.8")
        for ioc in result:
            assert "type" in ioc
            assert "value" in ioc
