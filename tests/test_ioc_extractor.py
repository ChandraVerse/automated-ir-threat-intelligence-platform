"""
Unit tests for wazuh-integration/parsers/ioc_extractor.py
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from wazuh_integration.parsers.ioc_extractor import (
    extract_iocs_from_text,
    extract_iocs_from_alert,
    _is_private_ip,
)


class TestIsPrivateIP:
    def test_private_10_range(self):
        assert _is_private_ip("10.0.0.1") is True

    def test_private_172_range(self):
        assert _is_private_ip("172.16.0.1") is True

    def test_private_192_range(self):
        assert _is_private_ip("192.168.1.100") is True

    def test_loopback(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_public_ip(self):
        assert _is_private_ip("185.220.101.45") is False

    def test_public_ip2(self):
        assert _is_private_ip("8.8.8.8") is False


class TestExtractIOCsFromText:
    def test_extracts_public_ip(self):
        iocs = extract_iocs_from_text("Connection from 185.220.101.45 port 443")
        assert any(i["type"] == "ip" and i["value"] == "185.220.101.45" for i in iocs)

    def test_filters_private_ip(self):
        iocs = extract_iocs_from_text("Traffic from 192.168.1.1")
        assert not any(i["value"] == "192.168.1.1" for i in iocs)

    def test_extracts_sha256(self):
        sha = "a" * 64
        iocs = extract_iocs_from_text(f"File hash: {sha}")
        assert any(i["type"] == "sha256" and i["value"] == sha for i in iocs)

    def test_extracts_md5(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        iocs = extract_iocs_from_text(f"MD5: {md5}")
        assert any(i["type"] == "md5" for i in iocs)

    def test_extracts_url(self):
        iocs = extract_iocs_from_text("Callback to http://malware.example.com/c2")
        assert any(i["type"] == "url" for i in iocs)

    def test_deduplication(self):
        iocs = extract_iocs_from_text("185.220.101.45 and again 185.220.101.45")
        ip_iocs = [i for i in iocs if i["value"] == "185.220.101.45"]
        assert len(ip_iocs) == 1

    def test_no_iocs_in_clean_text(self):
        iocs = extract_iocs_from_text("System startup completed successfully.")
        assert len(iocs) == 0


class TestExtractIOCsFromAlert:
    def test_structured_src_ip(self):
        alert = {"src_ip": "185.220.101.45", "description": "test"}
        iocs = extract_iocs_from_alert(alert)
        assert any(i["type"] == "ip" and i["value"] == "185.220.101.45" for i in iocs)

    def test_private_src_ip_excluded(self):
        alert = {"src_ip": "10.0.0.5"}
        iocs = extract_iocs_from_alert(alert)
        assert not any(i["value"] == "10.0.0.5" for i in iocs)

    def test_structured_file_hash_sha256(self):
        sha = "b" * 64
        alert = {"file_hash": sha}
        iocs = extract_iocs_from_alert(alert)
        assert any(i["type"] == "sha256" for i in iocs)

    def test_full_log_fallback(self):
        alert = {
            "full_log": "Suspicious connection from 203.0.113.5",
            "src_ip": None,
        }
        iocs = extract_iocs_from_alert(alert)
        assert any(i["value"] == "203.0.113.5" for i in iocs)

    def test_email_user_field(self):
        alert = {"user": "attacker@evil.com"}
        iocs = extract_iocs_from_alert(alert)
        assert any(i["type"] == "email" for i in iocs)
