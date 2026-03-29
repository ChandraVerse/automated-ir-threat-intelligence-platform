"""
Unit tests for wazuh-integration/parsers/ioc_extractor.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from wazuh_integration.parsers.ioc_extractor import IoCExtractor


@pytest.fixture
def extractor():
    return IoCExtractor()


class TestIoCExtractor:
    def test_extract_returns_list(self, extractor):
        result = extractor.extract("Suspicious traffic from 185.220.101.45")
        assert isinstance(result, list)

    def test_extract_ip_ioc(self, extractor):
        result = extractor.extract("Suspicious traffic from 185.220.101.45")
        values = [item.get("value") or item.get("ioc") for item in result if isinstance(item, dict)]
        assert "185.220.101.45" in values or any("185.220.101.45" in str(item) for item in result)
