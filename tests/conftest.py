"""
pytest configuration and shared fixtures.
"""

import pytest
import json
from pathlib import Path


@pytest.fixture(scope="session")
def sample_alert_raw():
    path = Path(__file__).resolve().parents[1] / "samples" / "sample_alert.json"
    with open(path) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def sample_config():
    return {
        "threat_intel": {
            "virustotal_api_key": "test_vt_key",
            "abuseipdb_api_key": "test_abuse_key",
            "shodan_api_key": "test_shodan_key",
        },
        "cache": {
            "db_path": ":memory:",
            "ttl_seconds": 86400,
        },
        "soar": {
            "slack_webhook_url": "",
            "jira_url": "",
            "jira_token": "",
            "dry_run": True,
        },
    }
