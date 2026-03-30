"""
wazuh_integration — Wazuh alert ingestion, parsing, and normalisation.
"""
from wazuh_integration.parsers.alert_normaliser import normalise_alert, normalise_alerts, NormalisedAlert, IOC
from wazuh_integration.parsers.ioc_extractor import extract_iocs_from_text, extract_iocs_from_alert

__all__ = [
    "normalise_alert",
    "normalise_alerts",
    "NormalisedAlert",
    "IOC",
    "extract_iocs_from_text",
    "extract_iocs_from_alert",
]
