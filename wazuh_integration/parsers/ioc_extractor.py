"""
IOC Extractor — extracts Indicators of Compromise from alert text.
Supports: IPv4, MD5, SHA1, SHA256, URLs, email addresses.
"""

import re
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

IPv4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
IPv6_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
MD5_PATTERN    = re.compile(r"\b[0-9a-fA-F]{32}\b")
SHA1_PATTERN   = re.compile(r"\b[0-9a-fA-F]{40}\b")
SHA256_PATTERN = re.compile(r"\b[0-9a-fA-F]{64}\b")
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|edu|gov|io|co|uk|de|ru|cn|info|biz|xyz|online|site|top)\b"
)
URL_PATTERN   = re.compile(r"https?://[^\s\"'<>]+")
EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")

PRIVATE_RANGES = (
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^0\."),
    re.compile(r"^169\.254\."),
)


def _is_private_ip(ip: str) -> bool:
    return any(p.match(ip) for p in PRIVATE_RANGES)


def extract_iocs_from_text(text: str) -> List[Dict]:
    if not text:
        return []
    iocs = []
    for url in URL_PATTERN.findall(text):
        iocs.append({"type": "url", "value": url})
    for email in EMAIL_PATTERN.findall(text):
        iocs.append({"type": "email", "value": email})
    for sha256 in SHA256_PATTERN.findall(text):
        iocs.append({"type": "sha256", "value": sha256.lower()})
    for sha1 in SHA1_PATTERN.findall(text):
        if not any(i["value"] == sha1.lower() for i in iocs):
            iocs.append({"type": "sha1", "value": sha1.lower()})
    for md5 in MD5_PATTERN.findall(text):
        if not any(i["value"] == md5.lower() for i in iocs):
            iocs.append({"type": "md5", "value": md5.lower()})
    for ip in IPv4_PATTERN.findall(text):
        if not _is_private_ip(ip):
            iocs.append({"type": "ip", "value": ip})
    for ip6 in IPv6_PATTERN.findall(text):
        iocs.append({"type": "ipv6", "value": ip6})
    seen = set()
    deduped = []
    for ioc in iocs:
        key = (ioc["type"], ioc["value"])
        if key not in seen:
            seen.add(key)
            deduped.append(ioc)
    return deduped


def extract_iocs_from_alert(alert: dict) -> List[Dict]:
    iocs = []
    src_ip = alert.get("src_ip")
    if src_ip and not _is_private_ip(src_ip):
        iocs.append({"type": "ip", "value": src_ip, "context": "src_ip"})
    dst_ip = alert.get("dst_ip")
    if dst_ip and not _is_private_ip(dst_ip):
        iocs.append({"type": "ip", "value": dst_ip, "context": "dst_ip"})
    file_hash = alert.get("file_hash")
    if file_hash:
        hash_type = "sha256" if len(file_hash) == 64 else "sha1" if len(file_hash) == 40 else "md5"
        iocs.append({"type": hash_type, "value": file_hash.lower(), "context": "file_hash"})
    for field in ["description", "full_log", "data"]:
        raw_text = alert.get(field)
        if raw_text and isinstance(raw_text, str):
            for tioc in extract_iocs_from_text(raw_text):
                tioc["context"] = field
                iocs.append(tioc)
    seen = set()
    deduped = []
    for ioc in iocs:
        key = (ioc["type"], ioc["value"])
        if key not in seen:
            seen.add(key)
            deduped.append(ioc)
    return deduped
