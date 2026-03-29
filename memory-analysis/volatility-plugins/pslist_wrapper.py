"""
Volatility 3 pslist plugin wrapper.
Parses pslist output and returns structured JSON list of running processes.
"""

import json
import re
import subprocess
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


def run_pslist(vol_path: str, dump_path: str, os_profile: Optional[str] = None) -> List[Dict]:
    """
    Run Volatility 3 windows.pslist (or linux.pslist) against a memory dump.

    Args:
        vol_path: Path to vol.py or vol3 binary
        dump_path: Path to memory dump file
        os_profile: Optional OS profile override (not needed for Vol3)

    Returns:
        List of process dicts with pid, ppid, name, create_time, etc.
    """
    plugin = "windows.pslist.PsList"
    cmd = [vol_path, "-f", dump_path, plugin, "--output", "json"]

    logger.info("Running pslist: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        logger.error("pslist timed out after 120s")
        return []
    except FileNotFoundError:
        logger.error("Volatility binary not found at: %s", vol_path)
        return []

    if proc.returncode != 0:
        logger.error("pslist stderr: %s", proc.stderr[:500])
        return []

    return _parse_json_output(proc.stdout, plugin="pslist")


def _parse_json_output(raw_output: str, plugin: str) -> List[Dict]:
    """Parse Volatility 3 JSON output into a clean list of dicts."""
    try:
        data = json.loads(raw_output)
        rows = data.get("rows", [])
        columns = data.get("columns", [])
        return [{columns[i]: row[i] for i in range(len(columns))} for row in rows]
    except (json.JSONDecodeError, KeyError, IndexError) as exc:
        logger.warning("%s JSON parse failed (%s), falling back to text parse", plugin, exc)
        return _parse_text_output(raw_output)


def _parse_text_output(raw_output: str) -> List[Dict]:
    """Fallback: parse Volatility text table output."""
    processes = []
    lines = raw_output.strip().splitlines()
    for line in lines:
        parts = line.split()
        if len(parts) >= 7 and parts[0].isdigit():
            processes.append({
                "PID": int(parts[0]),
                "PPID": int(parts[1]) if parts[1].isdigit() else None,
                "ImageFileName": parts[2],
                "Offset": parts[3] if len(parts) > 3 else None,
                "Threads": parts[4] if len(parts) > 4 else None,
                "Handles": parts[5] if len(parts) > 5 else None,
                "CreateTime": " ".join(parts[7:]) if len(parts) > 7 else None,
            })
    return processes
