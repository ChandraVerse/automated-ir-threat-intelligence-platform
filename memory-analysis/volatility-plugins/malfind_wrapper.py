"""
Volatility 3 malfind plugin wrapper.
Parses malfind output to detect injected code / suspicious memory regions.
"""

import json
import subprocess
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


def run_malfind(vol_path: str, dump_path: str) -> List[Dict]:
    """
    Run Volatility 3 windows.malfind against a memory dump.

    Returns a list of suspicious memory regions with process context.
    Each entry includes: PID, process name, virtual address, protection flags,
    and a hex dump excerpt.
    """
    plugin = "windows.malfind.Malfind"
    cmd = [vol_path, "-f", dump_path, plugin, "--output", "json"]

    logger.info("Running malfind: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        logger.error("malfind timed out after 300s")
        return []
    except FileNotFoundError:
        logger.error("Volatility binary not found at: %s", vol_path)
        return []

    if proc.returncode != 0:
        logger.error("malfind stderr: %s", proc.stderr[:500])
        return []

    findings = _parse_json_output(proc.stdout)
    logger.info("malfind: %d suspicious regions found", len(findings))
    return findings


def _parse_json_output(raw_output: str) -> List[Dict]:
    try:
        data = json.loads(raw_output)
        rows = data.get("rows", [])
        columns = data.get("columns", [])
        results = [{columns[i]: row[i] for i in range(len(columns))} for row in rows]
        # Annotate with risk hint
        for r in results:
            protection = str(r.get("Protection", ""))
            r["risk_hint"] = "HIGH" if "EXECUTE_READWRITE" in protection else "MEDIUM"
        return results
    except (json.JSONDecodeError, KeyError, IndexError) as exc:
        logger.warning("malfind JSON parse failed: %s", exc)
        return []
