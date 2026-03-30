"""
Volatility3 Memory Analysis Dispatcher.
Author  : Chandra Sekhar Chakraborty
Project : Automated IR & Threat Intelligence Platform
"""
from __future__ import annotations
import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

VOLATILITY_BIN = os.environ.get("VOLATILITY_BIN", "vol")

PLUGINS = {
    "pslist":   "windows.pslist.PsList",
    "cmdline":  "windows.cmdline.CmdLine",
    "netscan":  "windows.netstat.NetStat",
    "malfind":  "windows.malfind.Malfind",
    "dlllist":  "windows.dlllist.DllList",
    "filescan": "windows.filescan.FileScan",
}


@dataclass
class PluginResult:
    plugin: str
    success: bool
    rows: list = field(default_factory=list)
    raw_output: str = ""
    error: str = ""


@dataclass
class AnalysisReport:
    dump_path: str
    results: dict = field(default_factory=dict)
    suspicious_pids: list = field(default_factory=list)
    iocs: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "dump_path": self.dump_path,
            "suspicious_pids": self.suspicious_pids,
            "iocs": self.iocs,
            "plugin_results": {k: {"success": v.success, "rows": len(v.rows)} for k, v in self.results.items()},
        }


class VolatilityDispatcher:
    def __init__(self, dump_path: str):
        self.dump_path = dump_path
        if not Path(dump_path).exists():
            raise FileNotFoundError(f"Memory dump not found: {dump_path}")

    def run_plugin(self, plugin_key: str, extra_args: list | None = None) -> PluginResult:
        plugin_class = PLUGINS.get(plugin_key)
        if not plugin_class:
            return PluginResult(plugin=plugin_key, success=False, error=f"Unknown plugin: {plugin_key}")
        dump_path = str(Path(self.dump_path).resolve())
        cmd = [VOLATILITY_BIN, "-f", dump_path, "--renderer", "json", plugin_class] + (extra_args or [])
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # nosec B603
            if result.returncode != 0:
                return PluginResult(plugin=plugin_key, success=False, error=result.stderr)
            return PluginResult(plugin=plugin_key, success=True,
                                rows=self._parse_json(result.stdout), raw_output=result.stdout)
        except subprocess.TimeoutExpired:
            return PluginResult(plugin=plugin_key, success=False, error="Timeout after 300s")
        except FileNotFoundError:
            return PluginResult(plugin=plugin_key, success=False,
                                error=f"Volatility binary not found: {VOLATILITY_BIN}")

    @staticmethod
    def _parse_json(raw: str) -> list:
        try:
            data = json.loads(raw)
            return data if isinstance(data, list) else data.get("rows", [])
        except json.JSONDecodeError:
            return [{"raw": line} for line in raw.splitlines() if line.strip()]

    def run_triage(self) -> AnalysisReport:
        report = AnalysisReport(dump_path=self.dump_path)
        for plugin in ["pslist", "cmdline", "netscan", "malfind"]:
            result = self.run_plugin(plugin)
            report.results[plugin] = result
        return report
