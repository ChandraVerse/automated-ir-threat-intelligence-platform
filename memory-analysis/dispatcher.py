"""
Volatility3 Memory Analysis Dispatcher
Runs Volatility plugins against memory dumps and parses output.
"""
from __future__ import annotations
import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

VOLATILITY_BIN = os.environ.get("VOLATILITY_BIN", "vol")

PLUGINS = {
    "pslist":       "windows.pslist.PsList",
    "pstree":       "windows.pstree.PsTree",
    "cmdline":      "windows.cmdline.CmdLine",
    "netscan":      "windows.netstat.NetStat",
    "malfind":      "windows.malfind.Malfind",
    "dlllist":      "windows.dlllist.DllList",
    "handles":      "windows.handles.Handles",
    "filescan":     "windows.filescan.FileScan",
    "hashdump":     "windows.hashdump.Hashdump",
    "lsadump":      "windows.lsadump.Lsadump",
}


@dataclass
class PluginResult:
    plugin: str
    success: bool
    rows: list[dict[str, Any]] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""


@dataclass
class AnalysisReport:
    dump_path: str
    results: dict[str, PluginResult] = field(default_factory=dict)
    suspicious_pids: list[int] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "dump_path": self.dump_path,
            "suspicious_pids": self.suspicious_pids,
            "iocs": self.iocs,
            "plugin_results": {
                k: {"success": v.success, "rows": len(v.rows), "error": v.error}
                for k, v in self.results.items()
            },
        }


class VolatilityDispatcher:
    """
    Runs Volatility3 plugins and parses results for IOC extraction.
    Requires: vol3 installed and accessible via VOLATILITY_BIN env var.
    """

    def __init__(self, dump_path: str):
        self.dump_path = dump_path
        if not Path(dump_path).exists():
            raise FileNotFoundError(f"Memory dump not found: {dump_path}")

    def run_plugin(self, plugin_key: str, extra_args: list[str] | None = None) -> PluginResult:
        plugin_class = PLUGINS.get(plugin_key)
        if not plugin_class:
            return PluginResult(plugin=plugin_key, success=False, error=f"Unknown plugin: {plugin_key}")

        # Resolve and validate dump_path to prevent shell injection (bandit B603)
        dump_path = str(Path(self.dump_path).resolve())

        cmd = [
            VOLATILITY_BIN, "-f", dump_path,
            "--renderer", "json",
            plugin_class,
        ] + (extra_args or [])

        logger.info("Running: %s", " ".join(cmd))
        try:
            result = subprocess.run(  # nosec B603
                cmd, capture_output=True, text=True, timeout=300
            )
            if result.returncode != 0:
                return PluginResult(plugin=plugin_key, success=False,
                                    error=result.stderr, raw_output=result.stdout)
            rows = self._parse_json_output(result.stdout)
            return PluginResult(plugin=plugin_key, success=True,
                                rows=rows, raw_output=result.stdout)
        except subprocess.TimeoutExpired:
            return PluginResult(plugin=plugin_key, success=False, error="Timeout after 300s")
        except FileNotFoundError:
            return PluginResult(plugin=plugin_key, success=False,
                                error=f"Volatility binary not found: {VOLATILITY_BIN}")

    @staticmethod
    def _parse_json_output(raw: str) -> list[dict]:
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return data
            return data.get("rows", [])
        except json.JSONDecodeError:
            return [{"raw": line} for line in raw.splitlines() if line.strip()]

    def run_triage(self) -> AnalysisReport:
        """Run a standard triage set: pslist, cmdline, netscan, malfind."""
        report = AnalysisReport(dump_path=self.dump_path)
        triage_plugins = ["pslist", "cmdline", "netscan", "malfind"]

        for plugin in triage_plugins:
            result = self.run_plugin(plugin)
            report.results[plugin] = result
            if result.success:
                self._extract_iocs(result, report)

        return report

    def run_full_analysis(self) -> AnalysisReport:
        """Run all registered plugins."""
        report = AnalysisReport(dump_path=self.dump_path)
        for plugin in PLUGINS:
            result = self.run_plugin(plugin)
            report.results[plugin] = result
            if result.success:
                self._extract_iocs(result, report)
        return report

    @staticmethod
    def _extract_iocs(result: PluginResult, report: AnalysisReport) -> None:
        import re
        ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        for row in result.rows:
            row_str = json.dumps(row)
            for ip in ip_re.findall(row_str):
                if not ip.startswith(("10.", "192.168.", "127.", "0.")):
                    if ip not in report.iocs:
                        report.iocs.append(ip)
            if result.plugin == "malfind":
                pid = row.get("PID") or row.get("pid")
                if pid and int(pid) not in report.suspicious_pids:
                    report.suspicious_pids.append(int(pid))
