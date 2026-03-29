from pathlib import Path

_pkg_dir = Path(__file__).resolve().parent
_real_pkg = _pkg_dir.parent / "wazuh-integration"
__path__ = [str(_real_pkg)]
