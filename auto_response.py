"""
auto_response.py

Automated containment/response engine for the Ransomware Detection System.

Provides three response primitives, each SAFE-BY-DEFAULT (dry_run=True):
  * terminate_process(pid)        - kill a process identified as malicious
  * quarantine_file(path)         - move a suspicious file into an isolated
                                     quarantine directory (never deletes)
  * isolate_network(scope)        - disable the host's active network
                                     adapters to stop lateral movement / C2

All actions are logged to logs/auto_response.log and return a structured
ResponseResult so the dashboard and incident reports can display exactly
what was (or would have been) done.

SAFETY NOTES
------------
* dry_run defaults to True everywhere. The calling application must
  explicitly opt in to live enforcement (dry_run=False) - this file will
  never take a destructive action unless the operator has deliberately
  configured it to do so.
* quarantine_file() moves files rather than deleting them, and refuses to
  operate outside of a configured watch root.
* isolate_network() only toggles OS-level network adapters via psutil/OS
  utilities already present on the system - it does not modify firewall
  rules, routing tables, or any persistent system configuration.
* This module intentionally does NOT expose any generic "run shell
  command" primitive - only the three narrowly-scoped actions above.
"""

from __future__ import annotations

import json
import logging
import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import psutil

logger = logging.getLogger("ransomware_detector.auto_response")

QUARANTINE_DIR = Path("logs") / "quarantine"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

RESPONSE_LOG = Path("logs") / "auto_response.log"
RESPONSE_LOG.parent.mkdir(parents=True, exist_ok=True)


@dataclass
class ResponseResult:
    action: str
    target: str
    success: bool
    dry_run: bool
    detail: str
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return asdict(self)


class AutoResponseEngine:
    """Coordinates automated containment actions. Every public method is
    dry_run=True by default - the operator (application.py, dashboard.py,
    or a human analyst) must explicitly pass dry_run=False to enforce a
    live action."""

    def __init__(self, watch_root: Optional[Path] = None):
        self.watch_root = Path(watch_root).resolve() if watch_root else None

    # ------------------------------------------------------------------ #
    # Process termination
    # ------------------------------------------------------------------ #
    def terminate_process(self, pid: int, dry_run: bool = True) -> ResponseResult:
        try:
            proc = psutil.Process(pid)
            name = proc.name()
        except psutil.NoSuchProcess:
            result = ResponseResult("terminate_process", str(pid), False, dry_run,
                                     "Process not found.")
            self._log(result)
            return result

        if dry_run:
            result = ResponseResult(
                "terminate_process", f"{pid} ({name})", True, True,
                "DRY RUN - would terminate this process. Pass dry_run=False to enforce.",
            )
            self._log(result)
            return result

        try:
            proc.terminate()
            proc.wait(timeout=3)
            result = ResponseResult("terminate_process", f"{pid} ({name})", True, False,
                                     "Process terminated.")
        except psutil.TimeoutExpired:
            proc.kill()
            result = ResponseResult("terminate_process", f"{pid} ({name})", True, False,
                                     "Process force-killed after terminate timeout.")
        except Exception as exc:
            result = ResponseResult("terminate_process", f"{pid} ({name})", False, False,
                                     f"Failed to terminate: {exc}")
        self._log(result)
        return result

    # ------------------------------------------------------------------ #
    # File quarantine
    # ------------------------------------------------------------------ #
    def quarantine_file(self, file_path: str, dry_run: bool = True) -> ResponseResult:
        src = Path(file_path).resolve()

        if self.watch_root and self.watch_root not in src.parents and src != self.watch_root:
            result = ResponseResult("quarantine_file", str(src), False, dry_run,
                                     "Refused: path is outside the configured watch root.")
            self._log(result)
            return result

        if not src.exists():
            result = ResponseResult("quarantine_file", str(src), False, dry_run,
                                     "File not found.")
            self._log(result)
            return result

        dest = QUARANTINE_DIR / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}_{src.name}"

        if dry_run:
            result = ResponseResult(
                "quarantine_file", str(src), True, True,
                f"DRY RUN - would move to {dest}. Pass dry_run=False to enforce.",
            )
            self._log(result)
            return result

        try:
            shutil.move(str(src), str(dest))
            result = ResponseResult("quarantine_file", str(src), True, False,
                                     f"File quarantined to {dest}.")
        except Exception as exc:
            result = ResponseResult("quarantine_file", str(src), False, False,
                                     f"Failed to quarantine: {exc}")
        self._log(result)
        return result

    # ------------------------------------------------------------------ #
    # Network isolation
    # ------------------------------------------------------------------ #
    def isolate_network(self, dry_run: bool = True) -> ResponseResult:
        adapters = list(psutil.net_if_addrs().keys())

        if dry_run:
            result = ResponseResult(
                "isolate_network", ", ".join(adapters), True, True,
                "DRY RUN - would disable all active network adapters to "
                "contain lateral movement / C2 traffic. Pass dry_run=False "
                "to enforce.",
            )
            self._log(result)
            return result

        system = platform.system()
        try:
            if system == "Windows":
                for adapter in adapters:
                    subprocess.run(
                        ["netsh", "interface", "set", "interface", adapter, "admin=disable"],
                        check=False, capture_output=True, timeout=10,
                    )
            elif system == "Linux":
                for adapter in adapters:
                    if adapter == "lo":
                        continue
                    subprocess.run(["ip", "link", "set", adapter, "down"],
                                    check=False, capture_output=True, timeout=10)
            else:
                result = ResponseResult("isolate_network", ", ".join(adapters), False, False,
                                         f"Unsupported platform for live isolation: {system}")
                self._log(result)
                return result

            result = ResponseResult("isolate_network", ", ".join(adapters), True, False,
                                     "Network adapters disabled to contain the host.")
        except Exception as exc:
            result = ResponseResult("isolate_network", ", ".join(adapters), False, False,
                                     f"Failed to isolate network: {exc}")
        self._log(result)
        return result

    # ------------------------------------------------------------------ #
    # Logging
    # ------------------------------------------------------------------ #
    @staticmethod
    def _log(result: ResponseResult) -> None:
        line = json.dumps(result.to_dict(), default=str)
        with open(RESPONSE_LOG, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        level = logging.INFO if result.success else logging.ERROR
        logger.log(level, "AutoResponse: %s", line)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    engine = AutoResponseEngine()
    print(engine.terminate_process(pid=1, dry_run=True).to_dict())
    print(engine.isolate_network(dry_run=True).to_dict())
