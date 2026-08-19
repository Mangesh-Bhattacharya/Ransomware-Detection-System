"""Unit tests for auto_response.py — safe-by-default containment actions.

All tests exercise dry_run=True paths except the quarantine "live" test,
which only ever moves a throwaway file created inside pytest's tmp_path —
never a real process or a real network adapter.
"""

import json
import os

import pytest

import auto_response as ar_module
from auto_response import AutoResponseEngine


@pytest.fixture(autouse=True)
def _redirect_response_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(ar_module, "QUARANTINE_DIR", tmp_path)
    monkeypatch.setattr(ar_module, "RESPONSE_LOG", tmp_path / "auto_response.log")


def test_terminate_process_dry_run_does_not_kill_current_process():
    engine = AutoResponseEngine()
    result = engine.terminate_process(pid=os.getpid(), dry_run=True)
    assert result.dry_run is True
    assert result.success is True
    assert "DRY RUN" in result.detail
    # We're still alive to assert this, which is the actual proof.
    assert os.getpid() > 0


def test_terminate_process_nonexistent_pid_reports_failure():
    engine = AutoResponseEngine()
    # A PID that's astronomically unlikely to exist.
    result = engine.terminate_process(pid=2**30 - 1, dry_run=True)
    assert result.success is False
    assert "not found" in result.detail.lower()


def test_quarantine_file_dry_run_leaves_file_in_place(tmp_path):
    src = tmp_path / "suspicious.enc"
    src.write_text("fake ransomware artifact for testing")
    engine = AutoResponseEngine(watch_root=tmp_path)

    result = engine.quarantine_file(str(src), dry_run=True)

    assert result.dry_run is True
    assert result.success is True
    assert src.exists()  # not actually moved


def test_quarantine_file_live_moves_file_into_quarantine_dir(tmp_path):
    src = tmp_path / "watched" / "suspicious.enc"
    src.parent.mkdir()
    src.write_text("fake ransomware artifact for testing")
    engine = AutoResponseEngine(watch_root=src.parent)

    result = engine.quarantine_file(str(src), dry_run=False)

    assert result.success is True
    assert result.dry_run is False
    assert not src.exists()
    quarantined = list(tmp_path.glob("*suspicious.enc"))
    assert len(quarantined) == 1


def test_quarantine_file_refuses_path_outside_watch_root(tmp_path):
    watch_root = tmp_path / "watched"
    watch_root.mkdir()
    outside_file = tmp_path / "outside" / "not_watched.txt"
    outside_file.parent.mkdir()
    outside_file.write_text("should not be touched")
    engine = AutoResponseEngine(watch_root=watch_root)

    result = engine.quarantine_file(str(outside_file), dry_run=False)

    assert result.success is False
    assert "Refused" in result.detail
    assert outside_file.exists()  # untouched


def test_quarantine_file_missing_file_reports_failure(tmp_path):
    engine = AutoResponseEngine(watch_root=tmp_path)
    result = engine.quarantine_file(str(tmp_path / "does_not_exist.enc"), dry_run=True)
    assert result.success is False
    assert "not found" in result.detail.lower()


def test_isolate_network_dry_run_does_not_touch_adapters(monkeypatch):
    monkeypatch.setattr(
        ar_module.psutil, "net_if_addrs",
        lambda: {"eth0": None, "lo": None},
    )
    engine = AutoResponseEngine()
    result = engine.isolate_network(dry_run=True)
    assert result.dry_run is True
    assert result.success is True
    assert "eth0" in result.target
    assert "DRY RUN" in result.detail


def test_response_result_to_dict_roundtrips_via_json():
    engine = AutoResponseEngine()
    result = engine.terminate_process(pid=os.getpid(), dry_run=True)
    payload = json.loads(json.dumps(result.to_dict(), default=str))
    assert payload["action"] == "terminate_process"
    assert payload["dry_run"] is True


def test_every_action_appends_a_log_line(tmp_path):
    engine = AutoResponseEngine()
    engine.terminate_process(pid=os.getpid(), dry_run=True)
    log_path = ar_module.RESPONSE_LOG
    assert log_path.exists()
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 1
    json.loads(lines[-1])  # each line is a valid JSON record
