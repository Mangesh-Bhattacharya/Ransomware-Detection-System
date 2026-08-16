"""Unit tests for ransomware_monitor.block_ransomware().

Uses a fully mocked psutil so the suite never enumerates or terminates a
real process on the machine running the tests.
"""

import ransomware_monitor as rm_module
from ransomware_monitor import block_ransomware


class _FakeProc:
    def __init__(self, info):
        self.info = info


class _FakeTerminationHandle:
    def __init__(self, pid, on_terminate):
        self.pid = pid
        self._on_terminate = on_terminate

    def terminate(self):
        self._on_terminate(self.pid)


def test_block_ransomware_terminates_only_matching_process_names(monkeypatch):
    terminated_pids = []

    fake_procs = [
        _FakeProc({"pid": 111, "name": "lockbit_encryptor.exe"}),
        _FakeProc({"pid": 222, "name": "notepad.exe"}),
        _FakeProc({"pid": 333, "name": "conti_payload"}),
    ]

    monkeypatch.setattr(rm_module.psutil, "process_iter", lambda attrs=None: iter(fake_procs))
    monkeypatch.setattr(
        rm_module.psutil, "Process",
        lambda pid: _FakeTerminationHandle(pid, terminated_pids.append),
    )

    killed = block_ransomware(process_patterns=["lockbit", "conti"])

    assert terminated_pids == [111, 333]
    assert len(killed) == 2
    assert all("lockbit" in k.lower() or "conti" in k.lower() for k in killed)


def test_block_ransomware_defaults_to_engine_patterns_when_none_given(monkeypatch):
    from threat_intelligence import reset_engine

    reset_engine(industry="general")
    monkeypatch.setattr(rm_module.psutil, "process_iter", lambda attrs=None: iter([]))

    # Should not raise even with an empty process list, and should pull
    # patterns from the ThreatIntelligenceEngine singleton rather than crash.
    killed = block_ransomware(process_patterns=None)
    assert killed == []


def test_block_ransomware_survives_no_such_process(monkeypatch):
    fake_procs = [_FakeProc({"pid": 999, "name": "ransom_note_writer.exe"})]

    def _raise_no_such_process(pid):
        raise rm_module.psutil.NoSuchProcess(pid)

    monkeypatch.setattr(rm_module.psutil, "process_iter", lambda attrs=None: iter(fake_procs))
    monkeypatch.setattr(rm_module.psutil, "Process", _raise_no_such_process)

    # Should not raise — the exception is caught and the process just isn't
    # reported as killed.
    killed = block_ransomware(process_patterns=["ransom"])
    assert killed == []
