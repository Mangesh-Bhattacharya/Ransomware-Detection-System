"""Unit tests for behavioral_analyzer.py — sliding-window rate detection,
extension-diversity detection, entropy-triggered alerts, and LLM packaging."""

import os

import pytest

from behavioral_analyzer import (
    EVT_CREATE,
    EVT_DELETE,
    EVT_MODIFY,
    EVT_RENAME,
    BehavioralAnalyzer,
    ExtensionTracker,
    SlidingWindowCounter,
)
from threat_intelligence import reset_engine


@pytest.fixture(autouse=True)
def _general_industry():
    # Behavioral thresholds are industry-independent, but critical-path /
    # extension logic is not — pin to "general" so tests are deterministic.
    reset_engine(industry="general")


def test_sliding_window_counter_counts_recorded_events():
    counter = SlidingWindowCounter(window_seconds=60)
    for _ in range(5):
        counter.record()
    assert counter.count() == 5


def test_extension_tracker_flags_only_first_occurrence():
    tracker = ExtensionTracker(window_seconds=60)
    assert tracker.record(".enc") is True
    assert tracker.record(".enc") is False
    assert tracker.new_extension_count() == 1


def test_no_alert_below_all_thresholds():
    analyzer = BehavioralAnalyzer()
    alert = analyzer.record_event(EVT_MODIFY, "/tmp/normal_file.txt")
    assert alert is None


def test_modify_rate_threshold_triggers_alert():
    analyzer = BehavioralAnalyzer()
    alert = None
    for i in range(51):  # threshold is 50/min
        alert = analyzer.record_event(EVT_MODIFY, f"/tmp/bulk_modify_{i}.txt")
    assert alert is not None
    assert any("HIGH modify rate" in r for r in alert["reasons"])
    assert alert["severity"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_rename_rate_threshold_triggers_alert():
    analyzer = BehavioralAnalyzer()
    alert = None
    for i in range(21):  # threshold is 20/min
        alert = analyzer.record_event(EVT_RENAME, f"/tmp/renamed_{i}.txt")
    assert alert is not None
    assert any("HIGH rename rate" in r for r in alert["reasons"])


def test_delete_rate_threshold_triggers_alert():
    analyzer = BehavioralAnalyzer()
    alert = None
    for i in range(16):  # threshold is 15/min
        alert = analyzer.record_event(EVT_DELETE, f"/tmp/deleted_{i}.txt")
    assert alert is not None
    assert any("HIGH deletion rate" in r for r in alert["reasons"])


def test_extension_diversity_threshold_triggers_alert():
    analyzer = BehavioralAnalyzer()
    alert = None
    for i in range(11):  # threshold is 10 unique new extensions/min
        alert = analyzer.record_event(EVT_CREATE, f"/tmp/file_{i}.ext{i}")
    assert alert is not None
    assert any("new-extension diversity" in r for r in alert["reasons"])


def test_high_entropy_file_triggers_alert(tmp_path):
    analyzer = BehavioralAnalyzer()
    path = tmp_path / "encrypted.bin"
    path.write_bytes(os.urandom(4096))
    alert = analyzer.record_event(EVT_MODIFY, str(path))
    assert alert is not None
    assert any("HIGH file entropy" in r for r in alert["reasons"])


def test_suspicious_extension_triggers_alert():
    analyzer = BehavioralAnalyzer()
    alert = analyzer.record_event(EVT_MODIFY, "/tmp/important_document.locked")
    assert alert is not None
    assert any("SUSPICIOUS EXTENSION" in r for r in alert["reasons"])


def test_alert_callback_is_invoked_on_threshold_breach():
    seen = []
    analyzer = BehavioralAnalyzer(alert_callback=seen.append)
    for i in range(16):
        analyzer.record_event(EVT_DELETE, f"/tmp/cb_{i}.txt")
    assert len(seen) == 1
    assert seen[0]["event_type"] == EVT_DELETE


def test_alert_callback_exception_does_not_propagate():
    def bad_callback(_alert):
        raise RuntimeError("downstream integration is down")

    analyzer = BehavioralAnalyzer(alert_callback=bad_callback)
    # Should not raise even though the callback blows up.
    for i in range(16):
        analyzer.record_event(EVT_DELETE, f"/tmp/cberr_{i}.txt")


def test_get_status_snapshot_shape():
    analyzer = BehavioralAnalyzer()
    analyzer.record_event(EVT_MODIFY, "/tmp/one.txt")
    snapshot = analyzer.get_status_snapshot()
    for key in ("modify_rate_1min", "rename_rate_1min", "delete_rate_1min",
                "create_rate_1min", "new_extension_diversity", "recent_alerts"):
        assert key in snapshot


def test_get_alert_history_returns_a_copy_not_a_live_reference():
    analyzer = BehavioralAnalyzer()
    for i in range(16):
        analyzer.record_event(EVT_DELETE, f"/tmp/hist_{i}.txt")
    history = analyzer.get_alert_history()
    history.append({"fake": "entry"})
    assert len(analyzer.get_alert_history()) == 1  # unaffected by the mutation above


def test_build_llm_context_packet_shape():
    analyzer = BehavioralAnalyzer()
    for i in range(16):
        analyzer.record_event(EVT_DELETE, f"/tmp/llm_{i}.txt")
    packet = analyzer.build_llm_context_packet()
    assert packet["context_type"] == "ransomware_behavioral_analysis"
    assert "industry_profile" in packet
    assert "current_activity_snapshot" in packet
    assert len(packet["recent_alerts"]) >= 1
    assert "instructions_for_llm" in packet


def test_reset_counters_clears_state():
    analyzer = BehavioralAnalyzer()
    for i in range(16):
        analyzer.record_event(EVT_DELETE, f"/tmp/reset_{i}.txt")
    assert analyzer.get_status_snapshot()["recent_alerts"] >= 1

    analyzer.reset_counters()

    snapshot = analyzer.get_status_snapshot()
    assert snapshot["delete_rate_1min"] == 0
    assert snapshot["recent_alerts"] == 0
    assert analyzer.get_alert_history() == []
