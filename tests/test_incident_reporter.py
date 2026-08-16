"""Unit tests for incident_reporter.py — compliance-tagged incident reports."""

import json

import pytest

import incident_reporter as ir_module
from incident_reporter import IncidentReport, IncidentReporter
from threat_intelligence import reset_engine


def _sample_alert(**overrides):
    alert = {
        "timestamp": "2026-08-14T12:00:00",
        "event_type": "modify",
        "filepath": "/var/lib/ehr/patient_records.dcm",
        "old_filepath": None,
        "sha256": "abc123",
        "entropy": 7.8,
        "reasons": ["HIGH file entropy: 7.800 bits"],
        "severity": "HIGH",
        "industry": "healthcare",
        "compliance_controls": {"HIPAA": ["IR-6", "SI-3"]},
        "counters": {"modify_rate": 60, "rename_rate": 5, "delete_rate": 0, "new_extensions": 2},
    }
    alert.update(overrides)
    return alert


@pytest.fixture(autouse=True)
def _redirect_reports_dir(tmp_path, monkeypatch):
    # Reports dir is a module-level constant computed at import time; redirect
    # it to a temp directory so tests never write into the real repo tree.
    monkeypatch.setattr(ir_module, "REPORTS_DIR", str(tmp_path))


def test_healthcare_report_includes_hipaa_notification():
    reset_engine(industry="healthcare")
    report = IncidentReport(_sample_alert())
    notifications = report.report["compliance_obligations"]["regulatory_notification_requirements"]
    assert "HIPAA" in notifications


def test_healthcare_containment_includes_privacy_officer_step():
    reset_engine(industry="healthcare")
    report = IncidentReport(_sample_alert())
    actions = " ".join(report.report["containment_and_response"]["recommended_actions"])
    assert "Privacy Officer" in actions


def test_nuclear_containment_prepends_ot_ics_safety_check():
    reset_engine(industry="nuclear")
    report = IncidentReport(_sample_alert(industry="nuclear"))
    actions = report.report["containment_and_response"]["recommended_actions"]
    assert actions[0].startswith("0. VERIFY safety-critical OT/ICS")


@pytest.mark.parametrize("modify_rate,rename_rate,expected_phrase", [
    (250, 0, "EXTENSIVE"),
    (60, 0, "SIGNIFICANT"),
    (15, 0, "MODERATE"),
    (2, 0, "LIMITED"),
])
def test_blast_radius_scales_with_activity(modify_rate, rename_rate, expected_phrase):
    reset_engine(industry="general")
    alert = _sample_alert(counters={"modify_rate": modify_rate, "rename_rate": rename_rate,
                                     "delete_rate": 0, "new_extensions": 0})
    report = IncidentReport(alert)
    assert expected_phrase in report.report["containment_and_response"]["estimated_blast_radius"]


def test_report_is_valid_json():
    reset_engine(industry="general")
    report = IncidentReport(_sample_alert())
    parsed = json.loads(report.to_json())
    assert parsed["incident_id"] == report.incident_id


def test_summary_includes_incident_id_and_severity():
    reset_engine(industry="general")
    report = IncidentReport(_sample_alert())
    summary = report.to_summary()
    assert report.incident_id in summary
    assert "HIGH" in summary


def test_save_writes_report_to_reports_dir(tmp_path):
    reset_engine(industry="general")
    report = IncidentReport(_sample_alert())
    filepath = report.save()
    assert filepath.startswith(str(tmp_path))
    with open(filepath, encoding="utf-8") as f:
        saved = json.load(f)
    assert saved["incident_id"] == report.incident_id


def test_incident_reporter_tracks_reports_and_invokes_gui_callback():
    reset_engine(industry="general")
    seen = []
    reporter = IncidentReporter(gui_callback=lambda summary, severity: seen.append((summary, severity)))
    reporter.handle_alert(_sample_alert())
    assert reporter.get_report_count() == 1
    assert len(seen) == 1
    assert seen[0][1] == "HIGH"


def test_incident_reporter_survives_broken_gui_callback():
    reset_engine(industry="general")
    reporter = IncidentReporter(gui_callback=lambda *_: (_ for _ in ()).throw(RuntimeError("gui gone")))
    # Should not raise even though the GUI callback is broken.
    report = reporter.handle_alert(_sample_alert())
    assert reporter.get_report_count() == 1
    assert report.incident_id in [r["incident_id"] for r in reporter.get_all_reports()]
