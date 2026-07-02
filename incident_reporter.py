# incident_reporter.py
# Structured incident reporting for the Ransomware Detection System.
# Generates compliance-tagged JSON incident reports, persists them to disk,
# and provides a plain-text summary for console / GUI display.
#
# Report format is designed to satisfy:
#   - HIPAA Breach Notification Rule (45 CFR §164.410)
#   - NIST SP 800-61r2 incident handling phases
#   - PCI-DSS Requirement 12.10.1 incident response procedures
#   - NERC CIP-008 (cyber security incident reporting)
#   - NRC Inspection Procedure 71130.10 (cyber security event reporting)
#   - FISMA NIST SP 800-137 continuous monitoring reporting

import os
import json
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from threat_intelligence import get_engine

logger = logging.getLogger(__name__)

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "logs", "incidents")
os.makedirs(REPORTS_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# REPORT SEVERITY LEVELS
# ---------------------------------------------------------------------------
SEVERITY_LEVELS = {
    "LOW":      {"color": "#00cc00", "nist_category": "Informational", "priority": 1},
    "MEDIUM":   {"color": "#ffcc00", "nist_category": "Low",           "priority": 2},
    "HIGH":     {"color": "#ff6600", "nist_category": "Medium",        "priority": 3},
    "CRITICAL": {"color": "#ff0000", "nist_category": "High",          "priority": 4},
}

# ---------------------------------------------------------------------------
# NIST SP 800-61r2 INCIDENT HANDLING PHASES
# ---------------------------------------------------------------------------
NIST_PHASES = ["Preparation", "Detection & Analysis", "Containment",
               "Eradication", "Recovery", "Post-Incident Activity"]

# ---------------------------------------------------------------------------
# COMPLIANCE NOTIFICATION REQUIREMENTS
# Maps framework -> regulatory notification deadline / requirement text
# ---------------------------------------------------------------------------
COMPLIANCE_NOTIFICATIONS: Dict[str, str] = {
    "HIPAA":        "Notify covered entity / business associate within 60 days of discovery. "
                    "If >500 individuals affected, notify HHS and prominent media.",
    "HITECH":       "Same as HIPAA; breach must be reported to HHS Office for Civil Rights.",
    "PCI-DSS":      "Notify payment card brands and acquiring bank immediately upon confirmed breach. "
                    "Req 12.10.1 mandates a documented incident response plan.",
    "SOX":          "Material cybersecurity incidents may require 8-K disclosure within 4 business days "
                    "(SEC final rule effective 2023).",
    "GLBA":         "Notify FTC within 30 days of discovering a security event affecting 500+ customers.",
    "SWIFT-CSCF":   "Mandatory reporting to SWIFT ISAC; local regulatory reporting as required.",
    "NRC-10CFR73.54":"Notify NRC Operations Center within 1 hour of discovery of a cyber attack "
                    "that affects safety, security, or emergency preparedness functions.",
    "NERC-CIP":     "CIP-008-6: Notify E-ISAC within 1 hour for Critical Incident; "
                    "CIP-008-6 R4 mandates after-action review within 60 days.",
    "ICS-CERT":     "Report to CISA ICS-CERT (888-282-0870) and US-CERT as soon as possible.",
    "NIST-SP800-82":"Follow agency COOP / continuity plan; report to sector ISAC and CISA.",
    "IEC-62443":    "Follow site-specific incident response plan; notify asset owner and vendor.",
    "FISMA":        "Notify US-CERT within 1 hour for major incidents; submit annual FISMA report.",
    "CMMC":         "Report cybersecurity incidents to DoD within 72 hours via dibnet.pentagon.mil.",
    "FedRAMP":      "Notify FedRAMP PMO and agency AO within 1 hour of detecting an incident.",
    "NIST-800-53":  "Execute IR-6 control: report incident to organizational officials and authorities.",
    "CJIS":         "Report to FBI CJIS Division and state CSO within 24 hours.",
    "NIST-CSF":     "Execute RS.CO-2: incident response coordination with stakeholders.",
    "ISO-27001":    "A.16.1.2: Report information security events through management channels promptly.",
    "SOC2":         "CC7.3: Evaluate and communicate about detected security events.",
}


class IncidentReport:
    """
    Represents a single ransomware incident report.
    Encapsulates all evidence, timeline, compliance obligations, and
    recommended containment actions.
    """

    def __init__(self, alert: dict):
        self.incident_id = str(uuid.uuid4()).upper()
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.alert = alert
        self._engine = get_engine()
        self.industry = self._engine.industry
        self.profile = self._engine.profile
        self.severity = alert.get("severity", "MEDIUM")
        self.nist_phase = "Detection & Analysis"

        # Build full report structure
        self.report = self._build_report()

    def _build_report(self) -> dict:
        """Construct the full structured incident report."""
        severity_meta = SEVERITY_LEVELS.get(self.severity, SEVERITY_LEVELS["MEDIUM"])
        frameworks = self.profile.get("compliance_frameworks", [])

        # Collect applicable compliance notifications
        notifications = {}
        for fw in frameworks:
            if fw in COMPLIANCE_NOTIFICATIONS:
                notifications[fw] = COMPLIANCE_NOTIFICATIONS[fw]

        # Recommended containment actions
        containment_actions = self._recommend_containment()

        return {
            "incident_id": self.incident_id,
            "report_version": "2.0",
            "created_at": self.created_at,
            "organization_industry": self.industry,
            "industry_label": self.profile["label"],
            "compliance_frameworks": frameworks,
            "nist_incident_phase": self.nist_phase,
            "nist_phases_reference": NIST_PHASES,

            "threat_summary": {
                "severity": self.severity,
                "nist_category": severity_meta["nist_category"],
                "priority": severity_meta["priority"],
                "event_type": self.alert.get("event_type", "unknown"),
                "affected_file": self.alert.get("filepath", "unknown"),
                "file_sha256": self.alert.get("sha256"),
                "file_entropy": self.alert.get("entropy", 0.0),
                "detection_reasons": self.alert.get("reasons", []),
                "detection_timestamp": self.alert.get("timestamp"),
                "activity_counters": self.alert.get("counters", {}),
            },

            "compliance_obligations": {
                "applicable_frameworks": frameworks,
                "compliance_controls_triggered": self.alert.get("compliance_controls", {}),
                "regulatory_notification_requirements": notifications,
            },

            "containment_and_response": {
                "recommended_actions": containment_actions,
                "estimated_blast_radius": self._estimate_blast_radius(),
            },

            "evidence": {
                "raw_alert": self.alert,
            },

            "llm_analysis_placeholder": {
                "status": "pending",
                "instructions": (
                    "Submit the 'threat_summary' and 'activity_counters' fields to your "
                    "preferred LLM endpoint for automated root-cause analysis and "
                    "natural-language incident narrative generation."
                ),
                "result": None,
            },
        }

    def _recommend_containment(self) -> List[str]:
        """Generate ordered containment recommendations based on severity and industry."""
        actions = [
            "1. ISOLATE affected host(s) from the network immediately.",
            "2. KILL all processes matching ransomware patterns (see ransomware_monitor.py).",
            "3. PRESERVE volatile memory (RAM dump) before rebooting any affected system.",
            "4. SNAPSHOT affected storage volumes for forensic analysis.",
            "5. REVOKE active sessions / credentials for accounts active on affected hosts.",
            "6. NOTIFY the CSIRT / SOC lead and trigger the incident response plan.",
        ]
        if self.industry in ("nuclear", "energy"):
            actions.insert(0, "0. VERIFY safety-critical OT/ICS systems are UNAFFECTED and "
                              "switch to manual control if necessary.")
            actions.append("7. Notify plant security manager and activate physical security protocols.")
            actions.append("8. Report to sector ISAC and regulatory authority per site procedure.")
        elif self.industry == "healthcare":
            actions.append("7. Initiate downtime procedures for EHR / clinical systems.")
            actions.append("8. Notify Privacy Officer — potential PHI breach assessment required.")
        elif self.industry == "banking":
            actions.append("7. Engage fraud / payment operations team to halt suspicious transactions.")
            actions.append("8. Notify SWIFT ISAC and payment card brands if cardholder data may be affected.")
        elif self.industry == "government":
            actions.append("7. Notify agency ISSO and ISSM; begin FISMA major incident response.")
            actions.append("8. Report to US-CERT / CISA within 1 hour if major incident confirmed.")
        return actions

    def _estimate_blast_radius(self) -> str:
        """Provide a qualitative blast-radius estimate based on counters."""
        counters = self.alert.get("counters", {})
        modify = counters.get("modify_rate", 0)
        rename = counters.get("rename_rate", 0)
        total = modify + rename
        if total > 200:
            return "EXTENSIVE — hundreds of files affected per minute; mass encryption likely in progress."
        elif total > 50:
            return "SIGNIFICANT — dozens of files affected per minute; containment urgent."
        elif total > 10:
            return "MODERATE — early-stage encryption or targeted attack."
        else:
            return "LIMITED — single or few files affected; may be isolated event."

    def to_json(self) -> str:
        """Serialize report to a formatted JSON string."""
        return json.dumps(self.report, indent=2, default=str)

    def to_summary(self) -> str:
        """Return a plain-text summary for console / GUI display."""
        r = self.report
        ts = r["threat_summary"]
        lines = [
            "=" * 70,
            f"  RANSOMWARE INCIDENT REPORT  [{r['incident_id']}]",
            "=" * 70,
            f"  Severity      : {ts['severity']} ({ts['nist_category']})",
            f"  Industry      : {r['industry_label']}",
            f"  Detected At   : {ts['detection_timestamp']}",
            f"  Affected File : {ts['affected_file']}",
            f"  SHA-256       : {ts['file_sha256'] or 'N/A'}",
            f"  Entropy       : {ts['file_entropy']:.3f} bits",
            f"  Blast Radius  : {r['containment_and_response']['estimated_blast_radius']}",
            "-" * 70,
            "  DETECTION REASONS:",
        ]
        for reason in ts["detection_reasons"]:
            lines.append(f"    * {reason}")
        lines.append("-" * 70)
        lines.append("  COMPLIANCE OBLIGATIONS:")
        for fw, note in r["compliance_obligations"]["regulatory_notification_requirements"].items():
            lines.append(f"    [{fw}] {note[:100]}...")
        lines.append("-" * 70)
        lines.append("  CONTAINMENT ACTIONS:")
        for action in r["containment_and_response"]["recommended_actions"]:
            lines.append(f"    {action}")
        lines.append("=" * 70)
        return "\n".join(lines)

    def save(self) -> str:
        """Persist the report to disk. Returns the file path."""
        filename = f"incident_{self.incident_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(REPORTS_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        logger.info("[IncidentReport] Saved: %s", filepath)
        return filepath


class IncidentReporter:
    """
    Manages the lifecycle of incident reports for the detection session.
    Integrates with BehavioralAnalyzer via alert_callback.
    """

    def __init__(self, gui_callback: Optional[Any] = None):
        """
        :param gui_callback: Optional callable(summary_text: str, severity: str)
                             used to push summaries to the GUI log widget.
        """
        self._gui_callback = gui_callback
        self._reports: List[IncidentReport] = []
        self._lock = __import__("threading").Lock()

    def handle_alert(self, alert: dict) -> IncidentReport:
        """
        Create, persist, and display an incident report for the given alert.
        This method is intended to be passed as the alert_callback to BehavioralAnalyzer.
        """
        report = IncidentReport(alert)
        filepath = report.save()
        summary = report.to_summary()

        with self._lock:
            self._reports.append(report)

        logger.warning("[IncidentReporter] New incident: %s | %s | %s",
                       report.incident_id, report.severity, filepath)

        if self._gui_callback:
            try:
                self._gui_callback(summary, report.severity)
            except Exception as exc:
                logger.error("[IncidentReporter] GUI callback error: %s", exc)

        return report

    def get_all_reports(self) -> List[dict]:
        """Return all report dicts from the current session."""
        with self._lock:
            return [r.report for r in self._reports]

    def get_report_count(self) -> int:
        with self._lock:
            return len(self._reports)
