"""
llm_assistant.py

LLM-powered security assistant for the Ransomware Detection System.

Capabilities:
  1. explain_event()            - plain-language explanation of a suspicious
                                   behavioral snapshot / ML risk assessment
  2. generate_incident_report() - narrative incident report generation from
                                   a structured incident JSON (see
                                   incident_reporter.py)
  3. recommend_mitigation()     - ranked, actionable mitigation/containment
                                   steps for a given incident severity and
                                   industry profile

Design goals:
  * Works fully offline via a deterministic template fallback when no LLM
    API key is configured (LLM_API_KEY env var), so the dashboard and
    reports remain functional out of the box with zero external
    dependencies.
  * When an API key IS configured, calls an OpenAI-compatible chat
    completion endpoint (works with OpenAI, Azure OpenAI, or any
    self-hosted OpenAI-compatible gateway via LLM_BASE_URL).
  * Never sends raw file contents or PII off-host - only structured
    behavioral metadata (rates, entropy, hashes, extensions) is included
    in prompts.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Optional

logger = logging.getLogger("ransomware_detector.llm")

DEFAULT_MODEL = os.environ.get("LLM_MODEL", "gpt-4o-mini")
API_KEY = os.environ.get("LLM_API_KEY")
BASE_URL = os.environ.get("LLM_BASE_URL")  # optional, for self-hosted gateways

SYSTEM_PROMPT = (
    "You are a senior incident-response analyst embedded in a ransomware "
    "detection platform. You are given structured behavioral telemetry and "
    "must respond with concise, technically precise, actionable analysis. "
    "Never speculate beyond the provided data. Always structure mitigation "
    "steps in priority order."
)


class LLMSecurityAssistant:
    """Thin wrapper around an OpenAI-compatible chat completion API with a
    deterministic offline fallback so the platform degrades gracefully
    without network access or an API key configured."""

    def __init__(self, api_key: Optional[str] = None, model: str = DEFAULT_MODEL,
                 base_url: Optional[str] = None):
        self.api_key = api_key or API_KEY
        self.model = model
        self.base_url = base_url or BASE_URL
        self._client = None

        if self.api_key:
            try:
                from openai import OpenAI  # optional dependency
                kwargs = {"api_key": self.api_key}
                if self.base_url:
                    kwargs["base_url"] = self.base_url
                self._client = OpenAI(**kwargs)
            except ImportError:
                logger.warning(
                    "openai package not installed - falling back to offline "
                    "template mode. Install with: pip install openai"
                )

    @property
    def online(self) -> bool:
        return self._client is not None

    # ------------------------------------------------------------------ #
    # Core LLM call with offline fallback
    # ------------------------------------------------------------------ #
    def _complete(self, user_prompt: str, fallback: str) -> str:
        if not self._client:
            return fallback
        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.2,
                max_tokens=600,
            )
            return response.choices[0].message.content.strip()
        except Exception as exc:
            logger.error("LLM call failed (%s) - using offline fallback.", exc)
            return fallback

    # ------------------------------------------------------------------ #
    # Public capabilities
    # ------------------------------------------------------------------ #
    def explain_event(self, features: dict, assessment: dict) -> str:
        """Explain a behavioral snapshot + ML risk assessment in plain
        language for a SOC analyst."""
        prompt = (
            "Explain the following behavioral telemetry and ML risk "
            "assessment in 3-5 sentences for a SOC analyst. Identify which "
            "signals are most indicative of ransomware activity.\n\n"
            f"Telemetry: {json.dumps(features)}\n"
            f"ML assessment: {json.dumps(assessment)}"
        )
        fallback = self._offline_explanation(features, assessment)
        return self._complete(prompt, fallback)

    def generate_incident_report(self, incident: dict) -> str:
        """Turn a structured incident JSON (from incident_reporter.py) into
        a narrative report suitable for stakeholders/compliance."""
        prompt = (
            "Write a concise incident narrative (under 200 words) based on "
            "this structured incident report. Include what happened, "
            "which detection layer triggered, likely impact, and regulatory "
            "notification obligations if present.\n\n"
            f"Incident: {json.dumps(incident, default=str)}"
        )
        fallback = self._offline_incident_narrative(incident)
        return self._complete(prompt, fallback)

    def recommend_mitigation(self, severity: str, industry: str = "general",
                              context: Optional[dict] = None) -> str:
        """Return ranked mitigation/containment recommendations for a given
        severity level and industry profile."""
        prompt = (
            f"Recommend a prioritized list of containment and mitigation "
            f"actions for a {severity.upper()} severity ransomware "
            f"detection event in a {industry} environment. "
            f"Context: {json.dumps(context or {}, default=str)}"
        )
        fallback = self._offline_mitigation(severity, industry)
        return self._complete(prompt, fallback)

    # ------------------------------------------------------------------ #
    # Offline deterministic fallbacks (no network / no API key required)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _offline_explanation(features: dict, assessment: dict) -> str:
        risk = assessment.get("risk_score", 0)
        top = assessment.get("contributing_features", {})
        top_desc = ", ".join(f"{k}={v}" for k, v in top.items()) or "no standout features"
        level = "CRITICAL" if risk >= 80 else "HIGH" if risk >= 60 else \
            "MEDIUM" if risk >= 30 else "LOW"
        return (
            f"[Offline mode] Blended ML risk score is {risk:.1f}/100 ({level}). "
            f"The most anomalous signals driving this score are: {top_desc}. "
            f"IsolationForest anomaly flag: {assessment.get('is_anomalous')}; "
            f"RandomForest malicious probability: "
            f"{assessment.get('random_forest_probability', 0):.2f}. "
            f"Elevated file modify/rename/delete rates combined with high "
            f"Shannon entropy are the strongest ransomware indicators - "
            f"investigate the originating process immediately if risk is "
            f"HIGH or CRITICAL."
        )

    @staticmethod
    def _offline_incident_narrative(incident: dict) -> str:
        return (
            f"[Offline mode] Incident {incident.get('incident_id', 'unknown')} "
            f"was recorded at severity {incident.get('severity', 'UNKNOWN')}. "
            f"Detection was triggered by the behavioral/entropy/hash pipeline "
            f"documented in threat_intelligence.py and behavioral_analyzer.py. "
            f"Review the full JSON payload in logs/incidents/ for entropy, "
            f"hash, extension, and counter details, and cross-reference the "
            f"compliance obligations listed in the report for this "
            f"organization's regulatory framework. Configure LLM_API_KEY to "
            f"enable full natural-language narrative generation."
        )

    @staticmethod
    def _offline_mitigation(severity: str, industry: str) -> str:
        base_steps = [
            "Isolate the affected host from the network (disable adapter / "
            "block at switch port) to stop lateral movement and C2 traffic.",
            "Suspend or terminate the offending process identified by "
            "ransomware_monitor.py's process heuristics layer.",
            "Quarantine newly created/modified files matching known "
            "ransomware extensions before they propagate to network shares.",
            "Snapshot volatile memory and disk state for forensics prior to "
            "remediation if this is a CRITICAL event.",
            "Rotate credentials used by the affected host/service account.",
            "Restore encrypted files from the most recent clean backup after "
            "confirming eradication.",
        ]
        if severity.upper() == "CRITICAL":
            base_steps.insert(0, "Activate the incident response team and "
                                  "declare a formal security incident immediately.")
        return "[Offline mode] Recommended steps for " + severity.upper() + \
            " severity in a " + industry + " environment:\n" + \
            "\n".join(f"{i+1}. {s}" for i, s in enumerate(base_steps))


if __name__ == "__main__":
    assistant = LLMSecurityAssistant()
    demo_features = {
        "file_modify_rate": 95, "file_rename_rate": 70, "file_delete_rate": 25,
        "avg_entropy": 7.7, "max_entropy": 7.95, "proc_cpu_percent": 72,
    }
    demo_assessment = {
        "risk_score": 91.4, "is_anomalous": True,
        "random_forest_probability": 0.93,
        "contributing_features": {"max_entropy": 7.95, "file_modify_rate": 95},
    }
    print(assistant.explain_event(demo_features, demo_assessment))
    print()
    print(assistant.recommend_mitigation("CRITICAL", "healthcare"))
