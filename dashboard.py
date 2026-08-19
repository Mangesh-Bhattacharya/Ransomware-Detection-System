"""
dashboard.py

Real-time Streamlit dashboard for the Ransomware Detection System.

Run with:
    streamlit run dashboard.py

Displays:
  * Live telemetry (file event rates, entropy trend) pulled from
    logs/ransomware_scan_log.csv
  * Blended ML risk score (IsolationForest + RandomForest) via
    ml_models.anomaly_detector.MLAnomalyDetector
  * Incident report browser (logs/incidents/*.json)
  * Top system/process activity snapshot (psutil)
  * One-click sandbox attack simulation trigger
  * LLM assistant panel for natural-language incident explanations
"""

from __future__ import annotations

import glob
import json
from pathlib import Path

import pandas as pd
import psutil
import streamlit as st

from llm_assistant import LLMSecurityAssistant
from ml_models.anomaly_detector import MLAnomalyDetector

LOG_DIR = Path("logs")
CSV_LOG = LOG_DIR / "ransomware_scan_log.csv"
INCIDENT_DIR = LOG_DIR / "incidents"

st.set_page_config(
    page_title="Ransomware Detection - Live Dashboard",
    page_icon="🛡",
    layout="wide",
)


@st.cache_resource(show_spinner="Loading ML models...")
def get_detector():
    try:
        return MLAnomalyDetector.load()
    except FileNotFoundError:
        return None


@st.cache_resource
def get_assistant() -> LLMSecurityAssistant:
    return LLMSecurityAssistant()


def load_csv_log() -> pd.DataFrame:
    if not CSV_LOG.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(CSV_LOG, on_bad_lines="skip")
    except Exception:
        return pd.DataFrame()


def load_incidents() -> list:
    if not INCIDENT_DIR.exists():
        return []
    incidents = []
    for path in sorted(glob.glob(str(INCIDENT_DIR / "*.json")), reverse=True):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                incidents.append(json.load(fh))
        except Exception:
            continue
    return incidents


def current_process_snapshot(limit: int = 12) -> pd.DataFrame:
    rows = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "num_threads"]):
        try:
            rows.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    return df.sort_values("cpu_percent", ascending=False).head(limit)


st.title("🛡 Ransomware Detection System — Live Dashboard")
st.caption("AI-augmented behavioral monitoring, ML anomaly detection, and incident response")

detector = get_detector()
assistant = get_assistant()

log_df = load_csv_log()
incidents = load_incidents()

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Events Logged", len(log_df) if not log_df.empty else 0)
with col2:
    st.metric("Incidents Recorded", len(incidents))
with col3:
    critical = sum(1 for i in incidents if str(i.get("severity", "")).upper() == "CRITICAL")
    st.metric("Critical Incidents", critical)
with col4:
    st.metric("ML Model Status", "Loaded" if detector else "Not Trained")

st.divider()

left, right = st.columns([2, 1])

with left:
    st.subheader("📈 Live Telemetry")
    if not log_df.empty:
        numeric_df = log_df.select_dtypes(include="number")
        if not numeric_df.empty:
            st.line_chart(numeric_df.tail(200))
        else:
            st.dataframe(log_df.tail(50), use_container_width=True)
    else:
        st.info("No telemetry logged yet. Start ransomware_monitor.py to populate "
                "logs/ransomware_scan_log.csv.")

    st.subheader("🧮 ML Risk Score Simulator")
    st.caption("Adjust behavioral sliders to see the blended IsolationForest / "
               "RandomForest risk score update live.")
    defaults = {
        "file_modify_rate": (0, 150, 5), "file_rename_rate": (0, 150, 1),
        "file_delete_rate": (0, 100, 1), "file_create_rate": (0, 100, 2),
        "unique_extension_count": (0, 25, 3), "avg_entropy": (0.0, 8.0, 3.5),
        "max_entropy": (0.0, 8.0, 4.5), "proc_cpu_percent": (0, 100, 10),
        "proc_child_count": (0, 20, 1), "proc_handle_count": (0, 300, 15),
        "network_conn_count": (0, 30, 2),
    }
    feature_inputs = {}
    slider_cols = st.columns(3)
    for idx, (feat, (lo, hi, default)) in enumerate(defaults.items()):
        with slider_cols[idx % 3]:
            feature_inputs[feat] = st.slider(feat, lo, hi, default)

    if detector:
        assessment = detector.assess(feature_inputs)
        risk = assessment.risk_score
        badge = "🟢" if risk < 30 else "🟡" if risk < 65 else "🔴"
        st.metric(f"{badge} Blended Risk Score", f"{risk:.1f} / 100")
        st.progress(min(int(risk), 100))
        if st.button("🧠 Ask LLM Assistant to Explain This Score"):
            st.info(assistant.explain_event(feature_inputs, assessment.to_dict()))
    else:
        st.warning("No trained ML model found. Run `python ml_models/anomaly_detector.py` "
                   "to train and save one.")

with right:
    st.subheader("🧾 Recent Incident Reports")
    if not incidents:
        st.info("No incident reports yet.")
    for incident in incidents[:8]:
        sev = str(incident.get("severity", "UNKNOWN")).upper()
        badge = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(sev, "⚪")
        with st.expander(f"{badge} {str(incident.get('incident_id', 'unknown'))[:8]} — {sev}"):
            st.json(incident)
            if st.button("Generate LLM Summary", key=f"llm_{incident.get('incident_id')}"):
                st.write(assistant.generate_incident_report(incident))

    st.subheader("⚙ Top Processes by CPU")
    proc_df = current_process_snapshot()
    if not proc_df.empty:
        st.dataframe(proc_df, use_container_width=True)

st.divider()
st.subheader("🧪 Sandbox Mode")
st.caption("Simulate a ransomware attack pattern in an isolated sandbox directory "
           "to validate detection accuracy.")
if st.button("Launch Sandbox Simulation"):
    with st.spinner("Running sandbox simulation..."):
        from sandbox.sandbox_simulator import run_simulation
        result = run_simulation()
    st.success(
        f"Simulation complete — detected {result['detected_events']}/"
        f"{result['total_events']} malicious events "
        f"({result['detection_rate']:.1f}% detection rate)"
    )
    st.json(result)

st.caption("This dashboard reads local logs/incidents only — no telemetry leaves the host.")
