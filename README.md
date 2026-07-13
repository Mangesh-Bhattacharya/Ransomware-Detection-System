# ⛨ Ransomware Detection System

A Python-based, multi-industry ransomware detection and response platform that monitors
file system activity and running processes in real time.  Designed for use in regulated
sectors including **Healthcare, Banking & Finance, Nuclear, Energy & Utilities, and Government**,
with compliance tagging for HIPAA, PCI-DSS, NRC 10 CFR 73.54, NERC CIP, FISMA, CMMC,
GLBA, SOX, SWIFT-CSCF, IEC-62443, ISO-27001, and NIST frameworks.

---

## 📌 Overview

The system provides **five layers of detection**:

| Layer | Method | Module |
|-------|--------|--------|
| 1 | Suspicious file extension matching (50+ ransomware extensions) | `threat_intelligence.py` |
| 2 | Behavioral rate analysis — renames, modifications, deletions per minute | `behavioral_analyzer.py` |
| 3 | Shannon entropy screening — detects encrypted files in real time | `behavioral_analyzer.py` |
| 4 | SHA-256 hash matching against known ransomware family samples | `threat_intelligence.py` |
| 5 | Process name heuristics — kills ransomware-like processes on detection | `ransomware_monitor.py` |

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| **Industry Profiles** | Pre-configured profiles for healthcare, banking, nuclear, energy, government, and general use |
| **Compliance Tagging** | Every alert is tagged with the relevant NIST 800-53 / CSF controls for the active compliance framework |
| **Regulatory Notifications** | Incident reports include sector-specific breach notification obligations (HIPAA 60-day, NRC 1-hour, NERC CIP, CMMC 72-hour, etc.) |
| **Custom IOC Feeds** | Load JSON files with org-specific hashes, extensions, and process patterns (see `custom_ioc_template.json`) |
| **Incident Reports** | Structured JSON incident reports saved to `logs/incidents/` with NIST SP 800-61r2 phase mapping |
| **LLM Context Packets** | `BehavioralAnalyzer.build_llm_context_packet()` packages all telemetry for downstream LLM-based analysis |
| **Live Dashboard** | Real-time counter panel — modify rate, rename rate, delete rate, extension diversity, alert count |
| **Full-System Scan** | Walk entire filesystem and apply all detection layers to every file |
| **Real-Time Monitoring** | Watchdog-based directory monitoring with recursive observation |
| **Process Blocking** | Automatic termination of processes matching 25+ known ransomware name patterns |
| **Audit Logs** | CSV logs with timestamp, event type, path, extension, entropy, SHA-256, severity, industry |

---

## 🏭 Industry Profiles

| Profile Key | Label | Frameworks | Severity Boost |
|-------------|-------|-----------|----------------|
| `healthcare` | Healthcare (HIPAA / HITECH) | HIPAA, HITECH, NIST-CSF, SOC2 | +2 |
| `banking` | Banking & Finance (PCI-DSS / GLBA / SOX) | PCI-DSS, GLBA, SOX, SWIFT-CSCF, NIST-CSF | +2 |
| `nuclear` | Nuclear (NRC 10 CFR 73.54 / NERC CIP) | NRC-10CFR73.54, NERC-CIP, ICS-CERT, NIST-SP800-82 | +3 |
| `energy` | Energy & Utilities (NERC CIP / IEC-62443) | NERC-CIP, ICS-CERT, NIST-SP800-82, IEC-62443 | +3 |
| `government` | Government (FISMA / CMMC / FedRAMP) | FISMA, CMMC, FedRAMP, NIST-800-53, CJIS | +2 |
| `general` | General Purpose | NIST-CSF, ISO-27001 | 0 |

Severity boost adds to the base detection score — nuclear/energy incidents escalate to
**CRITICAL** faster due to safety-critical OT/ICS environments.

---

## 📂 Project Structure

```
Ransomware-Detection-System/
├── main.py                    # Entry point (argparse CLI + logging config)
├── application.py             # tkinter GUI with dashboard, industry selector, report viewer
├── ransomware_monitor.py      # Watchdog event handler + multi-layer detection pipeline
├── threat_intelligence.py     # Industry profiles, IOC feeds, entropy, hash check engine
├── behavioral_analyzer.py     # Sliding-window counters, LLM context packet builder
├── incident_reporter.py       # Compliance-tagged JSON incident reports
├── custom_ioc_template.json   # Template for org-specific custom IOC feeds
├── requirements.txt
├── logs/
│   ├── system.log             # Structured application log
│   ├── ransomware_scan_log.csv
│   └── incidents/             # JSON incident reports (per detection event)
└── README.md
```

---

## 🛠 Installation & Usage

### 1. Clone the repository

```bash
git clone https://github.com/Mangesh-Bhattacharya/Ransomware-Detection-System.git
cd Ransomware-Detection-System
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

> **Linux users:** Install tkinter via your package manager:
> `sudo apt install python3-tk` (Debian/Ubuntu) or `sudo dnf install python3-tkinter` (RHEL/Fedora)

### 3. Run

```bash
# Default — launch GUI with general profile
python main.py

# Pre-select an industry profile
python main.py --industry healthcare
python main.py --industry nuclear
python main.py --industry banking

# Load a custom IOC feed on startup
python main.py --industry healthcare --ioc custom_ioc_template.json
```

---

## 🔒 Custom IOC Feeds

Edit `custom_ioc_template.json` to add organization-specific indicators:

```json
{
  "hashes": ["sha256_of_known_bad_file"],
  "extensions": [".sector_specific_enc"],
  "process_patterns": ["malicious_process_name"]
}
```

Recommended external IOC sources:
- [CISA #StopRansomware advisories](https://www.cisa.gov/stopransomware)
- [FBI Flash reports (TLP:WHITE)](https://www.ic3.gov/Media/News/2024)
- Sector ISACs: FS-ISAC (banking), H-ISAC (healthcare), E-ISAC (energy), WaterISAC

---

## 🧠 LLM Integration

The `BehavioralAnalyzer` class exposes `build_llm_context_packet()` which returns a
fully structured JSON object containing all current telemetry, alert history, and industry
profile data. This packet can be submitted to any LLM API (self-hosted or commercial) for:

- Automated incident narrative generation
- Root-cause analysis assistance
- Natural-language compliance impact assessment
- Threat-actor attribution suggestions

No LLM calls are made inside the library — integration is entirely in the hands of the operator.

---

## 📄 Incident Reports

Every HIGH or CRITICAL event generates a JSON incident report in `logs/incidents/`.
Reports include:

- Unique incident ID (UUID)
- NIST SP 800-61r2 phase assignment
- Threat summary (entropy, hash, extension, counters)
- Compliance obligations per active framework
- Regulatory notification deadlines (sector-specific)
- Ordered containment action list
- Blast-radius estimate

View all reports from within the GUI via the **View Incident Reports** button.

---

## ⚠️ Regulatory Notification Reference

| Framework | Notification Requirement |
|-----------|-------------------------|
| HIPAA | 60 days to HHS; immediate if >500 individuals affected |
| NRC 10 CFR 73.54 | 1 hour to NRC Operations Center |
| NERC CIP-008 | 1 hour to E-ISAC for Critical Incidents |
| PCI-DSS 12.10.1 | Immediate notification to card brands and acquirer |
| CMMC | 72 hours via dibnet.pentagon.mil |
| FISMA | 1 hour to US-CERT for major incidents |
| GLBA | 30 days to FTC if 500+ customers affected |

---

## ⚙️ Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| watchdog | 4.0.0 | Real-time file system event monitoring |
| psutil | 5.9.8 | Process inspection and termination |
| openpyxl | 3.1.3 | Excel report generation |
| tkinter | stdlib | GUI (bundled with Python) |

---

## ⚠️ Disclaimer

This tool is designed for use by cybersecurity professionals in regulated environments.
It is **not** a replacement for a comprehensive EDR/XDR platform, enterprise SIEM, or
professional incident response services.  Always deploy as part of a layered defense
strategy and in accordance with your organization’s security policy and applicable regulations.
For OT/ICS environments (nuclear, energy), validate compatibility with safety-critical
systems before deployment.


## AI/ML Extensions — Behavioral Intelligence & Automated Response

Beyond the original five-layer detection pipeline, this project now includes
an AI-augmented tier for anomaly detection, natural-language analysis, live
visualization, safe attack simulation, and automated containment.

| Module | Purpose |
|---|---|
| `ml_models/anomaly_detector.py` | `IsolationForest` (unsupervised) + `RandomForestClassifier` (supervised) trained on file-activity/process-behavior features; blends both into a single 0–100 risk score |
| `llm_assistant.py` | LLM-powered assistant that explains suspicious events, generates incident narratives, and recommends prioritized mitigation steps — works fully offline via deterministic templates, or online via any OpenAI-compatible API |
| `dashboard.py` | Real-time Streamlit dashboard: live telemetry, ML risk score simulator, incident report browser, top-process view, and a one-click sandbox trigger |
| `sandbox/sandbox_simulator.py` | Safe, self-contained simulation of ransomware-like file behavior (no real malware/cryptography) used to measure detection accuracy end-to-end |
| `auto_response.py` | Dry-run-by-default containment engine: process termination, file quarantine (move, never delete), and network adapter isolation |
| `docs/ARCHITECTURE.md` | Full architecture diagram and data-flow documentation for the extended platform |
| `docs/DEPLOYMENT.md` | Step-by-step local, Docker, and systemd deployment instructions |

### Quick start for the new components

```bash
pip install -r requirements.txt

# Train the ML anomaly-detection models (uses a synthetic bootstrap dataset)
python ml_models/anomaly_detector.py

# Launch the real-time dashboard
streamlit run dashboard.py

# Run a safe sandbox attack simulation to validate detection accuracy
python sandbox/sandbox_simulator.py
```

The LLM assistant runs fully offline by default. To enable live LLM calls,
set `LLM_API_KEY` (and optionally `LLM_MODEL` / `LLM_BASE_URL`) as
environment variables — never commit API keys to source control.

`auto_response.py` defaults every action to `dry_run=True`. Live
enforcement (process termination, file quarantine, network isolation) must
be explicitly enabled by the operator and should be validated in
`sandbox/sandbox_simulator.py` and a staging environment first. See
`docs/ARCHITECTURE.md` and `docs/DEPLOYMENT.md` for full details.
