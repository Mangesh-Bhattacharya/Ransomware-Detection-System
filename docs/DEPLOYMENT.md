# Deployment Guide

This guide covers deploying the AI-augmented Ransomware Detection System —
core monitor, ML models, LLM assistant, Streamlit dashboard, sandbox, and
auto-response engine — from a local workstation up to a production host.

## 1. Prerequisites

* Python 3.10+
* pip
* (Linux) `python3-tk` for the legacy tkinter GUI: `sudo apt install python3-tk`
* Optional: an OpenAI-compatible API key if you want live LLM responses
  instead of the built-in offline fallback

## 2. Local installation

```bash
git clone https://github.com/Mangesh-Bhattacharya/Ransomware-Detection-System.git
cd Ransomware-Detection-System
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 3. Train the ML models

The IsolationForest / RandomForest models ship untrained. Bootstrap them with
the built-in synthetic dataset (recommended starting point), then retrain
periodically on real telemetry as it accumulates in `logs/`:

```bash
python ml_models/anomaly_detector.py
```

This writes `ml_models/saved_models/ransomware_ml_model.joblib`, which is
loaded automatically by `dashboard.py` and can be loaded from any module via
`MLAnomalyDetector.load()`.

## 4. Configure the LLM assistant (optional)

The LLM assistant works fully offline out of the box. To enable live LLM
calls:

```bash
export LLM_API_KEY="sk-..."          # never commit this to source control
export LLM_MODEL="gpt-4o-mini"       # optional, defaults shown
export LLM_BASE_URL="https://..."    # optional, for self-hosted gateways
```

Store secrets in your OS keychain, a secrets manager, or a local `.env` file
that is excluded via `.gitignore` — never hard-code API keys in source.

## 5. Run the core monitor (tkinter GUI)

```bash
python main.py --industry healthcare
```

## 6. Run the real-time Streamlit dashboard

```bash
streamlit run dashboard.py
```

By default this serves on `http://localhost:8501`. For remote/server
deployment, bind to all interfaces and put it behind a reverse proxy with
TLS and authentication (Streamlit itself has no built-in auth):

```bash
streamlit run dashboard.py --server.address 0.0.0.0 --server.port 8501
```

Recommended production front door: nginx or Caddy terminating TLS, with
HTTP basic auth or SSO (e.g. an OAuth2 proxy) in front of Streamlit — do not
expose the dashboard directly to the internet without an auth layer.

## 7. Validate detection accuracy with sandbox mode

```bash
python sandbox/sandbox_simulator.py
```

Or trigger it from the dashboard's "Sandbox Mode" panel. This creates and
cleans up its own isolated directory under `logs/sandbox/` and never touches
real files — safe to run repeatedly in CI or during onboarding demos.

## 8. Enable auto-response (optional, use with caution)

`auto_response.py` defaults to `dry_run=True` everywhere. To enable live
enforcement in your own integration code:

```python
from auto_response import AutoResponseEngine

engine = AutoResponseEngine(watch_root="/path/being/monitored")
engine.terminate_process(pid=1234, dry_run=False)
engine.quarantine_file("/path/being/monitored/suspicious.locked", dry_run=False)
engine.isolate_network(dry_run=False)
```

Test thoroughly in the sandbox and in a staging environment before enabling
`dry_run=False` on any production host. Network isolation and process
termination are disruptive actions — restrict them to CRITICAL-severity
events and pair with a human-in-the-loop approval step where possible.

## 9. Running as a background service

**Linux (systemd)** — example unit for the monitor:

```ini
[Unit]
Description=Ransomware Detection Monitor
After=network.target

[Service]
WorkingDirectory=/opt/ransomware-detection-system
ExecStart=/opt/ransomware-detection-system/.venv/bin/python main.py --industry general
Restart=on-failure
User=ransomware-monitor

[Install]
WantedBy=multi-user.target
```

Run the dashboard as a second unit invoking `streamlit run dashboard.py`.

**Docker** — minimal example `Dockerfile` for the dashboard service:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8501
CMD ["streamlit", "run", "dashboard.py", "--server.address", "0.0.0.0"]
```

## 10. Operational notes

* Rotate and back up `logs/incidents/` — these are your compliance record.
* Retrain the ML models on real, labeled telemetry as it accumulates;
  synthetic training data is only a bootstrap.
* This platform is a layered-defense component, not a replacement for
  enterprise EDR/XDR, SIEM, or professional incident response — see the
  disclaimer in `README.md`.
