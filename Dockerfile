# Dockerfile — Ransomware Detection System
#
# Builds a container image capable of running either:
#   * the Streamlit dashboard (default), or
#   * the core file/process monitor (main.py), or
#   * the ML training script
#
# Usage:
#   docker build -t ransomware-detection .
#   docker run -p 8501:8501 ransomware-detection                       # dashboard
#   docker run ransomware-detection python main.py --industry general  # monitor
#   docker run ransomware-detection python ml_models/anomaly_detector.py  # train

FROM python:3.11-slim

# python3-tk is only needed if you plan to run application.py's GUI inside
# the container with X11 forwarding; harmless to include for compatibility.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-tk \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p logs/incidents logs/quarantine logs/sandbox

EXPOSE 8501

CMD ["streamlit", "run", "dashboard.py", "--server.address", "0.0.0.0"]
