# Packaging & Easy-Run Options

This guide covers the two easiest ways to run the Ransomware Detection
System without needing git or manual Python environment setup: Docker
(recommended for most users and for enterprises) and a standalone
executable built with PyInstaller (best for non-technical end users who
only need the core detection GUI).

## Option 1: Docker / Docker Compose (recommended)

Best for: technically advanced teams, enterprises, and anyone comfortable
installing Docker Desktop once.

1. Download the repository as a ZIP from GitHub ("Code" -> "Download ZIP")
   and extract it -- no git command required.
2. Install Docker Desktop (docker.com/products/docker-desktop) if you
   don't already have it.
3. From the project folder, run:

```bash
docker compose up --build
```

4. Open http://localhost:8501 in a browser to use the real-time dashboard.
5. To train the ML models once before first use:

```bash
docker compose run --rm trainer
```

This single command builds the image, installs every dependency
(scikit-learn, streamlit, psutil, etc.), and starts both the dashboard and
the background monitor -- no pip, virtualenv, or Python version issues to
troubleshoot. It's also the natural foundation for a larger rollout: the
same image can be pushed to a private registry, scanned for
vulnerabilities, and deployed via Kubernetes, ECS, or a container-managed
fleet without any changes to the application itself.

See docker-compose.yml and Dockerfile at the repository root, and
docs/DEPLOYMENT.md for production hardening notes (reverse proxy, TLS,
authentication in front of the dashboard, etc.).

## Option 2: Standalone executable (for non-technical end users)

Best for: end users who just want to double-click and run the core
detection GUI, with no Docker or Python knowledge required.

The scripts in build_scripts/ use PyInstaller (pyinstaller.org) to bundle
application.py (the tkinter GUI) and its dependencies into a single
folder containing a native executable:

```bash
# Windows (run from an activated venv with requirements.txt installed)
build_scripts\build_windows.bat

# macOS / Linux
bash build_scripts/build_unix.sh
```

Both scripts install PyInstaller, then produce a
dist/RansomwareDetectionSystem/ folder containing the executable and all
bundled dependencies. Zip that folder and hand it to end users -- they
only need to double-click the executable inside; no Python installation
is required on their machine.

**Scope note:** this packaging path bundles the original tkinter GUI and
core detection pipeline only. The newer ML training, Streamlit dashboard,
and sandbox tooling are intended for analysts/IT staff and are better
distributed via the Docker path above, since they involve heavier
dependencies (scikit-learn, streamlit) that aren't a good fit for a
lightweight single-user executable.

## Choosing between the two

| Scenario | Recommended option |
|---|---|
| Enterprise-wide rollout, multiple endpoints, central dashboard | Docker / Docker Compose |
| Security/IT team wants ML risk scoring, LLM assistant, sandbox demos | Docker / Docker Compose |
| Individual non-technical user wants the core detector only | Standalone executable (PyInstaller) |
| CI/CD, automated testing, cloud deployment | Docker / Docker Compose |
