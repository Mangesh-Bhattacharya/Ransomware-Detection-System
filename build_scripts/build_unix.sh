#!/usr/bin/env bash
# build_unix.sh — Package the core detection GUI (application.py) as a
# standalone macOS/Linux executable using PyInstaller.
#
# Usage:
#   bash build_scripts/build_unix.sh

set -euo pipefail

pip install pyinstaller

pyinstaller --name RansomwareDetectionSystem \
    --onedir \
    --windowed \
    --add-data "custom_ioc_template.json:." \
    --hidden-import psutil \
    --hidden-import watchdog \
    application.py

echo
echo "Build complete. Find the executable in dist/RansomwareDetectionSystem/"
