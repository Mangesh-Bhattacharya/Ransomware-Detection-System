@echo off
REM build_windows.bat — Package the core detection GUI (application.py) as a
REM standalone Windows executable using PyInstaller. Produces
REM dist\RansomwareDetectionSystem\RansomwareDetectionSystem.exe
REM
REM Usage:
REM   build_scripts\build_windows.bat

pip install pyinstaller

pyinstaller --name RansomwareDetectionSystem ^
    --onedir ^
    --windowed ^
    --add-data "custom_ioc_template.json;." ^
    --hidden-import psutil ^
    --hidden-import watchdog ^
    application.py

echo.
echo Build complete. Find the executable in dist\RansomwareDetectionSystem\
