@echo off
setlocal
rem Troubleshooting only: runs Compass with a console window so you can see
rem every message. For normal use, double-click Compass.exe instead.
cd /d "%~dp0.."
title Compass (console)
python --version >nul 2>&1
if errorlevel 1 (
  echo Python 3.10 or newer is required. Install it from python.org and tick
  echo "Add python.exe to PATH" during setup, then run this file again.
  pause
  exit /b 1
)
python -c "import certifi" >nul 2>&1
if errorlevel 1 (
  echo Installing the CA certificate bundle ^(certifi^)...
  python -m pip install -r requirements.txt
)
python server.py
if errorlevel 1 (
  echo.
  echo The server stopped with an error.
  pause
)
