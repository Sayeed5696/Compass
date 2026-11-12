@echo off
setlocal enableextensions
set "APPDIR=%~dp0"
if "%APPDIR:~-1%"=="\" set "APPDIR=%APPDIR:~0,-1%"

rem --- find Windows' signed pythonw.exe (Smart App Control trusts it) ---
set "PYW="
for /f "delims=" %%I in ('where pythonw.exe 2^>nul') do if not defined PYW set "PYW=%%I"
if not defined PYW if exist "%SystemRoot%\pyw.exe" set "PYW=%SystemRoot%\pyw.exe"
if not defined PYW (
  echo.
  echo Could not find Python. Install Python 3.10 or newer from https://python.org
  echo and tick "Add python.exe to PATH" during setup, then run this again.
  echo.
  pause
  exit /b 1
)

set "TARGET=%APPDIR%\Compass.pyw"
set "ICON=%APPDIR%\launcher\compass.ico"
if not exist "%ICON%" set "ICON=%PYW%"

powershell -NoProfile -ExecutionPolicy Bypass -Command "$w=New-Object -ComObject WScript.Shell; foreach($p in @([Environment]::GetFolderPath('Desktop'),(Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'))){ $s=$w.CreateShortcut((Join-Path $p 'Compass.lnk')); $s.TargetPath=$env:PYW; $s.Arguments='\"'+$env:TARGET+'\"'; $s.WorkingDirectory=$env:APPDIR; $s.IconLocation=$env:ICON; $s.Description='Compass Threat Intelligence'; $s.Save() }"
if errorlevel 1 (
  echo.
  echo Could not create the shortcut automatically. You can make one by hand:
  echo   right-click Compass.pyw  ^>  Send to  ^>  Desktop ^(create shortcut^).
  echo.
  pause
  exit /b 1
)

echo.
echo Created a "Compass" shortcut on your Desktop and in the Start menu.
echo Double-click Compass to start it. It opens in your browser, with no console window.
echo.
pause
