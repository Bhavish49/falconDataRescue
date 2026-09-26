@echo off
REM ---- Self-elevate to Administrator (needed for raw disk / NTFS $MFT access) ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

title falconDataRescue Recovery Server (Administrator)
cd /d c:\MCE\backend
echo Backend server starting at http://127.0.0.1:8010  [Administrator]
echo Open that address to use the recovery UI.
echo Deleted-file drive scans now have raw disk access.
echo Press Ctrl+C to stop the server.
echo.
python -m uvicorn app.main:app --host 127.0.0.1 --port 8010
