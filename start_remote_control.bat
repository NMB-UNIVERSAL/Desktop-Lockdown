@echo off
echo Starting Nubaid Lockdown Remote Control...
echo This requires administrator privileges.
echo.

REM Request admin privileges
powershell -Command "Start-Process cmd -ArgumentList '/c cd /d %~dp0 && python server.py' -Verb RunAs" 