@echo off
echo Stopping Nubaid Lockdown Server...
taskkill /f /im NubaidLockdown.exe 2>nul
taskkill /f /im python.exe /fi "WINDOWTITLE eq python server.py" 2>nul
echo Done!
pause 