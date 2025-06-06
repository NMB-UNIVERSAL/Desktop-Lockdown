@echo off
echo Setting up Nubaid Lockdown to start automatically when Windows boots...

:: Check for admin rights
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if %errorlevel% neq 0 (
    echo Administrator privileges required.
    echo Please run this script as administrator.
    pause
    exit /b 1
)

:: Get the current directory
set "CURRENT_DIR=%~dp0"
set "STARTUP_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"

:: Create modified VBS script for the compiled exe
echo Set WshShell = CreateObject("WScript.Shell") > "%CURRENT_DIR%\run_lockdown.vbs"
echo Set fso = CreateObject("Scripting.FileSystemObject") >> "%CURRENT_DIR%\run_lockdown.vbs"
echo strPath = fso.GetParentFolderName(WScript.ScriptFullName) >> "%CURRENT_DIR%\run_lockdown.vbs"
echo. >> "%CURRENT_DIR%\run_lockdown.vbs"
echo ' Change to the script directory >> "%CURRENT_DIR%\run_lockdown.vbs"
echo WshShell.CurrentDirectory = strPath >> "%CURRENT_DIR%\run_lockdown.vbs"
echo. >> "%CURRENT_DIR%\run_lockdown.vbs"
echo ' Run the executable with administrator privileges (hidden) >> "%CURRENT_DIR%\run_lockdown.vbs"
echo WshShell.Run "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command ""Start-Process -FilePath '" ^& strPath ^& "\NubaidLockdown.exe' -Verb RunAs -WindowStyle Hidden""", 0, False >> "%CURRENT_DIR%\run_lockdown.vbs"

:: Create the shortcut in the startup folder
echo Creating shortcut in Windows startup folder...
powershell -Command "$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%STARTUP_DIR%\NubaidLockdown.lnk'); $Shortcut.TargetPath = 'wscript.exe'; $Shortcut.Arguments = '\"%CURRENT_DIR%run_lockdown.vbs\"'; $Shortcut.WorkingDirectory = '%CURRENT_DIR%'; $Shortcut.Description = 'Nubaid Lockdown'; $Shortcut.Save()"

echo.
echo Setup complete! Nubaid Lockdown will now start automatically when Windows boots.
echo.
echo Would you like to start Nubaid Lockdown now? (Y/N)
set /p STARTCHOICE="> "
if /i "%STARTCHOICE%"=="Y" (
    start "" wscript.exe "%CURRENT_DIR%run_lockdown.vbs"
    echo Nubaid Lockdown started!
)

pause 