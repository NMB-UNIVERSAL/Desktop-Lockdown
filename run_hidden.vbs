Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
strPath = fso.GetParentFolderName(WScript.ScriptFullName)

' Change to the script directory
WshShell.CurrentDirectory = strPath

' Run Python script with administrator privileges (hidden)
WshShell.Run "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command ""Start-Process -FilePath 'python' -ArgumentList 'server.py' -Verb RunAs -WindowStyle Hidden""", 0, False 