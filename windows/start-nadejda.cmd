@echo off
rem Start Nadejda for Windows with an UAC prompt.
rem
rem   windows\start-nadejda.cmd          - run the installed engine
rem   windows\start-nadejda.cmd test     - run a subcommand instead of "start"
rem
rem For autostart without UAC use the scheduled task created by install.ps1:
rem   schtasks /Run /TN Nadejda
setlocal

set "ACTION=%~1"
if "%ACTION%"=="" set "ACTION=start"

set "EXE=%ProgramData%\Nadejda\venv\Scripts\nadejda-win.exe"
if exist "%EXE%" goto installed

rem Not installed: run straight from the repository (requires Python 3.11+).
set "EXE=python"
set "ARGS=-m nadejda.win %ACTION%"
goto elevate

:installed
set "ARGS=%ACTION%"

:elevate
echo Starting Nadejda as administrator...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process -FilePath '%EXE%' -ArgumentList '%ARGS%' -WorkingDirectory '%CD%' -Verb RunAs"

endlocal
