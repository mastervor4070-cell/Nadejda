#Requires -Version 5.1
<#
    Nadejda for Windows: installer / uninstaller.

    Run from an elevated PowerShell:

        powershell -ExecutionPolicy Bypass -File windows\install.ps1
        powershell -ExecutionPolicy Bypass -File windows\install.ps1 -Start
        powershell -ExecutionPolicy Bypass -File windows\install.ps1 -NoTask
        powershell -ExecutionPolicy Bypass -File windows\install.ps1 -Uninstall

    The script copies the program to %ProgramData%\Nadejda\app, creates a
    virtual environment with pydivert (which bundles the signed WinDivert
    driver), installs the `nadejda-win` command, and registers a scheduled task
    that starts the engine elevated at logon (no UAC prompt on every boot).
#>
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$Start,
    [switch]$NoTask,
    [switch]$RemoveConfig
)

$ErrorActionPreference = "Stop"

$TaskName   = "Nadejda"
$Root       = Split-Path -Parent $PSScriptRoot
$Base       = Join-Path $env:ProgramData "Nadejda"
$AppDir     = Join-Path $Base "app"
$Venv       = Join-Path $Base "venv"
$Scripts    = Join-Path $Venv "Scripts"
$ConfigPath = Join-Path $Base "config.toml"
$Exe        = Join-Path $Scripts "nadejda-win.exe"
$StartMenu  = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"

function Write-Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Green
}

function Write-Warn([string]$Message) {
    Write-Host "warning: $Message" -ForegroundColor Yellow
}

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script as administrator (right-click -> Run as administrator)."
    }
}

function Find-Python {
    # The py.exe launcher is preferred: the Store alias for python.exe can
    # exist without a real interpreter and opens the Microsoft Store instead.
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($py) {
        $resolved = & $py.Source -3 -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $resolved) { return $resolved.Trim() }
    }
    $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Remove-Task {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Step "stopping and removing scheduled task '$TaskName'"
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
}

function Remove-FromUserPath {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $userPath) { return }
    $parts = $userPath.Split(';') | Where-Object { $_ -and ($_ -ne $Scripts) }
    [Environment]::SetEnvironmentVariable("Path", ($parts -join ';'), "User")
}

function Remove-Shortcuts {
    foreach ($name in @("Nadejda.lnk", "Nadejda (start).lnk")) {
        $path = Join-Path $StartMenu $name
        if (Test-Path $path) { Remove-Item $path -Force }
    }
}

# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------

if ($Uninstall) {
    Assert-Admin
    Remove-Task
    if (Test-Path $Exe) {
        Write-Step "stopping the running engine"
        & $Exe stop 2>$null | Out-Null
    }
    Remove-Shortcuts
    Remove-FromUserPath
    Write-Step "removing program files"
    if (Test-Path $AppDir) { Remove-Item $AppDir -Recurse -Force }
    if (Test-Path $Venv)   { Remove-Item $Venv -Recurse -Force }
    if ($RemoveConfig -and (Test-Path $ConfigPath)) {
        Remove-Item $ConfigPath -Force
        Write-Step "configuration removed"
    } elseif (Test-Path $ConfigPath) {
        Write-Host "configuration kept at $ConfigPath"
    }
    Write-Host ""
    Write-Host "Nadejda for Windows has been removed."
    exit 0
}

# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------

Assert-Admin

$python = Find-Python
if (-not $python) {
    throw "Python 3.11+ was not found in PATH. Install it from https://python.org (tick 'Add python.exe to PATH')."
}
& $python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"
if ($LASTEXITCODE -ne 0) {
    throw "Python 3.11 or newer is required (found: $(& $python -V 2>&1))."
}
Write-Step "python: $python"

# ---------------------------------------------------------------------------
# files
# ---------------------------------------------------------------------------

Remove-Task
if (Test-Path $Exe) {
    Write-Step "stopping the running engine"
    & $Exe stop 2>$null | Out-Null
}

New-Item -ItemType Directory -Force -Path $Base | Out-Null

$sourceFull = (Resolve-Path $Root).Path.TrimEnd('\')
$appFull = $AppDir.TrimEnd('\')
if ($sourceFull -ieq $appFull) {
    Write-Step "program is already in $AppDir; keeping it"
} else {
    Write-Step "copying program files to $AppDir"
    New-Item -ItemType Directory -Force -Path $AppDir | Out-Null
    & robocopy.exe $Root $AppDir /E `
        /XD .git __pycache__ .venv venv build dist .mypy_cache .pytest_cache `
        /XF *.pyc /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed with exit code $LASTEXITCODE" }
}

# ---------------------------------------------------------------------------
# virtual environment + pydivert
# ---------------------------------------------------------------------------

if (Test-Path $Venv) {
    Write-Step "recreating the virtual environment"
    Remove-Item $Venv -Recurse -Force
}
Write-Step "creating the virtual environment"
& $python -m venv $Venv
if ($LASTEXITCODE -ne 0) { throw "python -m venv failed" }

$venvPython = Join-Path $Scripts "python.exe"
Write-Step "installing pydivert and the nadejda-win command"
& $venvPython -m pip install --disable-pip-version-check --no-input --upgrade pip setuptools wheel
if ($LASTEXITCODE -ne 0) { throw "pip install (bootstrap) failed" }
& $venvPython -m pip install --disable-pip-version-check --no-input --no-build-isolation $AppDir
if ($LASTEXITCODE -ne 0) { throw "pip install nadejda failed" }

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------

if (Test-Path $ConfigPath) {
    Copy-Item (Join-Path $AppDir "config\config.toml") "$ConfigPath.new" -Force
    Write-Step "kept existing configuration (defaults written to $ConfigPath.new)"
} else {
    Copy-Item (Join-Path $AppDir "config\config.toml") $ConfigPath -Force
    Write-Step "installed default configuration"
}

# ---------------------------------------------------------------------------
# PATH
# ---------------------------------------------------------------------------

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$Scripts*") {
    if ([string]::IsNullOrEmpty($userPath)) {
        [Environment]::SetEnvironmentVariable("Path", $Scripts, "User")
    } else {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$Scripts", "User")
    }
    Write-Step "added $Scripts to the user PATH (open a new terminal to use it)"
}

# ---------------------------------------------------------------------------
# scheduled task (elevated start at logon, no UAC prompt)
# ---------------------------------------------------------------------------

if (-not $NoTask) {
    Write-Step "registering the scheduled task '$TaskName'"
    $command = "Start-Process -FilePath '$Exe' -ArgumentList 'start' -WindowStyle Hidden"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -Command `"$command`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit ([TimeSpan]::Zero)
    $principal = New-ScheduledTaskPrincipal `
        -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) `
        -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Settings $settings -Principal $principal -Force | Out-Null
}

# ---------------------------------------------------------------------------
# start menu shortcuts
# ---------------------------------------------------------------------------

New-Item -ItemType Directory -Force -Path $StartMenu | Out-Null
$shell = New-Object -ComObject WScript.Shell

$lnk = $shell.CreateShortcut((Join-Path $StartMenu "Nadejda.lnk"))
$lnk.TargetPath = Join-Path $Scripts "pythonw.exe"
$lnk.Arguments = "-m nadejda.win gui"
$lnk.WorkingDirectory = $AppDir
$lnk.Description = "Nadejda for Windows"
$lnk.Save()

if (-not $NoTask) {
    $lnk = $shell.CreateShortcut((Join-Path $StartMenu "Nadejda (start).lnk"))
    $lnk.TargetPath = "$env:SystemRoot\System32\schtasks.exe"
    $lnk.Arguments = "/Run /TN $TaskName"
    $lnk.Description = "Start the Nadejda engine (elevated scheduled task)"
    $lnk.Save()
}

# ---------------------------------------------------------------------------
# done
# ---------------------------------------------------------------------------

if ($Start -and -not $NoTask) {
    Write-Step "starting Nadejda"
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 2
    & $Exe status
}

Write-Host ""
Write-Host "Nadejda for Windows is installed." -ForegroundColor Green
Write-Host ""
Write-Host "  config     : $ConfigPath"
Write-Host "  command    : nadejda-win  (open a new terminal)"
Write-Host "  GUI        : Start menu -> Nadejda"
Write-Host "  autostart  : scheduled task '$TaskName' (elevated, at logon)"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. nadejda-win test          # filter + strategy self-check"
Write-Host "  2. nadejda-win start         # run in this elevated terminal"
Write-Host "     or: schtasks /Run /TN $TaskName"
Write-Host "  3. nadejda-win status        # counters"
Write-Host ""
if (-not $Start) {
    Write-Host "The engine was not started. Use 'schtasks /Run /TN $TaskName' or the"
    Write-Host "'Nadejda (start)' shortcut in the Start menu."
}
