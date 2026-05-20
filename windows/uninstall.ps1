#Requires -Version 5.1
# Plex Command Center - Windows Service Uninstaller
#
# Run from an *elevated* PowerShell:
#   .\uninstall.ps1
#
# By default this only removes the Windows Service registration. App files and the data
# directory are left intact. Pass -RemoveAll to wipe everything including DBs and fillers.

param(
  [switch]$RemoveAll
)

$ErrorActionPreference = 'Continue'

$current = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($current)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Must be run as Administrator." -ForegroundColor Red
  exit 1
}

$InstallDir = "$env:ProgramFiles\PlexCommandCenter"
$DataDir    = "$env:ProgramData\PlexCommandCenter"

if (-not (Test-Path $InstallDir)) {
  Write-Host "Not installed at $InstallDir - nothing to do." -ForegroundColor Yellow
  exit 0
}

Push-Location $InstallDir
try {
  Write-Host "==> Removing Windows Service" -ForegroundColor Cyan
  & node "windows\service-uninstaller.js"
} finally { Pop-Location }

if ($RemoveAll) {
  Write-Host "==> Removing install files at $InstallDir" -ForegroundColor Cyan
  Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction Continue
  Write-Host "==> Removing data dir at $DataDir" -ForegroundColor Cyan
  Remove-Item -Path $DataDir -Recurse -Force -ErrorAction Continue
  Write-Host "All gone."  -ForegroundColor Green
} else {
  Write-Host ""
  Write-Host "Service removed. Files kept:"
  Write-Host "  Install: $InstallDir"
  Write-Host "  Data   : $DataDir"
  Write-Host ""
  Write-Host "Re-run with -RemoveAll to wipe everything."
}
