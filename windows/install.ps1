#Requires -Version 5.1
# Plex Command Center - Windows Service Installer
#
# Run from an *elevated* PowerShell:
#   Set-ExecutionPolicy -Scope Process Bypass
#   .\install.ps1
#
# What this does:
#   1. Verifies Node.js >= 18.
#   2. Copies app files to %ProgramFiles%\PlexCommandCenter.
#   3. Creates the data directory at %ProgramData%\PlexCommandCenter.
#   4. Downloads ffmpeg + yt-dlp into <install>\bin (skip if already present).
#   5. Migrates existing Docker data (./data) if found, on opt-in.
#   6. Runs `npm install --omit=dev` to fetch dependencies (including node-windows).
#   7. Registers and starts the Windows Service.

$ErrorActionPreference = 'Stop'

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "  + $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  ! $msg" -ForegroundColor Yellow }

# 0. Elevation check
$current = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($current)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "This installer must be run as Administrator." -ForegroundColor Red
  Write-Host "Right-click PowerShell, choose 'Run as Administrator', then re-run." -ForegroundColor Red
  exit 1
}

$SrcDir     = Split-Path -Parent $PSScriptRoot
$InstallDir = "$env:ProgramFiles\PlexCommandCenter"
$DataDir    = "$env:ProgramData\PlexCommandCenter"
$BinDir     = Join-Path $InstallDir 'bin'

# 1. Node.js version check
Write-Step 'Checking Node.js'
try {
  $nodeVer = (node --version) -replace '^v',''
  $major = [int]($nodeVer.Split('.')[0])
  if ($major -lt 18) { throw "Need Node 18+, found $nodeVer" }
  Write-Ok "Node.js $nodeVer OK"
} catch {
  Write-Host "Node.js 18 or higher is required. Install the LTS build from https://nodejs.org/, then re-run." -ForegroundColor Red
  exit 1
}

# 2. Copy app files
Write-Step "Copying application files to $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
# Exclude data dirs / build artifacts so users with an existing checkout don't lose state.
$exclude = @('data', 'node_modules', 'logs', '.git', 'srv.log', '*.zip')
Get-ChildItem -Path $SrcDir -Force | Where-Object { $exclude -notcontains $_.Name } | ForEach-Object {
  Copy-Item -Path $_.FullName -Destination $InstallDir -Recurse -Force
}
Write-Ok "Files copied"

# 3. Data directory
Write-Step "Setting up data directory at $DataDir"
New-Item -ItemType Directory -Force -Path $DataDir, $BinDir | Out-Null
Write-Ok "Created $DataDir"

# 4. Download ffmpeg + yt-dlp if missing
function Download-File($url, $out) {
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
  } catch {
    Write-Host "Download failed for $url`: $($_.Exception.Message)" -ForegroundColor Red
    throw
  }
}

$ffmpeg  = Join-Path $BinDir 'ffmpeg.exe'
$ffprobe = Join-Path $BinDir 'ffprobe.exe'
$ytdlp   = Join-Path $BinDir 'yt-dlp.exe'

if (-not (Test-Path $ffmpeg) -or -not (Test-Path $ffprobe)) {
  Write-Step 'Downloading ffmpeg (Gyan.dev essentials build)'
  $tmp = Join-Path $env:TEMP "pcc-ffmpeg.zip"
  Download-File 'https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip' $tmp
  $extracted = Join-Path $env:TEMP 'pcc-ffmpeg-extract'
  if (Test-Path $extracted) { Remove-Item -Recurse -Force $extracted }
  Expand-Archive -Path $tmp -DestinationPath $extracted -Force
  $foundFfmpeg  = Get-ChildItem -Path $extracted -Recurse -Filter ffmpeg.exe  | Select-Object -First 1
  $foundFfprobe = Get-ChildItem -Path $extracted -Recurse -Filter ffprobe.exe | Select-Object -First 1
  if (-not $foundFfmpeg)  { throw "Couldn't find ffmpeg.exe inside the downloaded zip." }
  if (-not $foundFfprobe) { throw "Couldn't find ffprobe.exe inside the downloaded zip." }
  Copy-Item -Path $foundFfmpeg.FullName  -Destination $ffmpeg  -Force
  Copy-Item -Path $foundFfprobe.FullName -Destination $ffprobe -Force
  Remove-Item -Recurse -Force $extracted
  Remove-Item -Force $tmp
  Write-Ok "ffmpeg + ffprobe in $BinDir"
} else {
  Write-Ok 'ffmpeg + ffprobe already present, skipping download'
}

if (-not (Test-Path $ytdlp)) {
  Write-Step 'Downloading yt-dlp.exe'
  Download-File 'https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp.exe' $ytdlp
  Write-Ok "yt-dlp in $BinDir"
} else {
  Write-Ok 'yt-dlp already present, skipping download'
}

# 5. Optional: migrate Docker data
$dockerData = Join-Path $SrcDir 'data'
if ((Test-Path $dockerData) -and (-not (Test-Path (Join-Path $DataDir 'pcc.db')))) {
  Write-Step "Found existing data/ at $dockerData"
  $choice = Read-Host "Migrate Docker data (DBs, fillers) to $DataDir? [Y/n]"
  if ($choice -eq '' -or $choice -match '^[Yy]') {
    Copy-Item -Path "$dockerData\*" -Destination $DataDir -Recurse -Force
    Write-Ok "Migrated existing data"
  } else {
    Write-Warn "Skipped migration - service will start with a fresh DB."
  }
}

# 6. npm install
Write-Step "Installing Node dependencies (this can take a couple of minutes)"
Push-Location $InstallDir
try {
  & npm install --omit=dev --no-audit --no-fund
  if ($LASTEXITCODE -ne 0) { throw "npm install failed (exit $LASTEXITCODE)" }
  Write-Ok 'Dependencies installed'
} finally { Pop-Location }

# 7. Service registration
Write-Step 'Registering Windows Service'
Push-Location $InstallDir
try {
  $env:PCC_DATA_DIR = $DataDir
  $env:PCC_BIN_DIR  = $BinDir
  & node "windows\service-installer.js"
  if ($LASTEXITCODE -ne 0) { throw "service installer exited $LASTEXITCODE" }
} finally { Pop-Location }

Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "  Plex Command Center installed successfully!"   -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  URL      : http://localhost:3001"
Write-Host "  Install  : $InstallDir"
Write-Host "  Data dir : $DataDir"
Write-Host "  Bin dir  : $BinDir"
Write-Host ""
Write-Host "Manage the service from services.msc (name: PlexCommandCenter)"
Write-Host "First login: admin / admin (you'll be forced to change it)"
Write-Host ""
