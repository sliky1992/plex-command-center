#Requires -Version 5.1
# Builds the Plex Command Center Windows installer (.exe).
#
# Result: a SELF-CONTAINED installer with bundled Node.js, ffmpeg, ffprobe, yt-dlp, and
# pre-built node_modules. End users do not need to install Node, ffmpeg, or anything else.
# Just download the .exe and run it.
#
# Usage (on a Windows build machine):
#   .\build-installer.ps1
#   .\build-installer.ps1 -Clean              # wipe staging + bin caches and rebuild
#   .\build-installer.ps1 -NodeVersion 20.18.0  # pin a specific Node version
#
# Prerequisites for BUILDING (not for end users):
#   - Inno Setup 6   ->   https://jrsoftware.org/isdl.php
#   - Node.js (any recent version, used only to drive the build steps)
#   - Internet access (downloads Node portable + ffmpeg + yt-dlp)

param(
  [switch]$Clean,
  [switch]$Verbose,
  [string]$NodeVersion = '20.18.0'   # LTS at time of writing
)

$ErrorActionPreference = 'Stop'

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "  + $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  ! $msg" -ForegroundColor Yellow }

$root      = $PSScriptRoot
$appRoot   = Split-Path -Parent $root
$binDir    = Join-Path $root 'bin'
$cacheDir  = Join-Path $root '.cache'
$stageDir  = Join-Path $root 'staging'
$outputDir = Join-Path $root 'output'

if ($Clean) {
  Write-Step "Cleaning previous build artifacts"
  foreach ($d in @($binDir, $stageDir, $outputDir, $cacheDir)) {
    if (Test-Path $d) { Remove-Item -Recurse -Force $d }
  }
  Write-Ok "Cleaned"
}

# Fresh staging every build - anything left over could ship stale files
if (Test-Path $stageDir) { Remove-Item -Recurse -Force $stageDir }
New-Item -ItemType Directory -Force -Path $binDir, $stageDir, $outputDir, $cacheDir | Out-Null

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Download-Cached($url, $cacheFile) {
  if (Test-Path $cacheFile) { return $cacheFile }
  $dir = Split-Path -Parent $cacheFile
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  Write-Host "    downloading $url" -ForegroundColor DarkGray
  Invoke-WebRequest -Uri $url -OutFile $cacheFile -UseBasicParsing
  return $cacheFile
}

# --- (1) Stage app files ----------------------------------------------------
Write-Step "Staging application files"
$appExcludes = @('data', 'node_modules', 'logs', '.git', 'srv.log', '*.zip', 'dist', 'windows\bin', 'windows\staging', 'windows\output', 'windows\.cache')
# Use robocopy for fast, exclude-aware copy. Exit codes 0-7 are success.
$rcArgs = @($appRoot, $stageDir, '/E', '/NFL', '/NDL', '/NJH', '/NJS', '/NP', '/MT:8',
            '/XD', (Join-Path $appRoot 'data'), (Join-Path $appRoot 'node_modules'),
                  (Join-Path $appRoot 'logs'), (Join-Path $appRoot '.git'),
                  (Join-Path $appRoot 'dist'),
                  (Join-Path $root 'bin'), (Join-Path $root 'staging'),
                  (Join-Path $root 'output'), (Join-Path $root '.cache'),
            '/XF', '*.zip', 'srv.log', '*.exe')
& robocopy @rcArgs | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed (exit $LASTEXITCODE)" }

# package.json is gitignored in this repo - the canonical tracked file is package-v2.5.2.json.
# Fresh clones don't have package.json; copy from the canonical file if it's missing.
$stagedPkg = Join-Path $stageDir 'package.json'
$canonicalPkg = Join-Path $stageDir 'package-v2.5.2.json'
if ((-not (Test-Path $stagedPkg)) -and (Test-Path $canonicalPkg)) {
  Copy-Item $canonicalPkg $stagedPkg
  Write-Ok "Derived package.json from canonical package-v2.5.2.json"
}
if (-not (Test-Path $stagedPkg)) {
  throw "No package.json or package-v2.5.2.json found in $appRoot - cannot build"
}
Write-Ok "App files staged in $stageDir"

# --- (2) Bundle portable Node.js -------------------------------------------
Write-Step "Bundling Node.js $NodeVersion (portable)"
$nodeZipName = "node-v$NodeVersion-win-x64.zip"
$nodeUrl = "https://nodejs.org/dist/v$NodeVersion/$nodeZipName"
$nodeZip = Join-Path $cacheDir $nodeZipName
Download-Cached $nodeUrl $nodeZip | Out-Null
$stageNodeDir = Join-Path $stageDir 'node'
if (Test-Path $stageNodeDir) { Remove-Item -Recurse -Force $stageNodeDir }
# Extract to a temp, then move the inner folder up so the layout is staging\node\node.exe
$nodeExtract = Join-Path $cacheDir "node-$NodeVersion-extract"
if (Test-Path $nodeExtract) { Remove-Item -Recurse -Force $nodeExtract }
Expand-Archive -Path $nodeZip -DestinationPath $nodeExtract -Force
$inner = Get-ChildItem -Path $nodeExtract -Directory | Select-Object -First 1
if (-not $inner) { throw "Node zip did not contain the expected folder" }
Move-Item -Path $inner.FullName -Destination $stageNodeDir
Remove-Item -Recurse -Force $nodeExtract
$nodeExe = Join-Path $stageNodeDir 'node.exe'
if (-not (Test-Path $nodeExe)) { throw "node.exe missing after extraction" }
Write-Ok "Node $NodeVersion at $stageNodeDir"

# --- (3) ffmpeg + ffprobe ---------------------------------------------------
$ffmpegBundled  = Join-Path $stageDir 'bin\ffmpeg.exe'
$ffprobeBundled = Join-Path $stageDir 'bin\ffprobe.exe'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ffmpegBundled) | Out-Null
$ffmpegCached  = Join-Path $binDir 'ffmpeg.exe'
$ffprobeCached = Join-Path $binDir 'ffprobe.exe'
if ((-not (Test-Path $ffmpegCached)) -or (-not (Test-Path $ffprobeCached))) {
  Write-Step "Downloading ffmpeg (Gyan.dev essentials build)"
  $tmp = Join-Path $cacheDir 'ffmpeg.zip'
  Download-Cached 'https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip' $tmp | Out-Null
  $extracted = Join-Path $cacheDir 'ffmpeg-extract'
  if (Test-Path $extracted) { Remove-Item -Recurse -Force $extracted }
  Expand-Archive -Path $tmp -DestinationPath $extracted -Force
  $foundFf = Get-ChildItem $extracted -Recurse -Filter ffmpeg.exe  | Select-Object -First 1
  $foundFp = Get-ChildItem $extracted -Recurse -Filter ffprobe.exe | Select-Object -First 1
  if (-not $foundFf -or -not $foundFp) { throw "ffmpeg/ffprobe not in downloaded zip" }
  Copy-Item $foundFf.FullName $ffmpegCached  -Force
  Copy-Item $foundFp.FullName $ffprobeCached -Force
  Remove-Item -Recurse -Force $extracted
  Write-Ok "ffmpeg + ffprobe cached in $binDir"
}
Copy-Item $ffmpegCached  $ffmpegBundled  -Force
Copy-Item $ffprobeCached $ffprobeBundled -Force
Write-Ok "ffmpeg + ffprobe staged"

# --- (4) yt-dlp -------------------------------------------------------------
$ytdlpCached  = Join-Path $binDir 'yt-dlp.exe'
$ytdlpBundled = Join-Path $stageDir 'bin\yt-dlp.exe'
if (-not (Test-Path $ytdlpCached)) {
  Write-Step "Downloading yt-dlp"
  Invoke-WebRequest 'https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp.exe' -OutFile $ytdlpCached -UseBasicParsing
  Write-Ok "yt-dlp cached"
}
Copy-Item $ytdlpCached $ytdlpBundled -Force
Write-Ok "yt-dlp staged"

# --- (5) Install node_modules using the BUNDLED Node ------------------------
# CRITICAL: we must prepend the bundled Node dir to PATH before invoking npm. Otherwise
# npm's child processes (prebuild-install, node-gyp) pick up whatever node.exe is first on
# PATH - which on most dev boxes is a NEWER system Node. better-sqlite3 ships prebuilt
# binaries for specific Node ABI versions; if the child uses a Node version with no
# prebuild, it falls back to source-build (needs Python + VS Build Tools) and the install
# fails. With the bundled Node 20.18.0 at the front of PATH, prebuild-install finds an
# exact match and skips compilation entirely.
Write-Step "Installing node_modules with bundled Node $NodeVersion (1-2 minutes)"
$npmCli = Join-Path $stageNodeDir 'node_modules\npm\bin\npm-cli.js'
if (-not (Test-Path $npmCli)) { throw "Bundled npm not found at $npmCli" }

$savedPath = $env:PATH
$savedNpmCache = $env:npm_config_cache
$savedNpmPrefix = $env:npm_config_prefix
$env:PATH = "$stageNodeDir;$env:PATH"
# Isolate the npm cache so a corrupted user-global cache can't break the build
$env:npm_config_cache = Join-Path $cacheDir 'npm-cache'
# Clear any user-global prefix that could redirect installs away from our staging dir
$env:npm_config_prefix = $null

Push-Location $stageDir
try {
  & $nodeExe $npmCli install --omit=dev --no-audit --no-fund --no-progress
  if ($LASTEXITCODE -ne 0) { throw "npm install failed (exit $LASTEXITCODE)" }
} finally {
  Pop-Location
  $env:PATH = $savedPath
  if ($null -eq $savedNpmCache) { Remove-Item Env:\npm_config_cache -ErrorAction SilentlyContinue } else { $env:npm_config_cache = $savedNpmCache }
  if ($null -eq $savedNpmPrefix) { Remove-Item Env:\npm_config_prefix -ErrorAction SilentlyContinue } else { $env:npm_config_prefix = $savedNpmPrefix }
}
Write-Ok "node_modules built"

# --- (6) env.example.txt ----------------------------------------------------
$envFile = Join-Path $root 'env.example.txt'
if (-not (Test-Path $envFile)) {
  Write-Step "Generating env.example.txt"
@'
# Plex Command Center - environment variable template
# Most settings can be edited from the Settings tab in the UI; these are seeds at boot.

PORT=3001

# Plex
PLEX_URL=http://localhost:32400
PLEX_TOKEN=

# Tautulli / Jellyseerr / Zabbix / Bazarr / OpenSubtitles - set via UI or here
TAUTULLI_URL=
TAUTULLI_API_KEY=
JELLYSEERR_URL=
JELLYSEERR_API_KEY=
ZABBIX_URL=
ZABBIX_USER=Admin
ZABBIX_PASSWORD=
ZABBIX_HOST_ID=
BAZARR_URL=
BAZARR_API_KEY=
OPENSUBTITLES_API_KEY=
OPENSUBTITLES_USERNAME=
OPENSUBTITLES_PASSWORD=

# Set to a long random string to make stored secrets survive a DB rebuild.
# PCC_SECRETS_KEY=
'@ | Set-Content -Path $envFile -Encoding UTF8
  Write-Ok "Wrote $envFile"
}

# --- (7) Locate ISCC.exe ----------------------------------------------------
Write-Step "Locating Inno Setup compiler"
$candidates = @(
  "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
  "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
  "${env:ProgramFiles(x86)}\Inno Setup 5\ISCC.exe",
  "${env:ProgramFiles}\Inno Setup 5\ISCC.exe"
)
$iscc = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
  Write-Host ""
  Write-Host "Inno Setup is not installed." -ForegroundColor Red
  Write-Host "Download (free) from https://jrsoftware.org/isdl.php" -ForegroundColor Yellow
  exit 1
}
Write-Ok "Found $iscc"

# --- (8) Compile -----------------------------------------------------------
Write-Step "Compiling installer.iss"
$iss = Join-Path $root 'installer.iss'
$args = @($iss)
if (-not $Verbose) { $args += '/Qp' }
& $iscc @args
if ($LASTEXITCODE -ne 0) {
  Write-Host ""
  Write-Host "Installer build failed (ISCC exit $LASTEXITCODE)" -ForegroundColor Red
  exit $LASTEXITCODE
}

# --- (9) Report ------------------------------------------------------------
$built = Get-ChildItem -Path $outputDir -Filter 'PlexCommandCenter-Setup-*.exe' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "  Self-contained installer built!"                 -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
if ($built) {
  $sizeMb = [math]::Round($built.Length / 1MB, 1)
  Write-Host "  File: $($built.FullName)"
  Write-Host "  Size: $sizeMb MB"
  Write-Host ""
  Write-Host "  Bundled: Node.js $NodeVersion, ffmpeg, ffprobe, yt-dlp, pre-built node_modules."
  Write-Host "  End users need NO prerequisites - just download and run."
} else {
  Write-Warn "Couldn't locate the compiled .exe in $outputDir - check ISCC output above."
}
