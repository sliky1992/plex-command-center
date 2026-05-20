# Plex Command Center - Windows Install

Run the app natively on Windows (e.g. on the same machine that runs Plex Media Server) as a
true Windows Service. Same feature set as the Docker build.

## For end users

Download the single installer file from the Releases page and run it:

> `PlexCommandCenter-Setup-X.Y.Z.exe`

That's it. No Node.js, no ffmpeg, no Python, no Docker - everything is bundled inside the
installer. After install, open <http://localhost:3001> (or whatever port you picked during
setup) and log in with `admin` / `admin` (you'll be forced to change the password).

The installer:

- Asks for install location (default `C:\Program Files\PlexCommandCenter\`)
- Asks for HTTP port (default `3001`)
- Optionally migrates an existing Docker `data/` folder if found next to the .exe
- Copies the bundled app + Node.js + ffmpeg + yt-dlp + pre-built `node_modules`
- Registers and starts the `PlexCommandCenter` Windows Service
- Creates Start Menu shortcuts (Open Dashboard, Restart Service, Open Data/Install Folder)
- Optionally opens the dashboard in your browser

Data lives at `%ProgramData%\PlexCommandCenter\` and is preserved across upgrades. To
uninstall, use Add/Remove Programs - you'll be asked whether to also delete the data folder.

**No prerequisites required at the target machine.** The installer is fully self-contained.

---

## Managing the service

```powershell
Get-Service PlexCommandCenter
Restart-Service PlexCommandCenter
Stop-Service    PlexCommandCenter
Start-Service   PlexCommandCenter
```

Or via **services.msc** -> "Plex Command Center".

Logs are at `%ProgramData%\PlexCommandCenter\logs\`.

---

## Upgrading

Run the new installer over the old one. Inno Setup detects the existing install via a stable
AppId GUID, the installer stops the old service cleanly before replacing files, then
re-registers the service with the new code. Your data dir is preserved.

If you want a forced clean install, uninstall first (Add/Remove Programs), then run the new
installer. The uninstaller will ask whether to keep your data - say Yes if you plan to
re-install.

---

## Migrating from Docker

1. Stop the container so its SQLite WAL is flushed.
2. Place the container's `data/` directory **next to the installer .exe**.
3. Run the installer and tick **"Migrate existing Docker data folder"** in the task list.
4. DBs are copied verbatim - users, channels, sessions, security all carry over.
5. Tokens stored in your old `.env` won't transfer automatically - re-enter them from the
   new **Settings** tab once the service is running.

---

## Building the installer (for distributors)

End users don't need this. Only relevant if you're building the .exe yourself.

### Prerequisites for BUILDING

- Windows 10/11 (or a Windows VM)
- **Inno Setup 6** (free, from <https://jrsoftware.org/isdl.php>)
- Node.js (any recent version, used only by the build script to drive `npm install`)
- Internet access (downloads Node.js portable, ffmpeg, yt-dlp the first time)

### One command

```powershell
# From plex-monitor\windows\ in any PowerShell:
.\build-installer.ps1
```

What this does:

1. Stages app files into `windows\staging\`.
2. Downloads Node.js portable for Windows (default: v20.18.0 LTS - override with
   `-NodeVersion 22.x.x`) and extracts to `staging\node\`.
3. Downloads ffmpeg/ffprobe (Gyan.dev essentials build) and yt-dlp to `bin\` + staging.
4. Runs `npm install --omit=dev` **using the bundled Node** so `better-sqlite3` and other
   native deps fetch the prebuild matching exactly the bundled Node ABI.
5. Locates `ISCC.exe` (the Inno Setup compiler).
6. Compiles `installer.iss` -> `output\PlexCommandCenter-Setup-X.Y.Z.exe`.

The first build takes 3-5 minutes (downloads + npm install). Subsequent builds reuse the
caches in `bin\` and `.cache\` - re-runs take ~30 seconds.

Options:

- `-Clean` - wipes `bin\`, `staging\`, `output\`, `.cache\` before rebuilding
- `-Verbose` - show ISCC output (otherwise quiet)
- `-NodeVersion X.Y.Z` - pin a specific Node version (use any version published at
  <https://nodejs.org/dist/>)

### Installer size

The resulting `.exe` is ~120-180 MB (LZMA2/ultra64 compresses Node + ffmpeg + node_modules
down from ~400 MB raw).

### Building on Linux/macOS

Inno Setup is Windows-only. To build the `.exe` from a Mac/Linux dev box you have two
options:

1. **GitHub Actions** - use a `windows-latest` runner with `chocolatey install innosetup`,
   then run `build-installer.ps1`. Easy to wire up; one-line YAML.
2. **Windows VM** - any VM (UTM, Parallels, VirtualBox, Hyper-V) with Inno Setup installed.

### Alternative install paths (no .exe)

If you don't want to build/distribute an installer, the same machine can also use:

- `install.ps1` (elevated PowerShell) - needs system Node.js installed
- `npm run service:install` (after `npm install`) - direct service registration

See [Alternative install paths](#alternative-install-paths) below for details.

---

## Environment variable overrides

Mostly you don't need these - the Settings tab covers everything. But they're available
for command-line / scripted setups:

| Variable          | Default                                  | Purpose                       |
|-------------------|------------------------------------------|-------------------------------|
| `PCC_DATA_DIR`    | `%ProgramData%\PlexCommandCenter`        | SQLite DBs + fillers + subs   |
| `PCC_BIN_DIR`     | `<install>\bin`                          | ffmpeg / yt-dlp location      |
| `PCC_SECRETS_KEY` | (auto-generated)                         | Encryption key for stored API tokens. Set to a long random string if you want secrets to survive a DB rebuild. |
| `PORT`            | `3001`                                   | HTTP port                     |
| `TUNER_KEY`       | (unset = LAN trust)                      | Required key for /lineup endpoints when exposed publicly |

To change after install: stop the service, edit `<install>\daemon\PlexCommandCenter.xml`
(env vars are inside `<env name=... value=... />` tags), restart.

---

## Alternative install paths

Two non-installer paths for advanced users:

### Path A: PowerShell installer

```powershell
# Requires system Node.js 18+ already installed.
# Elevated PowerShell, cd to plex-monitor\windows, then:
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1
```

Uninstall: `.\uninstall.ps1` (or `-RemoveAll` to nuke data too).

### Path B: Manual

```powershell
cd plex-monitor
npm install --omit=dev
npm run service:install    # elevated PowerShell
```

`npm run service:uninstall` to remove.

---

## Troubleshooting

- **Service starts then immediately stops** - check `%ProgramData%\PlexCommandCenter\logs\`
  for stderr from the wrapper. Most common cause is a port conflict; change `PORT` in the
  service XML and restart the service.
- **Dashboard loads but Plex calls fail** - open Settings -> Plex and verify URL + token.
  If Plex binds to a specific IP rather than 0.0.0.0, use that IP, not `localhost`.
- **Building: `ISCC.exe` not found** - install Inno Setup 6 (link above). Default install
  location is auto-detected.
- **Building: `npm install` fails on better-sqlite3** - should not happen because the
  bundled Node version (20.18.0 by default) has prebuilt binaries. If you pinned a very
  recent Node version that lacks prebuilds, install [Visual Studio Build Tools]
  (https://aka.ms/buildtools) or downgrade `-NodeVersion`.
- **Upgrade install hangs at "Stopping service"** - winsw can occasionally take 30+s to
  release locks if the service is mid-snapshot. The installer waits 2 seconds after the
  uninstall call; in rare cases this isn't enough. Re-run the installer or manually stop
  the service from services.msc first.

---

## What's actually running

The installer registers a Windows Service via [node-windows](https://github.com/coreybutler/node-windows),
which itself wraps [winsw](https://github.com/winsw/winsw). The "node.exe + your script"
pair is launched by a tiny native helper that handles SCM events, auto-restart, and crash
backoff. The `<exec>` path in the generated winsw XML points to the **bundled** node.exe
under `<install>\node\node.exe`, so a system Node install is never consulted.

No Docker, no WSL, no Cygwin.
