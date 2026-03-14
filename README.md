# Plex Command Center

![Version](https://img.shields.io/badge/version-2.5.2--livetv-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-beta-yellow)

**Advanced Plex Media Server monitoring, control dashboard, and Virtual Linear TV**

[Features](#-features) • [What's New in v2](#-whats-new-in-v2) • [Installation](#-installation) • [Live TV Setup](#-virtual-linear-tv) • [Desktop App](#-desktop-app) • [Configuration](#-configuration) • [Screenshots](#-screenshots) • [Roadmap](#-roadmap)

> **⚠️ Development Status**
> This project is currently in **BETA (v2.5.2 + Live TV)**. While fully functional, some features are still being refined. We welcome bug reports and feature requests!

---

## 📋 Overview

Plex Command Center is a comprehensive web-based dashboard for monitoring and controlling your Plex Media Server. It provides real-time insights into your server's performance, active streams, user activity, media requests, system health, and now includes a **Virtual Linear TV** system that turns your Plex libraries into always-on TV channels.

### Key Capabilities

- **Real-time Monitoring**: Live CPU, memory, network, and disk usage from your actual Plex server (via Zabbix integration)
- **Stream Management**: View and control active streams with detailed playback information
- **User Analytics**: Track top users, watch history, and viewing patterns via Tautulli
- **Media Requests**: Manage Jellyseerr requests with approval/decline capabilities
- **Collection Management**: Create and manage Plex collections by genre, year, or actor
- **System Health**: Monitor server status, library counts, uptime, and disk usage
- **Virtual Linear TV** *(NEW in v2)*: Create virtual TV channels from your Plex libraries with EPG, fillers, schedule rules, and a dedicated desktop player app

---

## 🆕 What's New in v2

### Virtual Linear TV System
Transform your Plex library into a traditional TV experience with always-on channels.

- **Virtual Channels**: Create channels from any Plex library — by genre, actor, year, or entire libraries
- **Virtual Clock Engine**: Deterministic scheduling using modular arithmetic — every viewer sees the same thing at the same time, no server-side state needed
- **Zero-CPU Streaming**: 302 redirect to Plex direct play URLs means no transcoding overhead on the server
- **Auto-Build Playlists**: Automatically populate channels with content from your libraries, with smart filtering
- **Filler System**: Insert trailers, bumpers, or short clips between programs — auto-scan your Plex libraries for trailers
- **Schedule Rules**:
  - **Time Block (Broadcast Schedule)**: Set on-air hours per channel (e.g., "Cartoon channel: 6AM-9PM weekdays")
  - **Seasonal Boost**: Boost specific genres during date ranges (e.g., "Horror +30% in October")
- **TV Guide**: Full EPG grid in the web UI showing 6+ hours of programming with current time marker, respects on/off air schedule rules
- **Channel Logos**: Upload custom logos per channel, displayed as watermarks in the player with configurable position, size, and opacity
- **M3U + XMLTV**: Generate M3U playlist and XMLTV EPG for use with Plex DVR tuner, Channels DVR, or any IPTV player
- **In-Browser Player**: Watch channels directly in the web UI with channel switching (arrow keys), OSD, schedule bar, and channel list overlay
- **Desktop App** *(NEW)*: Dedicated Electron-based Windows app for a native TV viewing experience

### Desktop Player App (`plex-livetv-app/`)
A standalone Windows desktop application for watching your virtual channels:

- **Native Electron App**: Frameless window with custom title bar, system tray, always-on-top mode
- **Channel Sidebar**: Browse channels with live "now playing" info, or switch to TV Guide view
- **Keyboard Shortcuts**: Arrow keys for channel switching, number keys for direct tune, M for mute, F for fullscreen, S for sidebar
- **Auto-Reconnect**: Detects stalls and connection loss, automatically reconnects
- **Channel Logo Watermark**: Displays channel logos with your configured position/opacity/size settings
- **Heartbeat System**: Keeps watch sessions alive for accurate "active viewers" tracking

### Other v2 Improvements
- **PWA Support**: Install as a Progressive Web App with manifest and service worker
- **Improved Stream Handling**: Video player auto-advances on error or stall (no more stuck loading screens)
- **Better Guide Rendering**: Larger fonts, better spacing, responsive layout in the TV guide grid

---

## ✨ Features

### Dashboard Widgets
- **Server Status** - Real-time server status with clickable details (IP addresses, library count, uptime)
- **Active Streams** - Live view of current viewers with playback progress and quality
- **System Resources** - CPU, RAM, network I/O with toggle between Plex server (Zabbix) and Docker container metrics
- **Disk Usage** - All drives with usage percentages, automatic alerts for added/removed disks
- **Top Users** - Most active users with play counts and watch time
- **Recent Requests** - Jellyseerr media requests with approve/decline actions
- **Collections** - Visual collection browser with poster art

### Dedicated Tabs
- **Active Streams** - Detailed stream information with ability to stop streams
- **Top Users** - Complete user statistics with clickable details
- **Watch History** - Filterable history with date range, user, and search
- **System** - Server information, library details, disk usage
- **Tools** - Utilities including unwatched report generator
- **Live TV** *(NEW)* - Full virtual linear TV management with sub-views:
  - **Now Playing** - What's currently airing on each channel
  - **TV Guide** - EPG grid with 6-hour view, off-air blocks, and click-to-watch
  - **Channels** - Create, edit, configure channels with filters and logo upload
  - **Fillers** - Manage trailer/bumper content, auto-scan Plex libraries
  - **Setup** - M3U/XMLTV URLs, auto-build tools, session management

### Integrations
- **Plex Media Server** - Direct API integration for core functionality
- **Tautulli** - Advanced statistics and watch history
- **Jellyseerr** - Media request management with TMDB search
- **Zabbix** (Optional) - Real-time Windows server metrics (CPU, RAM, disk, network)

---

## 🚀 Installation

### Prerequisites
- Docker & Docker Compose
- Plex Media Server with API token
- Tautulli instance with API key
- Jellyseerr instance with API key
- (Optional) Zabbix server for Windows Plex server metrics

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/plex-command-center.git
   cd plex-command-center
   ```

2. **Configure environment variables**
   ```bash
   cp docker-compose.yml.example docker-compose.yml
   nano docker-compose.yml
   ```

   Edit the following **required** variables:
   ```yaml
   - PLEX_URL=http://YOUR_PLEX_IP:32400
   - PLEX_TOKEN=YOUR_PLEX_TOKEN
   - TAUTULLI_URL=http://YOUR_TAUTULLI_IP:8181
   - TAUTULLI_API_KEY=YOUR_TAUTULLI_KEY
   - JELLYSEERR_URL=https://your-jellyseerr-domain.com  # NO trailing slash!
   - JELLYSEERR_API_KEY=YOUR_JELLYSEERR_KEY
   ```

   Optional Zabbix integration (for real Plex server metrics):
   ```yaml
   - ZABBIX_URL=http://YOUR_ZABBIX_IP/zabbix
   - ZABBIX_USER=Admin
   - ZABBIX_PASSWORD=YOUR_PASSWORD
   - ZABBIX_HOST_ID=YOUR_PLEX_HOST_ID
   ```

3. **Build and start**
   ```bash
   docker-compose build
   docker-compose up -d
   ```

4. **Access the dashboard**
   ```
   http://YOUR_SERVER_IP:3001
   ```

---

## 📺 Virtual Linear TV

### Quick Setup

1. Navigate to the **Live TV** tab in the web UI
2. Go to **Setup** sub-view to see your M3U and XMLTV URLs
3. Go to **Channels** and click **+ New Channel**
4. Select a library source, set channel number and name
5. Click **Build Playlist** to populate the channel with content
6. (Optional) Upload a channel logo, add fillers, configure schedule rules
7. Watch directly in the browser or use the M3U URL with any IPTV player

### Schedule Rules

**Broadcast Schedule (Time Block)**:
Set specific hours when a channel is on-air. Outside these hours, the channel shows "Off Air" in the TV guide and won't stream.
- Example: Kids channel on 6:00-21:00 weekdays only

**Seasonal Boost**:
Increase the percentage of a specific genre during a date range.
- Example: Boost Horror by 30% during October (months 10-10)

### M3U/XMLTV for Plex DVR

You can add your virtual channels as a tuner in Plex:
1. In Plex, go to Settings > Live TV & DVR
2. Add tuner with M3U URL: `http://YOUR_SERVER_IP:3001/api/livetv/m3u`
3. Add EPG with XMLTV URL: `http://YOUR_SERVER_IP:3001/api/livetv/xmltv`

### Environment Variables for Live TV

| Variable | Default | Description |
|---|---|---|
| `LIVETV_ENABLED` | `true` | Enable/disable the Live TV feature |
| `LIVETV_BASE_URL` | auto-detected | Base URL for M3U/XMLTV (set if behind reverse proxy) |
| `LIVETV_GUIDE_HOURS` | `48` | Hours of EPG data to generate |
| `LIVETV_FILLER_INTERVAL` | `3` | Insert a filler every N programs |

---

## 🖥️ Desktop App

The `plex-livetv-app/` folder contains a standalone Electron desktop app for Windows.

### Building from Source

```bash
cd plex-livetv-app
npm install
npm start          # Run in development
npm run build      # Build Windows executable
```

### Using Pre-built

If you have a pre-built version, just replace `resources/app/renderer/index.html` to update the UI without rebuilding.

### First Launch
1. Launch the app
2. Enter your Plex Command Center server URL (e.g., `http://192.168.1.100:3001`)
3. Click Connect — channels load automatically
4. Click any channel or use arrow keys to start watching

### Keyboard Shortcuts

| Key | Action |
|---|---|
| `↑` / `↓` | Previous / Next channel |
| `←` / `→` | Volume down / up |
| `0-9` | Direct channel number entry |
| `M` | Toggle mute |
| `F` | Toggle fullscreen |
| `S` | Toggle sidebar |
| `G` | Toggle Guide / Channels view |
| `Esc` | Exit fullscreen |

---

## 🔧 Configuration

### Getting Your API Keys

<details>
<summary><strong>Plex Token</strong></summary>

1. Log into Plex Web App
2. Play any media item
3. Click the (i) info button → View XML
4. Look for `X-Plex-Token=XXXXX` in the URL
5. Copy the token value
</details>

<details>
<summary><strong>Tautulli API Key</strong></summary>

1. Tautulli → Settings → Web Interface
2. Scroll to "API" section
3. Copy the API Key
</details>

<details>
<summary><strong>Jellyseerr API Key</strong></summary>

1. Jellyseerr → Settings → General
2. Scroll to "API Key"
3. Click "Generate" if not present
4. Copy the API Key
</details>

<details>
<summary><strong>Zabbix Host ID (Optional)</strong></summary>

1. Log into Zabbix web interface
2. Configuration → Hosts
3. Click on your Plex server host
4. Look at the URL: `hostid=XXXXX`
5. Copy the host ID number
</details>

### Environment Variables

| Variable | Required | Description | Example |
|---|---|---|---|
| `PLEX_URL` | Yes | Plex server URL | `http://192.168.1.100:32400` |
| `PLEX_TOKEN` | Yes | Plex API token | `abc123xyz...` |
| `TAUTULLI_URL` | Yes | Tautulli URL | `http://192.168.1.100:8181` |
| `TAUTULLI_API_KEY` | Yes | Tautulli API key | `xyz789abc...` |
| `JELLYSEERR_URL` | Yes | Jellyseerr URL (no trailing slash!) | `https://jellyseerr.domain.com` |
| `JELLYSEERR_API_KEY` | Yes | Jellyseerr API key | `MTc1OTg2...` |
| `ZABBIX_URL` | No | Zabbix server URL | `http://192.168.1.50/zabbix` |
| `ZABBIX_USER` | No | Zabbix username | `Admin` |
| `ZABBIX_PASSWORD` | No | Zabbix password | `yourpassword` |
| `ZABBIX_HOST_ID` | No | Zabbix host ID for Plex server | `10662` |
| `TAILSCALE_IP` | No | Tailscale IP (display only) | `100.99.196.121` |
| `TZ` | No | Timezone | `America/New_York` |
| `PORT` | No | Application port | `3001` |
| `LIVETV_ENABLED` | No | Enable Virtual Linear TV | `true` |
| `LIVETV_BASE_URL` | No | Base URL for M3U/XMLTV generation | `http://myserver:3001` |
| `LIVETV_GUIDE_HOURS` | No | Hours of EPG data | `48` |
| `LIVETV_FILLER_INTERVAL` | No | Programs between fillers | `3` |

---

## 📸 Screenshots

*(Add screenshots here)*

- Dashboard overview
- Active streams view
- Top users analytics
- Watch history filters
- System resources widget
- Jellyseerr search & request
- Live TV guide grid
- Live TV in-browser player
- Desktop app player

---

## 🏗️ Architecture

### Tech Stack

**Backend:**
- Node.js 18
- Express.js
- Axios for API calls
- better-sqlite3 for Live TV data (channels, playlists, fillers, schedule rules)
- systeminformation for container metrics
- ffmpeg for MPEG-TS remuxing (Live TV stream fallback)

**Frontend:**
- React 18 (no build step — uses Babel standalone)
- Single-page application
- Auto-refresh every 10 seconds
- LocalStorage for widget preferences
- PWA support (manifest + service worker)

**Desktop App:**
- Electron
- mpegts.js for MPEG-TS fallback playback
- Native HTML5 video for Plex direct play / transcode

**Deployment:**
- Docker containerized
- Alpine Linux base image
- Health check endpoint
- SQLite database persisted via volume mount

### File Structure

```
plex-command-center/
├── backend-server-v2.5.2-final.js   # Express API server (~4000 lines)
├── plex-command-center-v2.5.2-final.html  # React frontend (single file)
├── package-v2.5.2.json              # Node dependencies
├── Dockerfile-v2.5.2                # Container build instructions
├── docker-compose.yml.example       # Orchestration config template
├── manifest.json                    # PWA manifest
├── sw.js                            # Service worker
├── .gitignore
├── LICENSE
├── README.md
├── data/                            # SQLite DB (persisted via volume)
├── logs/                            # Application logs
└── plex-livetv-app/                 # Desktop Electron app
    ├── main.js                      # Electron main process
    ├── preload.js                   # Context bridge
    ├── package.json                 # Electron dependencies
    ├── generate-icon.js             # Icon generator
    ├── icon.png                     # App icon
    └── renderer/
        └── index.html               # Desktop app UI
```

### API Endpoints

**Plex:**
- `GET /api/plex/status` - Server status and details
- `GET /api/plex/sessions` - Active streams
- `POST /api/plex/sessions/:id/stop` - Stop a stream
- `GET /api/plex/collections` - Get collections
- `POST /api/plex/collections/create` - Create collection
- `DELETE /api/plex/collections/:key` - Delete collection

**Tautulli:**
- `GET /api/tautulli/history` - Watch history with filters
- `GET /api/tautulli/user-stats` - Top users statistics
- `GET /api/tautulli/users` - User list

**Jellyseerr:**
- `GET /api/jellyseerr/requests` - Media requests
- `GET /api/jellyseerr/search` - Search TMDB
- `POST /api/jellyseerr/request` - Request media
- `POST /api/jellyseerr/request/:id/approve` - Approve request
- `POST /api/jellyseerr/request/:id/decline` - Decline request

**Live TV:**
- `GET /api/livetv/channels` - List channels
- `POST /api/livetv/channels` - Create channel
- `PUT /api/livetv/channels/:id` - Update channel
- `DELETE /api/livetv/channels/:id` - Delete channel
- `POST /api/livetv/channels/:id/build` - Build channel playlist
- `GET /api/livetv/now-playing` - Current programs on all channels
- `GET /api/livetv/guide` - EPG guide data (respects schedule rules)
- `GET /api/livetv/watch/:channelId` - Get stream URL for viewing
- `GET /api/livetv/stream/:channelId.ts` - MPEG-TS continuous stream
- `GET /api/livetv/m3u` - M3U playlist for IPTV players
- `GET /api/livetv/xmltv` - XMLTV EPG for IPTV players
- `POST /api/livetv/channels/:id/rules` - Add schedule rule
- `GET /api/livetv/fillers` - List fillers
- `POST /api/livetv/fillers` - Add filler
- `POST /api/livetv/fillers/scan-trailers` - Auto-scan Plex for trailers
- `GET /api/livetv/logos/:channelId` - Get channel logo
- `GET /api/livetv/logo-settings` - Get logo display settings

**System:**
- `GET /api/plex/resources` - Zabbix metrics (if configured)
- `GET /api/docker/resources` - Container metrics
- `GET /api/health` - Health check

---

## 🗺️ Roadmap

### Current Version (v2.5.2 + Live TV)
- [x] Real-time monitoring dashboard
- [x] Zabbix integration for Windows server metrics
- [x] Jellyseerr request management
- [x] Collection creation and management
- [x] Watch history with filters
- [x] Disk change detection and alerts
- [x] Virtual Linear TV with channels, playlists, and EPG
- [x] Filler system with auto-scan trailers
- [x] Schedule rules (time block + seasonal boost)
- [x] TV Guide with on/off air support
- [x] Channel logos with configurable watermark
- [x] In-browser video player with OSD
- [x] Desktop Electron app for Windows
- [x] M3U + XMLTV for Plex DVR integration
- [x] PWA support

### Planned Features (v3.0)
- [ ] User authentication and multi-user support
- [ ] Configurable alerts and notifications (email/webhook)
- [ ] Historical data graphs and trends
- [ ] Mobile-responsive improvements
- [ ] Dark/light theme toggle
- [ ] Export reports (PDF/CSV)
- [ ] macOS / Linux desktop app builds
- [ ] Channel categories and favorites
- [ ] DVR recording from virtual channels
- [ ] Plugin system for extensibility

### Known Issues
- Jellyseerr delete only works on pending requests (API limitation)
- Plex server metrics require Zabbix (no built-in Plex API for system stats)
- Some Zabbix templates may use different item keys (may need customization)
- Desktop app currently Windows-only (Electron supports cross-platform — builds for macOS/Linux coming)

---

## 🤝 Contributing

We welcome contributions! This project is actively being developed.

### How to Contribute
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
# Clone your fork
git clone https://github.com/yourusername/plex-command-center.git
cd plex-command-center

# Install dependencies
npm install

# Run locally (development)
node backend-server-v2.5.2-final.js

# Access at http://localhost:3001
```

---

## 🐛 Troubleshooting

<details>
<summary><strong>Container won't start</strong></summary>

- Check Docker logs: `docker-compose logs -f`
- Verify all required environment variables are set
- Ensure ports aren't already in use
</details>

<details>
<summary><strong>Zabbix metrics showing zeros</strong></summary>

- Verify Zabbix URL is accessible from container
- Check host ID is correct
- Ensure Zabbix user has API access
- Check Zabbix version (tested with 7.2.x)
</details>

<details>
<summary><strong>Jellyseerr requests fail with 404</strong></summary>

- Remove trailing slash from `JELLYSEERR_URL`
- Verify API key is correct
- Check Jellyseerr is accessible
</details>

<details>
<summary><strong>Live TV channels show "No programming"</strong></summary>

- Make sure you've clicked **Build Playlist** after creating a channel
- Check that the Plex library has content matching the channel's filters
- Verify `LIVETV_ENABLED=true` in environment variables
</details>

<details>
<summary><strong>Live TV player stuck on loading</strong></summary>

- The player auto-advances on error/stall (v2 fix) — wait 15 seconds
- Check that Plex is accessible from the app
- Try a different channel to rule out content-specific issues
</details>

<details>
<summary><strong>Desktop app won't connect</strong></summary>

- Ensure the server URL includes the port (e.g., `http://192.168.1.100:3001`)
- Check that LiveTV is enabled on the server
- Verify the server is reachable from your Windows machine
</details>

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Plex](https://www.plex.tv/) - For the amazing media server platform
- [Tautulli](https://tautulli.com/) - For comprehensive Plex analytics
- [Jellyseerr](https://github.com/Fallenbagel/jellyseerr) - For streamlined media requests
- [Zabbix](https://www.zabbix.com/) - For enterprise-grade monitoring
- [Electron](https://www.electronjs.org/) - For cross-platform desktop apps

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/plex-command-center/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/plex-command-center/discussions)

---

Made with ❤️ for the Plex community

**⭐ Star this repo if you find it useful!**
