# Plex Command Center

<div align="center">

![Version](https://img.shields.io/badge/version-2.5.2-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-beta-yellow.svg)

**Advanced Plex Media Server monitoring and control dashboard**

[Features](#features) • [Installation](#installation) • [Configuration](#configuration) • [Screenshots](#screenshots) • [Roadmap](#roadmap)

</div>

---

## ⚠️ Development Status

**This project is currently in BETA (v2.5.2)**

While fully functional, some features are still being refined and improved. Expect occasional updates and improvements. We welcome bug reports and feature requests!

---

## 📋 Overview

Plex Command Center is a comprehensive web-based dashboard for monitoring and controlling your Plex Media Server. It provides real-time insights into your server's performance, active streams, user activity, media requests, and system health.

### Key Capabilities

- **Real-time Monitoring**: Live CPU, memory, network, and disk usage from your actual Plex server (via Zabbix integration)
- **Stream Management**: View and control active streams with detailed playback information
- **User Analytics**: Track top users, watch history, and viewing patterns via Tautulli
- **Media Requests**: Manage Jellyseerr requests with approval/decline capabilities
- **Collection Management**: Create and manage Plex collections by genre, year, or actor
- **System Health**: Monitor server status, library counts, uptime, and disk usage

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

1. **Active Streams** - Detailed stream information with ability to stop streams
2. **Top Users** - Complete user statistics with clickable details
3. **Watch History** - Filterable history with date range, user, and search
4. **System** - Server information, library details, disk usage
5. **Tools** - Utilities including unwatched report generator

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

Edit the following required variables:
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
- TAILSCALE_IP=YOUR_PLEX_TAILSCALE_IP  # Optional
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

## 🔧 Configuration

### Getting Your API Keys

#### Plex Token
1. Log into Plex Web App
2. Play any media item
3. Click the ⓘ (info) button → View XML
4. Look for `X-Plex-Token=XXXXX` in the URL
5. Copy the token value

#### Tautulli API Key
1. Tautulli → Settings → Web Interface
2. Scroll to "API" section
3. Copy the API Key

#### Jellyseerr API Key
1. Jellyseerr → Settings → General
2. Scroll to "API Key"
3. Click "Generate" if not present
4. Copy the API Key

#### Zabbix Host ID (Optional)
1. Log into Zabbix web interface
2. Configuration → Hosts
3. Click on your Plex server host
4. Look at the URL: `hostid=XXXXX`
5. Copy the host ID number

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `PLEX_URL` | ✅ | Plex server URL | `http://192.168.1.100:32400` |
| `PLEX_TOKEN` | ✅ | Plex API token | `abc123xyz...` |
| `TAUTULLI_URL` | ✅ | Tautulli URL | `http://192.168.1.100:8181` |
| `TAUTULLI_API_KEY` | ✅ | Tautulli API key | `xyz789abc...` |
| `JELLYSEERR_URL` | ✅ | Jellyseerr URL (no trailing slash!) | `https://jellyseerr.domain.com` |
| `JELLYSEERR_API_KEY` | ✅ | Jellyseerr API key | `MTc1OTg2...` |
| `ZABBIX_URL` | ⚪ | Zabbix server URL | `http://192.168.1.50/zabbix` |
| `ZABBIX_USER` | ⚪ | Zabbix username | `Admin` |
| `ZABBIX_PASSWORD` | ⚪ | Zabbix password | `yourpassword` |
| `ZABBIX_HOST_ID` | ⚪ | Zabbix host ID for Plex server | `10662` |
| `TAILSCALE_IP` | ⚪ | Tailscale IP (display only) | `100.99.196.121` |
| `TZ` | ⚪ | Timezone | `America/New_York` |
| `PORT` | ⚪ | Application port | `3001` |

---

## 📸 Screenshots

*(Add screenshots here)*

- Dashboard overview
- Active streams view
- Top users analytics
- Watch history filters
- System resources widget
- Jellyseerr search & request

---

## 🏗️ Architecture

### Tech Stack

**Backend:**
- Node.js 18
- Express.js
- Axios for API calls
- systeminformation for container metrics

**Frontend:**
- React 18 (no build step - uses Babel standalone)
- Single-page application
- Auto-refresh every 10 seconds
- LocalStorage for widget preferences

**Deployment:**
- Docker containerized
- Alpine Linux base image
- Health check endpoint

### File Structure

```
plex-command-center/
├── backend-server.js          # Express API server
├── public/
│   └── index.html             # React frontend (single file)
├── package.json               # Node dependencies
├── Dockerfile                 # Container build instructions
├── docker-compose.yml         # Orchestration config
├── README.md                  # This file
└── LICENSE                    # MIT License
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

**System:**
- `GET /api/plex/resources` - Zabbix metrics (if configured)
- `GET /api/docker/resources` - Container metrics
- `GET /api/health` - Health check

---

## 🗺️ Roadmap

### Current Version (v2.5.2)
- ✅ Real-time monitoring dashboard
- ✅ Zabbix integration for Windows server metrics
- ✅ Jellyseerr request management
- ✅ Collection creation and management
- ✅ Watch history with filters
- ✅ Disk change detection and alerts

### Planned Features (v3.0)
- [ ] User authentication and multi-user support
- [ ] Configurable alerts and notifications (email/webhook)
- [ ] Historical data graphs and trends
- [ ] Mobile-responsive improvements
- [ ] Dark/light theme toggle
- [ ] Export reports (PDF/CSV)
- [ ] Additional tools (watch history cleaner, metadata editor)
- [ ] Plugin system for extensibility

### Known Issues
- Jellyseerr delete only works on pending requests (API limitation)
- Plex server metrics require Zabbix (no built-in Plex API for system stats)
- Some Zabbix templates may use different item keys (may need customization)

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
node backend-server.js

# Access at http://localhost:3001
```

---

## 🐛 Troubleshooting

### Container won't start
- Check Docker logs: `docker-compose logs -f`
- Verify all required environment variables are set
- Ensure ports aren't already in use

### Zabbix metrics showing zeros
- Verify Zabbix URL is accessible from container
- Check host ID is correct
- Ensure Zabbix user has API access
- Check Zabbix version (tested with 7.2.x)

### Jellyseerr requests fail with 404
- Remove trailing slash from `JELLYSEERR_URL`
- Verify API key is correct
- Check Jellyseerr is accessible

### No Tautulli data
- Verify Tautulli API key
- Check Tautulli URL is accessible
- Ensure Tautulli has recorded watch history

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Plex** - For the amazing media server platform
- **Tautulli** - For comprehensive Plex analytics
- **Jellyseerr** - For streamlined media requests
- **Zabbix** - For enterprise-grade monitoring

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/plex-command-center/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/plex-command-center/discussions)

---

<div align="center">

**Made with ❤️ for the Plex community**

⭐ Star this repo if you find it useful!

</div>
