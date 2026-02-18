# Changelog

All notable changes to Plex Command Center will be documented in this file.

## [2.5.2] - 2026-02-18

### Added
- ✨ **Zabbix Integration** - Real-time Windows server metrics (CPU, RAM, disk, network)
- 💾 **Disk Monitoring** - Automatic detection of added/removed disks with alerts
- 📊 **Docker Directory Sizes** - Shows actual directory sizes instead of mount points
- 🔍 **Jellyseerr Search** - Full TMDB search with poster display
- 📚 **Collection Creator** - Create collections by genre, year, or actor
- 👥 **Enhanced User Details** - Clickable user cards with detailed statistics
- 🖥️ **Server Details Modal** - Shows IPs, library count, uptime on click
- 💿 **All Disks Display** - Shows all available disks with scrollable view

### Fixed
- ✅ Jellyseerr request titles now display correctly (fetched from TMDB endpoint)
- ✅ Tautulli user stats field mapping (plays/duration)
- ✅ Watch history filters now functional
- ✅ Jellyseerr URL handling (removed double-slash issue)
- ✅ Delete requests only shown when allowed by Jellyseerr
- ✅ Docker disk deduplication (no more 5x same disk)
- ✅ Zabbix 7.x authentication compatibility

### Changed
- 🎨 Improved collections UI with better poster layout
- 📱 System Resources widget now shows disk usage
- 🔄 Frontend auto-refresh every 10 seconds
- 📊 Progress bars color-coded (green/yellow/red)

### Technical
- Backend: Express.js with proper error handling
- Frontend: React 18 with inline Babel
- API: RESTful endpoints for all integrations
- Health check endpoint for Docker monitoring

## [2.0.0] - 2026-02-17

### Added
- Initial dashboard with widgets
- Basic Plex, Tautulli, Jellyseerr integration
- Active streams view
- Watch history tab

### Known Issues
- Zabbix metrics showing zeros (fixed in 2.5.2)
- Jellyseerr titles missing (fixed in 2.5.2)
- Top users showing 0 plays (fixed in 2.5.2)

## [1.0.0] - 2026-02-16

### Added
- Initial release
- Basic monitoring dashboard
- Docker deployment

---

## Version Format

This project follows [Semantic Versioning](https://semver.org/):
- **MAJOR** version for incompatible API changes
- **MINOR** version for new functionality (backwards compatible)
- **PATCH** version for bug fixes (backwards compatible)

## Categories

- `Added` - New features
- `Changed` - Changes to existing functionality
- `Deprecated` - Soon-to-be removed features
- `Removed` - Removed features
- `Fixed` - Bug fixes
- `Security` - Security fixes
