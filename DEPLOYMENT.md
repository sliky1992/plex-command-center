# Deployment Guide

## Quick Start (5 Minutes)

### 1. Prerequisites Check

```bash
# Verify Docker is installed
docker --version
docker-compose --version

# Verify you have:
# ✓ Plex Media Server running
# ✓ Tautulli running  
# ✓ Jellyseerr running
# ✓ (Optional) Zabbix server
```

### 2. Get API Keys

**Plex Token:**
```
1. Open Plex Web App
2. Play any video
3. Click ⓘ → View XML
4. Copy X-Plex-Token=XXXXX from URL
```

**Tautulli API Key:**
```
Settings → Web Interface → API section → Copy API Key
```

**Jellyseerr API Key:**
```
Settings → General → API Key section → Copy
```

### 3. Deploy

```bash
# Clone repository
git clone https://github.com/yourusername/plex-command-center.git
cd plex-command-center

# Create config from example
cp docker-compose.yml.example docker-compose.yml

# Edit configuration
nano docker-compose.yml
# Add your:
# - PLEX_URL and PLEX_TOKEN
# - TAUTULLI_URL and TAUTULLI_API_KEY  
# - JELLYSEERR_URL and JELLYSEERR_API_KEY
# Save and exit (Ctrl+X, Y, Enter)

# Build and start
docker-compose up -d

# Check logs
docker-compose logs -f
```

### 4. Access Dashboard

Open browser: `http://YOUR_SERVER_IP:3001`

---

## Configuration Details

### Required Environment Variables

```yaml
PLEX_URL=http://192.168.1.100:32400
PLEX_TOKEN=abc123xyz789...

TAUTULLI_URL=http://192.168.1.100:8181
TAUTULLI_API_KEY=xyz789abc123...

JELLYSEERR_URL=https://jellyseerr.domain.com  # NO TRAILING SLASH!
JELLYSEERR_API_KEY=MTc1OTg2MjEz...
```

### Optional: Zabbix Integration

To see real Windows server metrics (CPU, RAM, disk):

```yaml
ZABBIX_URL=http://192.168.1.50/zabbix
ZABBIX_USER=Admin
ZABBIX_PASSWORD=your_password
ZABBIX_HOST_ID=10662  # Your Plex host ID in Zabbix
```

**Get Zabbix Host ID:**
1. Log into Zabbix web interface
2. Configuration → Hosts
3. Click your Plex server
4. URL shows `hostid=XXXXX` - copy that number

---

## Docker Commands

```bash
# Start containers
docker-compose up -d

# Stop containers
docker-compose down

# View logs
docker-compose logs -f

# Restart after config change
docker-compose restart

# Rebuild after code change
docker-compose build --no-cache
docker-compose up -d

# Check container status
docker-compose ps

# Update to latest version
git pull
docker-compose build --no-cache
docker-compose up -d
```

---

## Ports

- **3001** - Web dashboard (HTTP)

Ensure this port is:
- Not already in use
- Open in your firewall (if accessing remotely)
- Forwarded if needed for external access

---

## Updating

### Method 1: Docker Compose

```bash
cd plex-command-center
git pull
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Method 2: Manual File Update

```bash
# Download new files
# Replace backend-server.js and index.html

# Copy into container
docker cp backend-server.js plex-command-center:/app/
docker cp index.html plex-command-center:/app/public/

# Restart
docker restart plex-command-center
```

---

## Troubleshooting

### Container won't start

```bash
# Check logs
docker-compose logs

# Common issues:
# - Port 3001 already in use → Change PORT in docker-compose.yml
# - Missing API keys → Check environment variables
# - Permission issues → Run with sudo or fix Docker permissions
```

### Dashboard loads but no data

```bash
# Check connectivity
docker exec plex-command-center curl http://YOUR_PLEX_IP:32400

# Verify API keys
docker exec plex-command-center env | grep -E "PLEX|TAUTULLI|JELLYSEERR"

# Check backend logs
docker logs plex-command-center --tail 100
```

### Zabbix showing zeros

```bash
# Verify Zabbix connectivity
docker exec plex-command-center curl http://ZABBIX_IP/zabbix

# Check authentication
docker logs plex-command-center | grep -i zabbix

# Verify host ID is correct
# The number should match your Plex server in Zabbix
```

### Jellyseerr requests fail

```bash
# Most common: Trailing slash in URL
# WRONG: JELLYSEERR_URL=https://jellyseerr.com/
# RIGHT: JELLYSEERR_URL=https://jellyseerr.com

# Check API key is valid
# Settings → General → API Key
```

---

## Security Considerations

### Production Deployment

1. **Use HTTPS** - Put behind reverse proxy (nginx/Traefik)
2. **Restrict Access** - Use firewall rules or VPN
3. **Keep Updated** - Regularly pull latest version
4. **Secure API Keys** - Don't commit docker-compose.yml to Git
5. **Monitor Logs** - Watch for suspicious activity

### Example Nginx Reverse Proxy

```nginx
server {
    listen 443 ssl;
    server_name plex-dashboard.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Advanced Configuration

### Custom Port

```yaml
ports:
  - "8080:3001"  # Access on port 8080
```

### Persistent Data

```yaml
volumes:
  - ./data:/app/data
  - ./logs:/app/logs
```

### Custom Timezone

```yaml
environment:
  - TZ=Europe/London  # Your timezone
```

### Memory Limits

```yaml
deploy:
  resources:
    limits:
      memory: 512M
```

---

## Backup

```bash
# Backup configuration
cp docker-compose.yml docker-compose.yml.backup

# Backup data (if using volumes)
tar -czf pcc-backup-$(date +%Y%m%d).tar.gz data/ logs/
```

---

## Monitoring

### Health Check

```bash
# Check container health
docker inspect plex-command-center | grep -A 5 Health

# Manual health check
curl http://localhost:3001/api/health
```

### Resource Usage

```bash
# Check container stats
docker stats plex-command-center
```

---

## Getting Help

- **Documentation**: README.md
- **Issues**: GitHub Issues
- **Logs**: `docker-compose logs -f`

---

**Ready to deploy? Start at Step 1!** 🚀
