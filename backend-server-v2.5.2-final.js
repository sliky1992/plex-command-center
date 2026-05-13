// Plex Command Center v3.0.0
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const si = require('systeminformation');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const http = require('http');
const net = require('net');

const app = express();
const PORT = process.env.PORT || 3001;

// Trust the first reverse proxy (e.g. nginx) so req.ip and req.secure reflect the real client
app.set('trust proxy', 1);

// Lightweight security headers (no new dependency). We deliberately don't set CSP — the React-via-
// CDN frontend uses inline scripts and would break under a strict policy. These are
// defense-in-depth headers that browsers honor for HTML responses.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  next();
});

// CORS: optional comma-separated allowlist via ALLOWED_ORIGINS env. If unset, reflect the request
// origin (preserves prior behavior for LAN / desktop app usage). cookies/credentials are allowed.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: ALLOWED_ORIGINS.length
    ? (origin, cb) => cb(null, !origin || ALLOWED_ORIGINS.includes(origin))
    : true,
  credentials: true,
  allowedHeaders: ['Content-Type', 'X-PCC-Token', 'Authorization']
}));
app.use(express.json({ limit: '10mb' }));

// Tiny in-memory sliding-window rate limiter — keyed by IP. No new dependency.
function makeRateLimiter({ windowMs, max, keyFn, message }) {
  const hits = new Map();
  return (req, res, next) => {
    const key = (keyFn ? keyFn(req) : req.ip) || 'unknown';
    const now = Date.now();
    const cutoff = now - windowMs;
    const arr = (hits.get(key) || []).filter(t => t > cutoff);
    if (arr.length >= max) {
      res.set('Retry-After', String(Math.ceil(windowMs / 1000)));
      return res.status(429).json({ error: message || 'Too many requests' });
    }
    arr.push(now);
    hits.set(key, arr);
    // Opportunistic eviction so the map doesn't grow without bound
    if (hits.size > 5000) {
      for (const [k, v] of hits) {
        const filtered = v.filter(t => t > cutoff);
        if (filtered.length === 0) hits.delete(k); else hits.set(k, filtered);
      }
    }
    next();
  };
}
const loginRateLimiter = makeRateLimiter({
  windowMs: 15 * 60 * 1000, max: 8,
  message: 'Too many login attempts. Please wait a few minutes and try again.'
});

// Global request logger for debugging Plex connectivity
app.use((req, res, next) => {
  console.log(`[REQ] ${req.method} ${req.path} from ${req.ip}`);
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware MUST be mounted before any /api/* route is registered. Express applies
// middleware in registration order, so anything declared above this line is public.
// requireAuth itself is a hoisted function declaration — its body references AUTH_EXEMPT
// and friends only at request time, by which point those const tables are initialized.
app.use(requireAuth);

const config = {
  plex: { url: process.env.PLEX_URL || 'http://localhost:32400', token: process.env.PLEX_TOKEN },
  tautulli: { url: process.env.TAUTULLI_URL || 'http://localhost:8181', apiKey: process.env.TAUTULLI_API_KEY },
  jellyseerr: { url: process.env.JELLYSEERR_URL || 'http://localhost:5055', apiKey: process.env.JELLYSEERR_API_KEY },
  zabbix: { url: process.env.ZABBIX_URL || '', user: process.env.ZABBIX_USER || 'Admin', password: process.env.ZABBIX_PASSWORD || '', hostId: process.env.ZABBIX_HOST_ID || '' }
};

// ============================================
// ZABBIX INTEGRATION - Windows Plex Server Metrics
// ============================================

let zabbixAuthToken = null;
let zabbixAuthExpiry = 0;
let zabbixDisabled = false;
let zabbixDisabledReason = null;
let zabbixDisabledAt = null;

async function getZabbixToken() {
  if (zabbixDisabled) return null;
  if (zabbixAuthToken && Date.now() < zabbixAuthExpiry) return zabbixAuthToken;
  if (!config.zabbix.url || !config.zabbix.user || !config.zabbix.password) return null;

  try {
    const res = await axios.post(`${config.zabbix.url}/api_jsonrpc.php`, {
      jsonrpc: '2.0', method: 'user.login',
      params: { username: config.zabbix.user, password: config.zabbix.password },
      id: 1
    }, { timeout: 5000 });

    // Zabbix returns errors in the response body, not as HTTP errors
    if (res.data.error) {
      const errMsg = res.data.error.data || res.data.error.message || 'Unknown auth error';
      if (errMsg.toLowerCase().includes('incorrect') || errMsg.toLowerCase().includes('blocked')) {
        zabbixDisabled = true;
        zabbixDisabledReason = errMsg;
        zabbixDisabledAt = new Date().toISOString();
        zabbixAuthToken = null;
        console.error(`[ZABBIX HALTED] Authentication failed: ${errMsg}. Zabbix polling stopped to prevent account lockout. Call POST /api/zabbix/reset to re-enable after fixing credentials.`);
        return null;
      }
      console.error('Zabbix auth error:', errMsg);
      return null;
    }

    zabbixAuthToken = res.data.result;
    zabbixAuthExpiry = Date.now() + 3600000;
    console.log('Zabbix login successful, token expires in 1 hour');
    return zabbixAuthToken;
  } catch (err) {
    console.error('Zabbix auth error:', err.response?.data || err.message);
    return null;
  }
}

async function getZabbixMetrics() {
  const token = await getZabbixToken();
  if (!token) return null;

  try {
    // Fetch all items for this host
    // Zabbix 7.x: Add auth token to headers
    const res = await axios.post(
      `${config.zabbix.url}/api_jsonrpc.php`,
      {
        jsonrpc: '2.0',
        method: 'item.get',
        params: {
          hostids: config.zabbix.hostId,
          output: ['key_', 'lastvalue', 'units', 'name'],
          limit: 200
        },
        id: 2
      },
      { 
        headers: {
          'Content-Type': 'application/json-rpc',
          'Authorization': `Bearer ${token}`
        },
        timeout: 5000 
      }
    );

    const items = res.data.result || [];
    console.log('Zabbix returned', items.length, 'items');
    if (items.length > 0) {
      console.log('Sample item:', JSON.stringify(items[0]));
      console.log('CPU item:', items.find(i => i.key_ === 'system.cpu.util'));
      console.log('Memory item:', items.find(i => i.key_ === 'vm.memory.util'));
    } else {
      console.log('Zabbix response:', JSON.stringify(res.data).substring(0, 500));
    }
    const get = (key) => items.find(i => i.key_ === key || i.key_.startsWith(key))?.lastvalue;

    // Extract disk info from vfs.fs.dependent items
    const disks = items
      .filter(i => i.key_.includes('vfs.fs.dependent') && i.key_.includes(',pused]'))
      .map(i => {
        const match = i.key_.match(/\[(.+?),pused\]/);
        const drive = match ? match[1] : i.key_;
        return {
          name: drive,
          percentage: parseFloat(i.lastvalue || 0).toFixed(1),
          label: i.name || drive
        };
      });

    // Get network traffic (sum of all interfaces)
    const netIn = items.filter(i => i.key_.includes('net.if.in[') && !i.key_.includes('dropped') && !i.key_.includes('errors'));
    const netOut = items.filter(i => i.key_.includes('net.if.out[') && !i.key_.includes('dropped') && !i.key_.includes('errors'));
    
    const rxTotal = netIn.reduce((sum, i) => sum + (parseFloat(i.lastvalue) || 0), 0);
    const txTotal = netOut.reduce((sum, i) => sum + (parseFloat(i.lastvalue) || 0), 0);

    const changes = checkDiskChanges(disks);
    
    return {
      source: 'zabbix',
      available: true,
      cpu: parseFloat(get('system.cpu.util') || 0).toFixed(1),
      memory: parseFloat(get('vm.memory.util') || 0).toFixed(1),
      network: {
        rx: Math.round(rxTotal / 1024), // bytes to KB/s
        tx: Math.round(txTotal / 1024)
      },
      uptime: parseInt(get('system.uptime') || 0),
      hostname: get('system.hostname') || get('agent.hostname') || 'Unknown',
      os: get('system.sw.os') || 'Windows Server',
      disks: disks,
      diskChanges: changes  // Include change alerts
    };
  } catch (err) {
    console.error('Zabbix metrics error:', err.message);
    console.error('Zabbix error details:', err.response?.data || err.toString());
    return null;
  }
}


// Track disk changes
let lastKnownDisks = [];

function checkDiskChanges(currentDisks) {
  if (lastKnownDisks.length === 0) {
    lastKnownDisks = currentDisks.map(d => d.name);
    return { added: [], removed: [] };
  }

  const currentNames = currentDisks.map(d => d.name);
  const added = currentNames.filter(n => !lastKnownDisks.includes(n));
  const removed = lastKnownDisks.filter(n => !currentNames.includes(n));

  if (added.length > 0 || removed.length > 0) {
    console.log('🚨 DISK CHANGES DETECTED!');
    if (added.length > 0) console.log('  ➕ Added:', added.join(', '));
    if (removed.length > 0) console.log('  ➖ Removed:', removed.join(', '));
    lastKnownDisks = currentNames;
  }

  return { added, removed };
}

// Plex Server Resources (try Zabbix first, then fallback)
app.get('/api/plex/resources', async (req, res) => {
  // Try Zabbix if configured
  if (config.zabbix.url) {
    const zabbixData = await getZabbixMetrics();
    if (zabbixData) return res.json(zabbixData);
  }

  // Fallback: indicate not available
  const response = {
    source: 'unavailable',
    available: false,
    cpu: 0, memory: 0,
    network: { rx: 0, tx: 0 },
  };
  if (zabbixDisabled) {
    response.message = `Zabbix polling halted: ${zabbixDisabledReason}. Fix credentials in Zabbix, then call POST /api/zabbix/reset`;
    response.zabbixDisabled = true;
    response.zabbixDisabledAt = zabbixDisabledAt;
  } else {
    response.message = 'Configure Zabbix to see Plex server metrics. Set ZABBIX_URL, ZABBIX_USER, ZABBIX_PASSWORD, ZABBIX_HOST_ID in docker-compose.yml';
  }
  res.json(response);
});

// Zabbix status & reset
app.get('/api/zabbix/status', (req, res) => {
  res.json({
    configured: !!config.zabbix.url,
    disabled: zabbixDisabled,
    reason: zabbixDisabledReason,
    disabledAt: zabbixDisabledAt,
    hasToken: !!zabbixAuthToken,
    tokenExpiry: zabbixAuthExpiry ? new Date(zabbixAuthExpiry).toISOString() : null
  });
});

app.post('/api/zabbix/reset', async (req, res) => {
  const wasDisabled = zabbixDisabled;
  zabbixDisabled = false;
  zabbixDisabledReason = null;
  zabbixDisabledAt = null;
  zabbixAuthToken = null;
  zabbixAuthExpiry = 0;
  console.log('[ZABBIX] Manual reset triggered — re-enabling Zabbix polling');

  // Attempt a test login immediately
  const token = await getZabbixToken();
  if (token) {
    res.json({ success: true, message: 'Zabbix re-enabled and login successful' });
  } else if (zabbixDisabled) {
    res.json({ success: false, message: `Login failed again: ${zabbixDisabledReason}. Zabbix remains halted.` });
  } else {
    res.json({ success: false, message: 'Login failed (network/timeout), will retry on next request' });
  }
});

// Docker container metrics
let dockerHistory = [];
setInterval(async () => {
  try {
    const [cpu, mem, net] = await Promise.all([si.currentLoad(), si.mem(), si.networkStats()]);
    dockerHistory.push({
      timestamp: Date.now(),
      cpu: Math.round(cpu.currentLoad * 10) / 10,
      memory: Math.round(((mem.total - mem.available) / mem.total) * 1000) / 10,
      network: { rx: Math.round((net[0]?.rx_sec || 0) / 1024), tx: Math.round((net[0]?.tx_sec || 0) / 1024) }
    });
    if (dockerHistory.length > 720) dockerHistory.shift();
  } catch (e) {}
}, 5000);

app.get('/api/docker/resources', async (req, res) => {
  try {
    const [cpu, mem, disks, net] = await Promise.all([si.currentLoad(), si.mem(), si.fsSize(), si.networkStats()]);
    
    // Get actual directory sizes using du command (async, parallel)
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execPromise = promisify(exec);
    const directories = ['/app', '/app/logs', '/app/data', '/app/public', '/tmp'];
    const dirSizes = [];

    const duResults = await Promise.all(directories.map(async (dir) => {
      try {
        const { stdout } = await execPromise(`du -sb ${dir} 2>/dev/null | cut -f1`);
        const bytes = parseInt(stdout.toString().trim());
        if (bytes > 0) {
          return {
            name: dir,
            mount: dir,
            label: dir.replace('/app/', ''),
            total: Math.round(bytes / 1048576), // MB
            used: Math.round(bytes / 1048576),
            percentage: 0, // Will calculate based on parent
            sizeFormatted: bytes > 1073741824
              ? `${(bytes / 1073741824).toFixed(2)} GB`
              : `${(bytes / 1048576).toFixed(1)} MB`
          };
        }
        return null;
      } catch (e) {
        return null; // Directory doesn't exist or can't read
      }
    }));
    dirSizes.push(...duResults.filter(Boolean));
    
    // Add main disk info
    const mainDisk = disks.find(d => d.mount === '/');
    if (mainDisk) {
      dirSizes.unshift({
        name: 'overlay',
        mount: '/',
        label: 'Container Root',
        total: Math.round(mainDisk.size / 1073741824),
        used: Math.round(mainDisk.used / 1073741824),
        percentage: Math.round(mainDisk.use * 10) / 10,
        sizeFormatted: `${Math.round(mainDisk.used / 1073741824)} GB / ${Math.round(mainDisk.size / 1073741824)} GB`
      });
    }
    
    res.json({
      source: 'docker-container', available: true,
      cpu: Math.round(cpu.currentLoad * 10) / 10,
      memory: Math.round(((mem.total - mem.available) / mem.total) * 1000) / 10,
      disks: dirSizes,
      network: { rx: Math.round((net[0]?.rx_sec || 0) / 1024), tx: Math.round((net[0]?.tx_sec || 0) / 1024) }
    });
  } catch (error) {
    res.status(500).json({ error: error.message, available: false });
  }
});

// ============================================
// PLEX API ENDPOINTS
// ============================================

// Full server status with name, IPs, libraries, uptime
app.get('/api/plex/status', async (req, res) => {
  try {
    const response = await axios.get(`${config.plex.url}/`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { 'Accept': 'application/json' },
      timeout: 5000
    });

    const mc = response.data.MediaContainer;

    // Get library count
    let libraries = [];
    try {
      const libRes = await axios.get(`${config.plex.url}/library/sections`, {
        params: { 'X-Plex-Token': config.plex.token },
        headers: { 'Accept': 'application/json' },
        timeout: 5000
      });
      libraries = libRes.data.MediaContainer.Directory || [];
    } catch (e) {}

    // Fetch item counts for each library in parallel
    const libCounts = await Promise.allSettled(
      libraries.map(lib => axios.get(`${config.plex.url}/library/sections/${lib.key}/all`, {
        params: { 'X-Plex-Token': config.plex.token, 'X-Plex-Container-Size': 0, 'X-Plex-Container-Start': 0 },
        headers: { 'Accept': 'application/json' }, timeout: 5000
      }))
    );
    const countMap = {};
    libCounts.forEach((r, i) => {
      if (r.status === 'fulfilled') {
        countMap[libraries[i].key] = r.value.data.MediaContainer.totalSize || r.value.data.MediaContainer.size || 0;
      }
    });

    // Determine local IP: env override > Plex-reported LAN address > PLEX_URL hostname
    let localIP = process.env.LOCAL_IP;
    if (!localIP) {
      // Plex reports its LAN address in the root response
      const plexLocalAddr = mc.publicAddress ? null : null; // publicAddress is WAN
      // Try Plex preferences/resources for LAN IP
      try {
        const resRes = await axios.get('https://plex.tv/api/v2/resources?includeHttps=1', {
          headers: { 'Accept': 'application/json', 'X-Plex-Token': config.plex.token },
          timeout: 5000
        });
        const server = resRes.data.find(r => r.provides === 'server');
        if (server) {
          const lanConn = server.connections.find(c => !c.relay && c.local);
          if (lanConn) {
            localIP = new URL(lanConn.uri).hostname;
          }
        }
      } catch (e) {}
    }
    if (!localIP) {
      localIP = new URL(config.plex.url).hostname;
    }

    res.json({
      online: true,
      friendlyName: mc.friendlyName || 'Plex Media Server',
      version: mc.version,
      platform: mc.platform,
      platformVersion: mc.platformVersion,
      localIP: localIP,
      tailscaleIP: process.env.TAILSCALE_IP || new URL(config.plex.url).hostname,
      libraryCount: libraries.length,
      libraries: libraries.map(l => ({ key: l.key, title: l.title, type: l.type, count: countMap[l.key] || l.count || 0 })),
      startedAt: mc.startedAt ? new Date(mc.startedAt * 1000).toISOString() : null,
      updatedAt: mc.updatedAt
    });
  } catch (error) {
    res.json({ online: false, error: error.message });
  }
});

// Sessions with real client IPs
app.get('/api/plex/sessions', async (req, res) => {
  try {
    const response = await axios.get(`${config.plex.url}/status/sessions`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { 'Accept': 'application/json' },
      timeout: 5000
    });

    const sessions = response.data.MediaContainer.Metadata || [];
    res.json(sessions.map(s => ({
      sessionId: s.Session?.id || s.sessionKey,
      user: s.User?.title || 'Unknown',
      userThumb: s.User?.thumb || '',
      content: s.type === 'episode' ? `${s.grandparentTitle} - ${s.title}` : s.title,
      contentType: s.type === 'movie' ? 'Movie' : 'TV Show',
      thumb: s.thumb || s.grandparentThumb || '',
      year: s.year || '',
      progress: s.viewOffset && s.duration ? Math.round((s.viewOffset / s.duration) * 100) : 0,
      duration: s.duration || 0, viewOffset: s.viewOffset || 0,
      quality: s.Media?.[0]?.videoResolution || 'SD',
      transcoding: !!s.TranscodeSession,
      bandwidth: Math.round((s.Session?.bandwidth || 0) / 1024),
      player: s.Player?.product || 'Unknown',
      device: s.Player?.device || s.Player?.product || 'Unknown',
      platform: s.Player?.platform || 'Unknown',
      ip: s.Player?.remotePublicAddress || s.Player?.address || s.Session?.address || 'Unknown',
      state: s.Player?.state || 'playing'
    })));
  } catch (error) {
    console.error('Sessions error:', error.message);
    res.json([]);
  }
});

// Stop stream
app.post('/api/plex/sessions/:sessionId/stop', async (req, res) => {
  try {
    await axios.get(`${config.plex.url}/status/sessions/terminate`, {
      params: { sessionId: req.params.sessionId, reason: 'Stopped by administrator', 'X-Plex-Token': config.plex.token },
      timeout: 5000
    });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Libraries
app.get('/api/plex/libraries', async (req, res) => {
  try {
    const response = await axios.get(`${config.plex.url}/library/sections`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { 'Accept': 'application/json' },
      timeout: 5000
    });
    res.json((response.data.MediaContainer.Directory || []).map(l => ({
      key: l.key, title: l.title, type: l.type, count: l.count
    })));
  } catch (error) {
    res.json([]);
  }
});

// Browse library items with pagination and search
app.get('/api/plex/libraries/:key/items', async (req, res) => {
  try {
    const { key } = req.params;
    const start = parseInt(req.query.start) || 0;
    const size = Math.min(parseInt(req.query.size) || 50, 100);
    const sort = req.query.sort || 'titleSort';
    const search = req.query.search || '';

    const params = {
      'X-Plex-Token': config.plex.token,
      'X-Plex-Container-Start': start,
      'X-Plex-Container-Size': size,
      sort
    };
    if (search) params.title = search;

    const response = await axios.get(`${config.plex.url}/library/sections/${key}/all`, {
      params,
      headers: { 'Accept': 'application/json' },
      timeout: 15000
    });

    const mc = response.data.MediaContainer;
    const items = (mc.Metadata || []).map(item => ({
      ratingKey: item.ratingKey,
      title: item.title,
      type: item.type,
      year: item.year || '',
      summary: item.summary || '',
      rating: item.audienceRating || item.rating || '',
      contentRating: item.contentRating || '',
      duration: item.duration ? Math.round(item.duration / 60000) : 0,
      addedAt: item.addedAt ? new Date(item.addedAt * 1000).toISOString().split('T')[0] : '',
      viewCount: item.viewCount || 0,
      lastViewed: item.lastViewedAt ? new Date(item.lastViewedAt * 1000).toISOString().split('T')[0] : null,
      genres: (item.Genre || []).map(g => g.tag).slice(0, 4),
      thumb: item.thumb ? `${config.plex.url}${item.thumb}?X-Plex-Token=${config.plex.token}` : null,
      art: item.art ? `${config.plex.url}${item.art}?X-Plex-Token=${config.plex.token}` : null,
      studio: item.studio || '',
      childCount: item.childCount || 0,
      leafCount: item.leafCount || 0
    }));

    res.json({
      totalSize: mc.totalSize || mc.size || items.length,
      offset: start,
      items
    });
  } catch (error) {
    console.error('Library browse error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Collections with posters
app.get('/api/plex/collections', async (req, res) => {
  try {
    const libRes = await axios.get(`${config.plex.url}/library/sections`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { 'Accept': 'application/json' },
      timeout: 5000
    });

    // Build a set of pinned collection identifiers from managed hubs
    const pinnedSet = new Set();
    const libs = libRes.data.MediaContainer.Directory || [];
    await Promise.allSettled(libs.map(async (lib) => {
      try {
        const hubRes = await axios.get(`${config.plex.url}/hubs/sections/${lib.key}/manage`, {
          params: { 'X-Plex-Token': config.plex.token },
          headers: { 'Accept': 'application/json' },
          timeout: 5000
        });
        for (const hub of (hubRes.data.MediaContainer.Hub || [])) {
          if (hub.identifier && hub.identifier.startsWith('custom.collection.') && (hub.promotedToOwnHome || hub.promotedToRecommended || hub.promotedToSharedHome)) {
            // identifier format: custom.collection.{sectionId}.{ratingKey}
            const rk = hub.identifier.split('.').pop();
            if (rk) pinnedSet.add(rk);
          }
        }
      } catch(e) {}
    }));

    const allCollections = [];
    for (const lib of libs) {
      try {
        const colRes = await axios.get(`${config.plex.url}/library/sections/${lib.key}/collections`, {
          params: { 'X-Plex-Token': config.plex.token },
          headers: { 'Accept': 'application/json' },
          timeout: 5000
        });
        (colRes.data.MediaContainer.Metadata || []).forEach(col => {
          allCollections.push({
            key: col.ratingKey, title: col.title,
            thumb: col.thumb ? `${config.plex.url}${col.thumb}${col.thumb.includes('?') ? '&' : '?'}X-Plex-Token=${config.plex.token}` : null,
            art: col.art ? `${config.plex.url}${col.art}${col.art.includes('?') ? '&' : '?'}X-Plex-Token=${config.plex.token}` : null,
            itemCount: col.childCount || 0,
            library: lib.title, libraryKey: lib.key, summary: col.summary || '',
            pinned: pinnedSet.has(String(col.ratingKey))
          });
        });
      } catch (e) {}
    }
    res.json(allCollections);
  } catch (error) {
    res.json([]);
  }
});

// Helper: get Plex machine identifier
let plexMachineId = null;
async function getPlexMachineId() {
  if (plexMachineId) return plexMachineId;
  const rootRes = await axios.get(`${config.plex.url}/`, {
    params: { 'X-Plex-Token': config.plex.token },
    headers: { 'Accept': 'application/json' },
    timeout: 5000
  });
  plexMachineId = rootRes.data.MediaContainer.machineIdentifier;
  return plexMachineId;
}

// Helper: determine Plex type number for a library
async function getLibraryType(libraryKey) {
  const libRes = await axios.get(`${config.plex.url}/library/sections/${libraryKey}`, {
    params: { 'X-Plex-Token': config.plex.token },
    headers: { 'Accept': 'application/json' },
    timeout: 5000
  });
  const libType = libRes.data.MediaContainer.type || libRes.data.MediaContainer.viewGroup;
  return libType === 'show' ? 2 : 1; // 1=movie, 2=show
}

// Create collection by genre/year/actor
app.post('/api/plex/collections/create', async (req, res) => {
  try {
    const { libraryKey, title, type, value, summary } = req.body;

    if (!libraryKey || !title) {
      return res.status(400).json({ success: false, error: 'libraryKey and title required' });
    }

    // Step 1: Get machine identifier
    const machineId = await getPlexMachineId();

    // Step 2: Determine library type (movie=1, show=2)
    const plexType = await getLibraryType(libraryKey);

    // Step 3: Find matching items in the library
    let filterParams = {};
    if (type === 'genre') filterParams.genre = value;
    else if (type === 'year') {
      const decade = parseInt(value);
      filterParams['year>>'] = decade;
      filterParams['year<<'] = decade + 9;
    } else if (type === 'actor') filterParams.actor = value;
    else if (type === 'director') filterParams.director = value;
    else if (type === 'studio') filterParams.studio = value;

    const itemsRes = await axios.get(`${config.plex.url}/library/sections/${libraryKey}/all`, {
      params: { 'X-Plex-Token': config.plex.token, ...filterParams },
      headers: { 'Accept': 'application/json' },
      timeout: 10000
    });

    const items = itemsRes.data.MediaContainer.Metadata || [];

    if (items.length === 0) {
      return res.json({ success: false, error: `No items found for ${type}: ${value}` });
    }

    // Step 4: Create collection with first item, then add rest one by one
    const selectedItems = items.slice(0, 150);
    const firstUri = `server://${machineId}/com.plexapp.plugins.library/library/metadata/${selectedItems[0].ratingKey}`;

    const createParams = new URLSearchParams();
    createParams.append('X-Plex-Token', config.plex.token);
    createParams.append('type', String(plexType));
    createParams.append('title', title);
    createParams.append('smart', '0');
    createParams.append('sectionId', String(libraryKey));
    if (summary) createParams.append('summary', summary);
    createParams.append('uri', firstUri);

    const createRes = await axios.post(
      `${config.plex.url}/library/collections?${createParams.toString()}`,
      null,
      { headers: { 'Accept': 'application/json' }, timeout: 15000 }
    );

    // Get the new collection's ratingKey
    let colKey = createRes.data?.MediaContainer?.Metadata?.[0]?.ratingKey;
    if (!colKey) {
      // Fallback: find by title
      const colsRes = await axios.get(`${config.plex.url}/library/sections/${libraryKey}/collections`, {
        params: { 'X-Plex-Token': config.plex.token },
        headers: { 'Accept': 'application/json' }, timeout: 5000
      });
      const match = (colsRes.data.MediaContainer.Metadata || []).find(c => c.title === title);
      if (match) colKey = match.ratingKey;
    }

    // Add remaining items one by one
    if (colKey && selectedItems.length > 1) {
      for (const item of selectedItems.slice(1)) {
        try {
          const addUri = `server://${machineId}/com.plexapp.plugins.library/library/metadata/${item.ratingKey}`;
          await axios.put(
            `${config.plex.url}/library/collections/${colKey}/items?X-Plex-Token=${config.plex.token}&uri=${encodeURIComponent(addUri)}`,
            null,
            { headers: { 'Accept': 'application/json' }, timeout: 5000 }
          );
        } catch(e) {}
      }
    }

    res.json({
      success: true,
      message: `Collection "${title}" created with ${selectedItems.length} items`,
      itemCount: selectedItems.length,
      totalMatched: items.length,
      collectionKey: colKey
    });
  } catch (error) {
    console.error('Collection create error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create smart collection using filter rules
app.post('/api/plex/collections/smart', async (req, res) => {
  try {
    const { libraryKey, title, filters, summary } = req.body;

    if (!libraryKey || !title || !filters) {
      return res.status(400).json({ success: false, error: 'libraryKey, title, and filters required' });
    }

    const machineId = await getPlexMachineId();
    const plexType = await getLibraryType(libraryKey);

    // Build filter query string for the URI
    const filterParts = [`type=${plexType}`, 'push=1'];
    if (filters.genre) filterParts.push(`genre=${encodeURIComponent(filters.genre)}`);
    if (filters.year) filterParts.push(`year=${filters.year}`);
    if (filters.yearFrom) filterParts.push(`year>>=${filters.yearFrom}`);
    if (filters.yearTo) filterParts.push(`year<<=${filters.yearTo}`);
    if (filters.contentRating) filterParts.push(`contentRating=${encodeURIComponent(filters.contentRating)}`);
    if (filters.studio) filterParts.push(`studio=${encodeURIComponent(filters.studio)}`);
    if (filters.resolution) filterParts.push(`resolution=${encodeURIComponent(filters.resolution)}`);
    if (filters.unwatched) filterParts.push('unwatched=1');

    const filterUri = `server://${machineId}/com.plexapp.plugins.library/library/sections/${libraryKey}/all?${filterParts.join('&')}`;

    const params = new URLSearchParams();
    params.append('X-Plex-Token', config.plex.token);
    params.append('type', String(plexType));
    params.append('title', title);
    params.append('smart', '1');
    params.append('uri', filterUri);
    if (summary) params.append('summary', summary);

    await axios.post(
      `${config.plex.url}/library/sections/${libraryKey}/collections?${params.toString()}`,
      null,
      {
        headers: { 'Accept': 'application/json' },
        timeout: 10000
      }
    );

    res.json({
      success: true,
      message: `Smart collection "${title}" created`
    });
  } catch (error) {
    console.error('Smart collection create error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Smart Suggestion Engine - Title-based ("Because you watched X")
app.post('/api/plex/collections/suggestions', async (req, res) => {
  try {
    const suggestions = [];

    // Get libraries info
    const libRes = await axios.get(`${config.plex.url}/library/sections`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { 'Accept': 'application/json' },
      timeout: 5000
    });
    const libraries = libRes.data.MediaContainer.Directory || [];
    const movieLibs = libraries.filter(l => l.type === 'movie');
    const showLibs = libraries.filter(l => l.type === 'show');

    // --- a) Title-based suggestions from watch history ---
    if (config.tautulli.apiKey) {
      try {
        // Get recent watch history - movies and episodes
        const [movieHistRes, episodeHistRes] = await Promise.all([
          axios.get(`${config.tautulli.url}/api/v2`, {
            params: { apikey: config.tautulli.apiKey, cmd: 'get_history', length: 30, media_type: 'movie' },
            timeout: 10000
          }),
          axios.get(`${config.tautulli.url}/api/v2`, {
            params: { apikey: config.tautulli.apiKey, cmd: 'get_history', length: 30, media_type: 'episode' },
            timeout: 10000
          })
        ]);
        const movieHistory = movieHistRes.data?.response?.data?.data || [];
        const episodeHistory = episodeHistRes.data?.response?.data?.data || [];

        // Deduplicate: get unique titles (use grandparent for episodes = show title)
        const seenTitles = new Set();
        const watchedItems = [];
        for (const item of movieHistory) {
          if (!item.rating_key || seenTitles.has(item.rating_key)) continue;
          seenTitles.add(item.rating_key);
          watchedItems.push({ ratingKey: item.rating_key, title: item.title, type: 'movie' });
        }
        for (const item of episodeHistory) {
          const rk = item.grandparent_rating_key || item.rating_key;
          const title = item.grandparent_title || item.title;
          if (!rk || seenTitles.has(rk)) continue;
          seenTitles.add(rk);
          watchedItems.push({ ratingKey: rk, title, type: 'show' });
        }

        // Fetch full metadata for up to 15 recently watched titles
        const itemsToAnalyze = watchedItems.slice(0, 15);
        const metaResults = await Promise.allSettled(
          itemsToAnalyze.map(item => axios.get(`${config.plex.url}/library/metadata/${item.ratingKey}`, {
            params: { 'X-Plex-Token': config.plex.token },
            headers: { Accept: 'application/json' }, timeout: 5000
          }))
        );

        // Build rich profiles for each watched title
        const watchedProfiles = [];
        for (let i = 0; i < metaResults.length; i++) {
          const r = metaResults[i];
          if (r.status !== 'fulfilled') continue;
          const meta = r.value.data?.MediaContainer?.Metadata?.[0];
          if (!meta) continue;
          const genres = (meta.Genre || []).map(g => g.tag || g).filter(Boolean);
          const directors = (meta.Director || []).map(d => d.tag || d).filter(Boolean);
          const actors = (meta.Role || []).slice(0, 5).map(a => a.tag || a).filter(Boolean);
          const studio = meta.studio || '';
          const year = meta.year;
          const libSectionId = meta.librarySectionID;
          watchedProfiles.push({
            ...itemsToAnalyze[i],
            genres, directors, actors, studio, year, libSectionId,
            fullTitle: meta.title || itemsToAnalyze[i].title
          });
        }

        // Generate title-based suggestions
        const suggestionTitles = new Set();

        // Prefer non-anime libraries for title-based picks too. Without this, a "Project Hail Mary"
        // watch could produce a Sci-Fi collection sourced from Anime-Movies (lib 4) instead of the
        // main Movies library (lib 1) — which is exactly the "Science Fiction shows mostly anime"
        // bug the user hit.
        const isAnimeLib_t = (lib) => /anime/i.test(lib.title);
        const sortedMovieLibs_t = [...movieLibs].sort((a, b) => (isAnimeLib_t(a) ? 1 : 0) - (isAnimeLib_t(b) ? 1 : 0));
        const sortedShowLibs_t = [...showLibs].sort((a, b) => (isAnimeLib_t(a) ? 1 : 0) - (isAnimeLib_t(b) ? 1 : 0));

        for (const profile of watchedProfiles.slice(0, 8)) {
          const targetLibs = profile.type === 'movie' ? sortedMovieLibs_t : sortedShowLibs_t;

          // 1) "Because you watched X" - by director (movies only, if director exists)
          // For all three branches below, the lib loop now BREAKS on first match so we don't
          // create a duplicate suggestion per library — and since targetLibs is sorted with
          // non-anime first, the chosen lib will be the "main" one.
          if (profile.directors.length > 0 && profile.type === 'movie') {
            const director = profile.directors[0];
            const sugKey = `dir:${director}`;
            if (!suggestionTitles.has(sugKey)) {
              for (const lib of targetLibs) {
                try {
                  const dirRes = await axios.get(`${config.plex.url}/library/sections/${lib.key}/all`, {
                    params: { 'X-Plex-Token': config.plex.token, director, 'X-Plex-Container-Size': 0, 'X-Plex-Container-Start': 0 },
                    headers: { Accept: 'application/json' }, timeout: 5000
                  });
                  const count = dirRes.data.MediaContainer.totalSize || dirRes.data.MediaContainer.size || 0;
                  if (count > 2) {
                    suggestionTitles.add(sugKey);
                    suggestions.push({
                      title: `More from ${director}`,
                      type: 'personal', subtype: 'director',
                      sourceTitle: profile.fullTitle, filters: { director },
                      reason: `Because you watched "${profile.fullTitle}" — ${count} more by ${director}`,
                      libraryKey: lib.key, libraryTitle: lib.title, estimatedItems: count,
                      createType: 'director', createValue: director
                    });
                    break;
                  }
                } catch(e) {}
              }
            }
          }

          // 2) "Because you watched X" - by lead actor
          if (profile.actors.length > 0) {
            const actor = profile.actors[0];
            const sugKey = `act:${actor}`;
            if (!suggestionTitles.has(sugKey)) {
              for (const lib of targetLibs) {
                try {
                  const actRes = await axios.get(`${config.plex.url}/library/sections/${lib.key}/all`, {
                    params: { 'X-Plex-Token': config.plex.token, actor, 'X-Plex-Container-Size': 0, 'X-Plex-Container-Start': 0 },
                    headers: { Accept: 'application/json' }, timeout: 5000
                  });
                  const count = actRes.data.MediaContainer.totalSize || actRes.data.MediaContainer.size || 0;
                  if (count > 2) {
                    suggestionTitles.add(sugKey);
                    suggestions.push({
                      title: `More with ${actor}`,
                      type: 'personal', subtype: 'actor',
                      sourceTitle: profile.fullTitle, filters: { actor },
                      reason: `Because you watched "${profile.fullTitle}" — ${count} more starring ${actor}`,
                      libraryKey: lib.key, libraryTitle: lib.title, estimatedItems: count,
                      createType: 'actor', createValue: actor
                    });
                    break;
                  }
                } catch(e) {}
              }
            }
          }

          // 3) "Because you watched X" - by genre combo (use primary+secondary genre)
          if (profile.genres.length >= 2) {
            const [g1, g2] = profile.genres;
            const sugKey = `genre:${g1}+${g2}`;
            if (!suggestionTitles.has(sugKey)) {
              for (const lib of targetLibs) {
                try {
                  const genreRes = await axios.get(`${config.plex.url}/library/sections/${lib.key}/all`, {
                    params: { 'X-Plex-Token': config.plex.token, genre: g1, unwatched: 1, 'X-Plex-Container-Size': 0, 'X-Plex-Container-Start': 0 },
                    headers: { Accept: 'application/json' }, timeout: 5000
                  });
                  const count = genreRes.data.MediaContainer.totalSize || genreRes.data.MediaContainer.size || 0;
                  if (count > 3) {
                    suggestionTitles.add(sugKey);
                    suggestions.push({
                      title: `${g1} & ${g2} Mix`,
                      type: 'personal', subtype: 'genre',
                      sourceTitle: profile.fullTitle, filters: { genre: g1, secondaryGenre: g2, unwatched: true },
                      reason: `Because you watched "${profile.fullTitle}" (${g1}/${g2}) — ${count} unwatched similar titles`,
                      libraryKey: lib.key, libraryTitle: lib.title, estimatedItems: count,
                      createType: 'genre', createValue: g1, intersectGenre: g2
                    });
                    break;
                  }
                } catch(e) {}
              }
            }
          } else if (profile.genres.length === 1) {
            const genre = profile.genres[0];
            for (const lib of targetLibs) {
              try {
                const genreRes = await axios.get(`${config.plex.url}/library/sections/${lib.key}/all`, {
                  params: { 'X-Plex-Token': config.plex.token, genre, unwatched: 1, 'X-Plex-Container-Size': 0, 'X-Plex-Container-Start': 0 },
                  headers: { Accept: 'application/json' }, timeout: 5000
                });
                const count = genreRes.data.MediaContainer.totalSize || genreRes.data.MediaContainer.size || 0;
                const sugKey = `genre:${genre}:${lib.key}`;
                if (count > 3 && !suggestionTitles.has(sugKey)) {
                  suggestionTitles.add(sugKey);
                  suggestions.push({
                    title: `More ${genre}`,
                    type: 'personal',
                    subtype: 'genre',
                    sourceTitle: profile.fullTitle,
                    filters: { genre, unwatched: true },
                    reason: `Because you watched "${profile.fullTitle}" — ${count} unwatched ${genre} titles`,
                    libraryKey: lib.key,
                    libraryTitle: lib.title,
                    estimatedItems: count,
                    createType: 'genre',
                    createValue: genre
                  });
                }
              } catch(e) {}
            }
          }

          // 4) "Because you watched X" - by studio (if available)
          if (profile.studio && profile.type === 'movie') {
            for (const lib of targetLibs) {
              try {
                const studioRes = await axios.get(`${config.plex.url}/library/sections/${lib.key}/all`, {
                  params: { 'X-Plex-Token': config.plex.token, studio: profile.studio, 'X-Plex-Container-Size': 0, 'X-Plex-Container-Start': 0 },
                  headers: { Accept: 'application/json' }, timeout: 5000
                });
                const count = studioRes.data.MediaContainer.totalSize || studioRes.data.MediaContainer.size || 0;
                const sugKey = `studio:${profile.studio}:${lib.key}`;
                if (count > 3 && !suggestionTitles.has(sugKey)) {
                  suggestionTitles.add(sugKey);
                  suggestions.push({
                    title: `${profile.studio} Collection`,
                    type: 'personal',
                    subtype: 'studio',
                    sourceTitle: profile.fullTitle,
                    filters: { studio: profile.studio },
                    reason: `Because you watched "${profile.fullTitle}" — ${count} more from ${profile.studio}`,
                    libraryKey: lib.key,
                    libraryTitle: lib.title,
                    estimatedItems: count,
                    createType: 'studio',
                    createValue: profile.studio
                  });
                }
              } catch(e) {}
            }
          }

          // Cap total suggestions
          if (suggestions.length >= 16) break;
        }
      } catch(e) {
        console.error('Suggestion engine - history error:', e.message);
      }
    }

    // --- b) Seasonal / Holiday suggestions ---
    const now = new Date();
    const month = now.getMonth() + 1;
    const day = now.getDate();
    const dayOfWeek = now.getDay();

    const seasonalMap = [];

    // Look-ahead: also check tomorrow for short events so we don't miss them
    const tomorrow = new Date(now.getTime() + 24 * 3600000);
    const tMonth = tomorrow.getMonth() + 1;
    const tDay = tomorrow.getDate();
    const tDow = tomorrow.getDay();

    // Helper: check if today OR tomorrow matches (for look-ahead)
    const dateMatch = (fn) => fn(month, day, dayOfWeek) || fn(tMonth, tDay, tDow);

    // === HOLIDAYS & EVENTS ===
    // durationHours = how long the collection should stay pinned (matches the event window)

    // New Year's (Dec 29 - Jan 5) — 8 days
    if ((month === 12 && day >= 29) || (month === 1 && day <= 5)) {
      seasonalMap.push({ title: "New Year's Party Picks", genres: ['Comedy'], reason: "🎆 Ring in the New Year with laughs", priority: 1, durationHours: 192 });
      seasonalMap.push({ title: "New Year's Romance", genres: ['Romance'], reason: "💋 New Year, new love stories", priority: 2, durationHours: 192 });
    }
    // Valentine's Day (Feb 1-14) — 14 days
    if (month === 2 && day <= 14) {
      seasonalMap.push({ title: "Valentine's Romance", genres: ['Romance'], reason: "❤️ Valentine's Day is coming", priority: 1, durationHours: 336 });
      seasonalMap.push({ title: "Valentine's Comedies", genres: ['Romance', 'Comedy'], reason: "💝 Feel-good love stories", priority: 2, durationHours: 336 });
      seasonalMap.push({ title: "Anti-Valentine's: Thrillers", genres: ['Thriller'], reason: "🖤 Not feeling romantic? Try suspense instead", priority: 3, durationHours: 336 });
    }
    // St. Patrick's Day (Mar 14-17) — 4 days
    if (month === 3 && day >= 14 && day <= 17) {
      seasonalMap.push({ title: "St. Patrick's Adventures", genres: ['Adventure', 'Fantasy'], reason: "☘️ St. Patrick's Day adventures", priority: 2, durationHours: 96 });
    }
    // Easter week (approximate: late March / April) — ~5 weeks
    if ((month === 3 && day >= 20) || (month === 4 && day <= 25)) {
      seasonalMap.push({ title: "Spring Family Favorites", genres: ['Family', 'Animation'], reason: "🐣 Spring family movie time", priority: 2, durationHours: 168 });
    }
    // Earth Day (Apr 20-22) — 3 days
    if (month === 4 && day >= 20 && day <= 22) {
      seasonalMap.push({ title: "Nature & Environment", genres: ['Documentary'], reason: "🌍 Earth Day — explore nature documentaries", priority: 1, durationHours: 72 });
    }
    // Cinco de Mayo (May 3-5) — 3 days
    if (month === 5 && day >= 3 && day <= 5) {
      seasonalMap.push({ title: "Cinco de Mayo Fiesta", genres: ['Action', 'Comedy'], reason: "🎉 Cinco de Mayo celebration picks", priority: 2, durationHours: 72 });
    }
    // Mother's Day (2nd Sunday of May — approximate May 8-14)
    if (month === 5 && day >= 8 && day <= 14 && dayOfWeek === 0) {
      seasonalMap.push({ title: "Movies for Mom", genres: ['Drama', 'Family'], reason: "💐 Happy Mother's Day!", priority: 1, durationHours: 48 });
    }
    // Memorial Day / Start of Summer (last week of May) — 7 days
    if (month === 5 && day >= 25) {
      seasonalMap.push({ title: "Memorial Day War Classics", genres: ['War', 'History'], reason: "🎖️ Memorial Day — honoring the brave", priority: 1, durationHours: 168 });
    }
    // Father's Day (3rd Sunday of June — approximate Jun 15-21)
    if (month === 6 && day >= 15 && day <= 21 && dayOfWeek === 0) {
      seasonalMap.push({ title: "Movies for Dad", genres: ['Action', 'Adventure'], reason: "👨 Happy Father's Day!", priority: 1, durationHours: 48 });
    }
    // 4th of July (Jul 1-4) — 4 days
    if (month === 7 && day <= 4) {
      seasonalMap.push({ title: "4th of July Action", genres: ['Action'], reason: "🇺🇸 Independence Day celebration", priority: 1, durationHours: 96 });
      seasonalMap.push({ title: "Patriotic War Films", genres: ['War'], reason: "🎆 Patriotic picks for the 4th", priority: 2, durationHours: 96 });
    }
    // Summer (Jun-Aug) — long season
    if (month >= 6 && month <= 8) {
      seasonalMap.push({ title: 'Summer Blockbusters', genres: ['Action', 'Adventure'], reason: '☀️ Action-packed summer entertainment', priority: 3, durationHours: 336 });
      seasonalMap.push({ title: 'Summer Comedies', genres: ['Comedy'], reason: '😎 Light summer laughs', priority: 3, durationHours: 336 });
    }
    // Back to School (Aug 15 - Sep 7) — ~3 weeks
    if ((month === 8 && day >= 15) || (month === 9 && day <= 7)) {
      seasonalMap.push({ title: "Back to School", genres: ['Comedy', 'Family'], reason: "📚 Back to school season", priority: 2, durationHours: 504 });
    }
    // Friday the 13th (any month) — 1 day event, look-ahead so it's ready the night before
    if (dateMatch((m, d, dow) => dow === 5 && d === 13)) {
      seasonalMap.push({ title: 'Friday the 13th Special', genres: ['Horror'], reason: "🔪 It's Friday the 13th!", priority: 0, durationHours: 36 });
    }
    // Halloween season (Oct 1 - Nov 1) — month-long
    if (month === 10 || (month === 11 && day === 1)) {
      seasonalMap.push({ title: 'Halloween Horror', genres: ['Horror'], reason: '🎃 Spooky season is here!', priority: 0, durationHours: 168 });
      seasonalMap.push({ title: 'Halloween Thrillers', genres: ['Thriller', 'Mystery'], reason: '🌙 Chilling thrillers for October nights', priority: 1, durationHours: 168 });
      seasonalMap.push({ title: 'Spooky Family Fun', genres: ['Family', 'Animation'], reason: '👻 Family-friendly Halloween picks', priority: 2, durationHours: 168 });
      if (day >= 25) {
        seasonalMap.push({ title: 'Halloween Night Terrors', genres: ['Horror'], reason: '💀 Final week of Halloween — maximum fear!', priority: 0, durationHours: 168 });
      }
    }
    // Thanksgiving (Nov 20-28) — 9 days
    if (month === 11 && day >= 20 && day <= 28) {
      seasonalMap.push({ title: 'Thanksgiving Family', genres: ['Family', 'Comedy'], reason: '🦃 Thanksgiving family favorites', priority: 1, durationHours: 216 });
      seasonalMap.push({ title: 'Thanksgiving Drama', genres: ['Drama'], reason: '🍂 Heartwarming dramas for the holiday', priority: 2, durationHours: 216 });
    }
    // Holiday/Christmas season (Dec 1-31) — month-long
    if (month === 12) {
      seasonalMap.push({ title: 'Holiday Classics', genres: ['Family'], reason: '🎄 Family-friendly holiday entertainment', priority: 0, durationHours: 336 });
      seasonalMap.push({ title: 'Holiday Comedies', genres: ['Comedy'], reason: '🎅 Laugh through the holidays', priority: 1, durationHours: 336 });
      seasonalMap.push({ title: 'Holiday Romance', genres: ['Romance'], reason: '❄️ Romantic holiday picks', priority: 2, durationHours: 336 });
      seasonalMap.push({ title: 'Holiday Animation', genres: ['Animation'], reason: '⛄ Animated holiday magic', priority: 2, durationHours: 336 });
      if (day >= 20) {
        seasonalMap.push({ title: 'Christmas Countdown', genres: ['Family', 'Comedy'], reason: '🎁 Christmas is almost here!', priority: 0, durationHours: 264 });
      }
    }
    // Fall / Autumn (Sep 15 - Nov 15) — long season
    if ((month === 9 && day >= 15) || month === 10 || (month === 11 && day <= 15)) {
      seasonalMap.push({ title: 'Autumn Mystery', genres: ['Mystery', 'Thriller'], reason: '🍂 Cozy autumn mystery picks', priority: 3, durationHours: 336 });
    }
    // Winter (Dec - Feb) — long season
    if (month === 12 || month === 1 || month === 2) {
      seasonalMap.push({ title: 'Winter Chill: Sci-Fi', genres: ['Science Fiction'], reason: '❄️ Cold nights, epic sci-fi', priority: 3, durationHours: 336 });
    }
    // Spring (Mar - May) — long season
    if (month >= 3 && month <= 5) {
      seasonalMap.push({ title: 'Spring Adventures', genres: ['Adventure'], reason: '🌸 Fresh adventures for spring', priority: 3, durationHours: 336 });
    }

    // Sort seasonal by priority (0=highest)
    seasonalMap.sort((a, b) => (a.priority || 99) - (b.priority || 99));

    // Sort libraries: prefer non-anime libraries for seasonal (anime libraries as fallback)
    const isAnimeLib = (lib) => /anime/i.test(lib.title);
    const sortedMovieLibs = [...movieLibs].sort((a, b) => (isAnimeLib(a) ? 1 : 0) - (isAnimeLib(b) ? 1 : 0));
    const sortedShowLibs = [...showLibs].sort((a, b) => (isAnimeLib(a) ? 1 : 0) - (isAnimeLib(b) ? 1 : 0));

    for (const sug of seasonalMap) {
      const genre = sug.genres[0]; // Primary genre for filtering
      const extraGenres = sug.genres.slice(1); // Additional genres to AND-intersect against
      const targetLibs = [...sortedMovieLibs, ...sortedShowLibs];
      let found = false;
      for (const lib of targetLibs) {
        try {
          const countRes = await axios.get(`${config.plex.url}/library/sections/${lib.key}/all`, {
            params: { 'X-Plex-Token': config.plex.token, genre, 'X-Plex-Container-Size': 0, 'X-Plex-Container-Start': 0 },
            headers: { Accept: 'application/json' }, timeout: 5000
          });
          const count = countRes.data.MediaContainer.totalSize || countRes.data.MediaContainer.size || 0;
          if (count > 0) {
            suggestions.push({
              title: sug.title, type: 'seasonal', subtype: 'seasonal',
              filters: { genre, extraGenres }, reason: sug.reason,
              libraryKey: lib.key, libraryTitle: lib.title, estimatedItems: count,
              createType: 'seasonal', createValue: genre,
              extraGenres,
              seasonal: true, priority: sug.priority, seasonalDurationHours: sug.durationHours
            });
            found = true;
            break; // Use first matching library (prefers non-anime)
          }
        } catch(e) {}
      }
    }

    // Deduplicate by title+libraryKey
    const seen = new Set();
    const uniqueSuggestions = suggestions.filter(s => {
      const key = `${s.title}:${s.libraryKey}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    res.json(uniqueSuggestions);
  } catch (error) {
    console.error('Suggestion engine error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Collection Auto-Rotation
app.post('/api/plex/collections/rotate', async (req, res) => {
  try {
    const results = { deleted: [], replaced: [], kept: [], errors: [] };

    // Get all collections and find PCC-created ones (tagged in summary)
    const libRes = await axios.get(`${config.plex.url}/library/sections`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { 'Accept': 'application/json' },
      timeout: 5000
    });

    const now = new Date();
    const month = now.getMonth() + 1;

    for (const lib of (libRes.data.MediaContainer.Directory || [])) {
      try {
        const colRes = await axios.get(`${config.plex.url}/library/sections/${lib.key}/collections`, {
          params: { 'X-Plex-Token': config.plex.token },
          headers: { 'Accept': 'application/json' },
          timeout: 5000
        });

        for (const col of (colRes.data.MediaContainer.Metadata || [])) {
          const summary = col.summary || '';
          if (!summary.includes('[PCC-Auto]') && !summary.includes('[PCC-Seasonal]')) continue;

          const isSeasonal = summary.includes('[PCC-Seasonal]');

          if (isSeasonal) {
            // Check if the season has passed
            // Parse season info from summary: [PCC-Seasonal:month-start:month-end]
            const seasonMatch = summary.match(/\[PCC-Seasonal:(\d+):(\d+)\]/);
            if (seasonMatch) {
              const startMonth = parseInt(seasonMatch[1]);
              const endMonth = parseInt(seasonMatch[2]);
              const inSeason = startMonth <= endMonth
                ? (month >= startMonth && month <= endMonth)
                : (month >= startMonth || month <= endMonth);

              if (!inSeason) {
                // Season passed, delete collection
                try {
                  await axios.delete(`${config.plex.url}/library/collections/${col.ratingKey}`, {
                    params: { 'X-Plex-Token': config.plex.token },
                    timeout: 5000
                  });
                  results.deleted.push({ title: col.title, reason: 'Season ended' });
                } catch(e) {
                  results.errors.push({ title: col.title, error: e.message });
                }
                continue;
              }
            }
            results.kept.push({ title: col.title, reason: 'Still in season' });
          } else {
            // PCC-Auto: check age and watch activity
            const createdMatch = summary.match(/\[PCC-Created:(\d{4}-\d{2}-\d{2})\]/);
            if (createdMatch) {
              const createdDate = new Date(createdMatch[1]);
              const daysSinceCreation = Math.floor((now - createdDate) / 86400000);

              if (daysSinceCreation >= 30) {
                // Check if user watched any items in this collection via Tautulli
                let watched = false;
                if (config.tautulli.apiKey) {
                  try {
                    // Get collection items
                    const itemsRes = await axios.get(`${config.plex.url}/library/collections/${col.ratingKey}/children`, {
                      params: { 'X-Plex-Token': config.plex.token },
                      headers: { 'Accept': 'application/json' },
                      timeout: 5000
                    });
                    const colItems = itemsRes.data.MediaContainer.Metadata || [];
                    for (const item of colItems.slice(0, 10)) {
                      const histRes = await axios.get(`${config.tautulli.url}/api/v2`, {
                        params: { apikey: config.tautulli.apiKey, cmd: 'get_history', rating_key: item.ratingKey, length: 1 },
                        timeout: 5000
                      });
                      const histData = histRes.data?.response?.data?.data || [];
                      if (histData.length > 0) { watched = true; break; }
                    }
                  } catch(e) {}
                }

                if (!watched) {
                  // Delete old unwatched collection
                  try {
                    await axios.delete(`${config.plex.url}/library/collections/${col.ratingKey}`, {
                      params: { 'X-Plex-Token': config.plex.token },
                      timeout: 5000
                    });
                    results.replaced.push({ title: col.title, reason: '30+ days old, no watches' });
                  } catch(e) {
                    results.errors.push({ title: col.title, error: e.message });
                  }
                } else {
                  results.kept.push({ title: col.title, reason: 'Has watch activity' });
                }
              } else {
                results.kept.push({ title: col.title, reason: `Only ${daysSinceCreation} days old` });
              }
            }
          }
        }
      } catch(e) {
        results.errors.push({ library: lib.title, error: e.message });
      }
    }

    res.json({ success: true, results });
  } catch (error) {
    console.error('Collection rotation error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete collection
app.delete('/api/plex/collections/:key', async (req, res) => {
  try {
    await axios.delete(`${config.plex.url}/library/collections/${req.params.key}`, {
      params: { 'X-Plex-Token': config.plex.token },
      timeout: 5000
    });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Pin/Unpin collection to Plex Home
app.post('/api/plex/collections/:key/pin', async (req, res) => {
  try {
    const { key } = req.params;
    const { pin, libraryKey } = req.body; // pin: true/false, libraryKey: library section id

    // Need to find the libraryKey if not provided
    let sectionId = libraryKey;
    if (!sectionId) {
      // Look up the collection to find its library
      const metaRes = await axios.get(`${config.plex.url}/library/collections/${key}`, {
        params: { 'X-Plex-Token': config.plex.token },
        headers: { 'Accept': 'application/json' },
        timeout: 5000
      });
      sectionId = metaRes.data.MediaContainer.librarySectionID;
    }

    if (pin) {
      // POST to managed hubs to pin
      await axios.post(
        `${config.plex.url}/hubs/sections/${sectionId}/manage`,
        null,
        {
          params: { 'X-Plex-Token': config.plex.token, metadataItemId: key, promotedToOwnHome: 1, promotedToRecommended: 1, promotedToSharedHome: 1 },
          headers: { 'Accept': 'application/json' },
          timeout: 5000
        }
      );
    } else {
      // DELETE from managed hubs to unpin
      await axios.delete(
        `${config.plex.url}/hubs/sections/${sectionId}/manage`,
        {
          params: { 'X-Plex-Token': config.plex.token, metadataItemId: key },
          headers: { 'Accept': 'application/json' },
          timeout: 5000
        }
      );
    }

    res.json({ success: true, pinned: pin, message: pin ? 'Collection pinned to Plex Home' : 'Collection unpinned from Plex Home' });
  } catch (error) {
    console.error('Pin collection error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// AUTO-COLLECTION ENGINE (SQLite-backed)
// ============================================

const fs = require('fs');
const pccDbDir = path.join(__dirname, 'data');
if (!fs.existsSync(pccDbDir)) fs.mkdirSync(pccDbDir, { recursive: true });
const pccDb = new Database(path.join(pccDbDir, 'pcc.db'));
pccDb.pragma('journal_mode = WAL');
pccDb.exec(`
  CREATE TABLE IF NOT EXISTS auto_collections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plex_key TEXT NOT NULL,
    library_key TEXT NOT NULL,
    title TEXT NOT NULL,
    create_type TEXT NOT NULL,
    create_value TEXT NOT NULL,
    source_title TEXT,
    pinned INTEGER NOT NULL DEFAULT 1,
    duration_hours INTEGER NOT NULL DEFAULT 168,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS auto_collection_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    interval_hours INTEGER NOT NULL DEFAULT 12,
    duration_hours INTEGER NOT NULL DEFAULT 168,
    max_collections INTEGER NOT NULL DEFAULT 3,
    pin_to_home INTEGER NOT NULL DEFAULT 1,
    seasonal_enabled INTEGER NOT NULL DEFAULT 1,
    max_seasonal INTEGER NOT NULL DEFAULT 1,
    last_run TEXT
  );
  INSERT OR IGNORE INTO auto_collection_settings (id, enabled) VALUES (1, 0);
`);

// ============================================
// AUTH SYSTEM - Users & Sessions (pcc.db)
// ============================================

pccDb.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    plex_user_id TEXT,
    plex_email TEXT,
    plex_thumb TEXT,
    role TEXT NOT NULL DEFAULT 'viewer',
    is_plex_user INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_login TEXT
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
`);

// Add must_change_password column if missing (idempotent for existing installs)
try {
  pccDb.prepare("SELECT must_change_password FROM users LIMIT 0").get();
} catch (e) {
  pccDb.exec("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0");
  console.log('[AUTH] Added users.must_change_password column');
}

// Soft warning for legacy installs that still have the literal 'admin' password. We do NOT
// auto-flag these accounts because the existing UI has no password-change modal yet — flagging
// them would lock the user out. Once a UI flow exists, this can be upgraded to a hard flag.
try {
  const localUsers = pccDb.prepare("SELECT id, username, password_hash FROM users WHERE is_plex_user = 0 AND password_hash IS NOT NULL").all();
  for (const u of localUsers) {
    try {
      if (bcrypt.compareSync('admin', u.password_hash)) {
        console.warn(`[AUTH] WARNING: user "${u.username}" still uses the default password "admin". Rotate it via POST /api/auth/change-password.`);
      }
    } catch(e) {}
  }
} catch(e) {}

// --- Security Tables ---
pccDb.exec(`
  CREATE TABLE IF NOT EXISTS blocked_entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_value TEXT NOT NULL,
    reason TEXT,
    blocked_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(entity_type, entity_value)
  );
  CREATE TABLE IF NOT EXISTS connection_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plex_user TEXT,
    ip_address TEXT,
    device TEXT,
    platform TEXT,
    player_product TEXT,
    geo_country TEXT,
    geo_city TEXT,
    geo_lat REAL,
    geo_lon REAL,
    geo_isp TEXT,
    content_title TEXT,
    session_id TEXT,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_connlog_user ON connection_log(plex_user);
  CREATE INDEX IF NOT EXISTS idx_connlog_ip ON connection_log(ip_address);
  CREATE INDEX IF NOT EXISTS idx_connlog_lastseen ON connection_log(last_seen);
`);

// --- Regional Security (Telegram alerts + region-based session termination) ---
//
// The pipeline is: 30s session poll detects a new playback session → geo-locate the IP →
// if the country is not in allowed_countries AND the IP isn't whitelisted → record an alert,
// fire a Telegram message with Allow/Block buttons, and (when configured) auto-terminate.
// The admin can react via the Telegram inline buttons or via the web UI's alerts panel.
//
// Plex limitation: we cannot block the SIGNIN itself (that happens on plex.tv), only the
// resulting playback session — so the worst-case delay is ~30s of unauthorized streaming
// before the kill, which matches the existing block enforcement model.
pccDb.exec(`
  CREATE TABLE IF NOT EXISTS regional_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS regional_whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    reason TEXT,
    added_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS region_alert_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_uuid TEXT NOT NULL UNIQUE,
    session_id TEXT,
    plex_user TEXT,
    ip_address TEXT,
    geo_country TEXT,
    geo_city TEXT,
    geo_isp TEXT,
    device TEXT,
    platform TEXT,
    product TEXT,
    decision TEXT NOT NULL DEFAULT 'pending',  -- pending | allow | block
    decided_by TEXT,
    decided_at TEXT,
    telegram_message_id TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_alertlog_decision ON region_alert_log(decision);
  CREATE INDEX IF NOT EXISTS idx_alertlog_created ON region_alert_log(created_at);
  -- Audit trail for the Plex reverse-proxy gateway. We only log denies and the FIRST allow
  -- per (ip, day) to keep volume manageable; full allow-stream traffic isn't worth the writes.
  CREATE TABLE IF NOT EXISTS gateway_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    country TEXT,
    city TEXT,
    allowed INTEGER NOT NULL,
    action TEXT,
    url_path TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_gwlog_ip ON gateway_log(ip_address);
  CREATE INDEX IF NOT EXISTS idx_gwlog_created ON gateway_log(created_at);
  CREATE INDEX IF NOT EXISTS idx_gwlog_allowed ON gateway_log(allowed);
`);
// Seed defaults: feature off, Israel + LAN allowed, alert-only (no auto-terminate) by default.
pccDb.exec("INSERT OR IGNORE INTO regional_settings (key, value) VALUES ('enabled', '0')");
pccDb.exec("INSERT OR IGNORE INTO regional_settings (key, value) VALUES ('allowed_countries', '[\"Israel\",\"Local\"]')");
pccDb.exec("INSERT OR IGNORE INTO regional_settings (key, value) VALUES ('action', 'alert_only')");
pccDb.exec("INSERT OR IGNORE INTO regional_settings (key, value) VALUES ('telegram_bot_token', '')");
pccDb.exec("INSERT OR IGNORE INTO regional_settings (key, value) VALUES ('telegram_chat_id', '')");
pccDb.exec("INSERT OR IGNORE INTO regional_settings (key, value) VALUES ('telegram_webhook_secret', '')");

// Seed default admin if no users exist — flagged so the first login is forced to rotate password.
const userCount = pccDb.prepare('SELECT COUNT(*) as cnt FROM users').get().cnt;
if (userCount === 0) {
  const defaultPass = 'admin';
  const hash = bcrypt.hashSync(defaultPass, 10);
  pccDb.prepare('INSERT INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, ?, 1)').run('admin', hash, 'admin');
  console.log('[AUTH] Default admin user created (username: admin, password: admin) — password change is REQUIRED on first login.');
}

// Session helpers
//
// Two expiry rules: an absolute 7-day cap (sessions.expires_at) AND an idle window enforced by
// `last_seen_at`. Activity bumps last_seen_at; if it's older than IDLE_TIMEOUT_MS the session is
// rejected. This bounds the damage window from a stolen cookie that's no longer in use.
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const SESSION_IDLE_MS = 24 * 60 * 60 * 1000; // 24h of inactivity → re-auth required

// Add last_seen_at column for idle-timeout enforcement (idempotent)
try {
  pccDb.prepare("SELECT last_seen_at FROM sessions LIMIT 0").get();
} catch (e) {
  pccDb.exec("ALTER TABLE sessions ADD COLUMN last_seen_at TEXT");
}

function createSession(userId, ip, userAgent) {
  const token = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  pccDb.prepare('INSERT INTO sessions (id, user_id, expires_at, ip_address, user_agent, last_seen_at) VALUES (?,?,?,?,?, datetime(\'now\'))').run(token, userId, expiresAt, ip, userAgent);
  return { token, expiresAt };
}

function getSessionUser(token) {
  if (!token) return null;
  const row = pccDb.prepare(`
    SELECT s.*, u.id as uid, u.username, u.role, u.plex_thumb, u.plex_email, u.is_plex_user, u.enabled, u.must_change_password
    FROM sessions s JOIN users u ON s.user_id = u.id
    WHERE s.id = ? AND s.expires_at > datetime('now')
  `).get(token);
  if (!row || !row.enabled) return null;
  // Idle check
  if (row.last_seen_at) {
    const last = Date.parse(row.last_seen_at + 'Z') || Date.parse(row.last_seen_at);
    if (Number.isFinite(last) && (Date.now() - last) > SESSION_IDLE_MS) {
      pccDb.prepare("DELETE FROM sessions WHERE id = ?").run(token);
      return null;
    }
  }
  // Bump last_seen_at — best-effort, throttle to once a minute to keep DB writes light
  try {
    pccDb.prepare("UPDATE sessions SET last_seen_at = datetime('now') WHERE id = ? AND (last_seen_at IS NULL OR last_seen_at < datetime('now', '-60 seconds'))").run(token);
  } catch(e) {}
  return { id: row.uid, username: row.username, role: row.role, plex_thumb: row.plex_thumb, plex_email: row.plex_email, is_plex_user: row.is_plex_user, must_change_password: !!row.must_change_password };
}

// Clean expired sessions every hour
setInterval(() => {
  pccDb.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();
}, 3600000);

// Cookie parser helper
function parseCookies(req) {
  const cookies = {};
  const header = req.headers.cookie;
  if (!header) return cookies;
  header.split(';').forEach(c => {
    const [k, ...v] = c.trim().split('=');
    if (k) cookies[k.trim()] = decodeURIComponent(v.join('='));
  });
  return cookies;
}

// Auth routes (no auth required)
const AUTH_EXEMPT = new Set([
  '/api/auth/login', '/api/auth/login/plex', '/api/health',
  // server-info is fetched by the TV app *before* it has a session token, so it can learn the
  // tailscale URL to use as automatic fallback when the LAN URL becomes unreachable. The payload
  // is env-derived and only useful to clients that already know one valid URL to reach us.
  '/api/server-info',
  // Telegram webhook authenticates via per-install secret in the URL/header, not session.
  '/api/security/telegram-webhook'
]);
const AUTH_EXEMPT_PREFIXES = [
  '/api/livetv/stream/', '/api/livetv/m3u', '/api/livetv/xmltv', '/api/livetv/logos/'
];
const TUNER_PATHS = new Set([
  '/discover.json', '/lineup.json', '/lineup_status.json', '/lineup.post', '/device.xml'
]);

// Routes a user with must_change_password=1 is still allowed to call
const PWCHANGE_OK_ROUTES = new Set([
  '/api/auth/me', '/api/auth/logout', '/api/auth/change-password'
]);

// Optional shared key for tuner endpoints. When TUNER_KEY env is set, /lineup.json,
// /api/livetv/stream/*, /api/livetv/m3u, /api/livetv/xmltv, /api/livetv/logos/* require
// `?key=…` query or `X-Tuner-Key` header. Plex DVR's HDHR config supports adding the query
// to the discovery URL. When TUNER_KEY is unset, behavior is unchanged (LAN-trust mode).
const TUNER_KEY = process.env.TUNER_KEY || '';
function checkTunerKey(req) {
  if (!TUNER_KEY) return true;
  const provided = (req.query && req.query.key) || req.headers['x-tuner-key'] || '';
  // crypto.timingSafeEqual requires equal-length buffers
  if (typeof provided !== 'string' || provided.length !== TUNER_KEY.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(TUNER_KEY));
  } catch(e) { return false; }
}

// Auth middleware - placed before all API routes
function requireAuth(req, res, next) {
  // Skip auth for exempt routes
  if (AUTH_EXEMPT.has(req.path)) return next();
  if (TUNER_PATHS.has(req.path)) {
    if (!checkTunerKey(req)) return res.status(401).json({ error: 'Tuner key required' });
    return next();
  }
  if (AUTH_EXEMPT_PREFIXES.some(p => req.path.startsWith(p))) {
    if (!checkTunerKey(req)) return res.status(401).json({ error: 'Tuner key required' });
    return next();
  }
  // Loopback bypass — the auto-collection cron calls /api/plex/collections/suggestions over
  // HTTP against its own process. Loopback (127.0.0.1 / ::1) traffic can only come from inside
  // the container's own network namespace, so it's safe to trust. Without this bypass the auth
  // middleware introduced in 3.1.0 broke the internal cron.
  if (req.ip === '127.0.0.1' || req.ip === '::1' || req.ip === '::ffff:127.0.0.1') {
    if (req.path.startsWith('/api/')) return next();
  }
  // Skip auth for static files / non-API
  if (!req.path.startsWith('/api/')) return next();

  const cookies = parseCookies(req);
  const token = cookies.pcc_session || req.headers['x-pcc-token'];
  const user = getSessionUser(token);
  if (!user) return res.status(401).json({ error: 'Authentication required' });
  // If the user must rotate their password, gate everything except the rotation endpoint itself.
  if (user.must_change_password && !PWCHANGE_OK_ROUTES.has(req.path)) {
    return res.status(403).json({ error: 'Password change required', mustChangePassword: true });
  }
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

// Build the session cookie header — adds Secure flag when the request came over TLS (works behind
// a reverse proxy because trust proxy + X-Forwarded-Proto is honored).
function sessionCookie(token, secure) {
  const flags = ['Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${7*24*3600}`];
  if (secure) flags.push('Secure');
  return `pcc_session=${token}; ${flags.join('; ')}`;
}

// --- Auth Endpoints ---
app.post('/api/auth/login', loginRateLimiter, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = pccDb.prepare('SELECT * FROM users WHERE username = ? AND is_plex_user = 0').get(username);
  if (!user || !user.enabled) return res.status(401).json({ error: 'Invalid credentials' });
  if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Invalid credentials' });

  pccDb.prepare('UPDATE users SET last_login = datetime(?) WHERE id = ?').run(new Date().toISOString(), user.id);
  const session = createSession(user.id, req.ip, req.headers['user-agent']);
  res.setHeader('Set-Cookie', sessionCookie(session.token, !!req.secure));
  res.json({
    success: true,
    token: session.token,
    user: { id: user.id, username: user.username, role: user.role, plex_thumb: user.plex_thumb },
    mustChangePassword: !!user.must_change_password
  });
});

app.post('/api/auth/login/plex', loginRateLimiter, async (req, res) => {
  const { authToken } = req.body;
  if (!authToken) return res.status(400).json({ error: 'Plex auth token required' });

  try {
    // Validate token with Plex
    const plexRes = await axios.get('https://plex.tv/api/v2/user', {
      headers: { 'X-Plex-Token': authToken, Accept: 'application/json' },
      timeout: 10000
    });
    const plexUser = plexRes.data;
    if (!plexUser || !plexUser.id) return res.status(401).json({ error: 'Invalid Plex token' });

    // Check if this Plex user is the server owner or a friend with access
    let isOwner = false;
    try {
      const serverRes = await axios.get(`${config.plex.url}/myplex/account`, {
        params: { 'X-Plex-Token': config.plex.token },
        headers: { Accept: 'application/json' },
        timeout: 5000
      });
      const serverAccount = serverRes.data?.MyPlex || serverRes.data?.MediaContainer || serverRes.data;
      const serverUser = serverAccount?.username || serverAccount?.email || '';
      const plexUsername = plexUser.username || plexUser.title || '';
      const plexEmail = plexUser.email || '';
      if (String(serverAccount?.id) === String(plexUser.id) ||
          (serverUser && (serverUser === plexUsername || serverUser === plexEmail || plexUsername === serverUser))) {
        isOwner = true;
      }
    } catch(e) { /* couldn't check ownership, proceed as viewer */ }

    // Upsert user record
    const existing = pccDb.prepare('SELECT * FROM users WHERE plex_user_id = ?').get(String(plexUser.id));
    let userId;
    // Keep existing admin role if already set, only upgrade to admin if owner detected
    const role = isOwner ? 'admin' : (existing?.role || 'viewer');
    if (existing) {
      const keepRole = (existing.role === 'admin') ? 'admin' : role;
      pccDb.prepare('UPDATE users SET username=?, plex_email=?, plex_thumb=?, role=?, last_login=datetime(?) WHERE id=?')
        .run(plexUser.username || plexUser.title, plexUser.email, plexUser.thumb, keepRole, new Date().toISOString(), existing.id);
      userId = existing.id;
    } else {
      const result = pccDb.prepare('INSERT INTO users (username, plex_user_id, plex_email, plex_thumb, role, is_plex_user, last_login) VALUES (?,?,?,?,?,1,datetime(?))')
        .run(plexUser.username || plexUser.title, String(plexUser.id), plexUser.email, plexUser.thumb, role, new Date().toISOString());
      userId = result.lastInsertRowid;
    }

    const session = createSession(userId, req.ip, req.headers['user-agent']);
    res.setHeader('Set-Cookie', sessionCookie(session.token, !!req.secure));
    res.json({ success: true, token: session.token, user: { id: userId, username: plexUser.username || plexUser.title, role, plex_thumb: plexUser.thumb } });
  } catch (err) {
    console.error('[AUTH] Plex login error:', err.message);
    res.status(401).json({ error: 'Plex authentication failed' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  const cookies = parseCookies(req);
  if (cookies.pcc_session) pccDb.prepare('DELETE FROM sessions WHERE id = ?').run(cookies.pcc_session);
  res.setHeader('Set-Cookie', 'pcc_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  res.json({ success: true });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  res.json({ user: req.user });
});

// Self-service password change (also used to clear must_change_password on first login).
// requireAuth already populates req.user; the PWCHANGE_OK_ROUTES exemption lets callers with
// must_change_password=1 reach this handler.
app.post('/api/auth/change-password', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Authentication required' });
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'currentPassword and newPassword required' });
  if (typeof newPassword !== 'string' || newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }
  if (newPassword === currentPassword) return res.status(400).json({ error: 'New password must differ from current' });

  const dbUser = pccDb.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!dbUser || dbUser.is_plex_user) return res.status(400).json({ error: 'Plex-linked accounts cannot change password here' });
  if (!bcrypt.compareSync(currentPassword, dbUser.password_hash)) return res.status(401).json({ error: 'Current password is incorrect' });

  const hash = bcrypt.hashSync(newPassword, 10);
  pccDb.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?').run(hash, dbUser.id);
  // Invalidate all OTHER sessions for this user — keep the current one active
  const cookies = parseCookies(req);
  const currentToken = cookies.pcc_session || req.headers['x-pcc-token'] || '';
  pccDb.prepare('DELETE FROM sessions WHERE user_id = ? AND id != ?').run(dbUser.id, currentToken);
  res.json({ success: true });
});

// --- Admin User Management ---
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = pccDb.prepare('SELECT id, username, role, is_plex_user, plex_email, plex_thumb, enabled, created_at, last_login FROM users ORDER BY created_at').all();
  res.json(users);
});

app.post('/api/admin/users', requireAdmin, (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (role && !['admin', 'viewer'].includes(role)) return res.status(400).json({ error: 'Invalid role' });

  const existing = pccDb.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'Username already exists' });

  const hash = bcrypt.hashSync(password, 10);
  const result = pccDb.prepare('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)').run(username, hash, role || 'viewer');
  res.json({ success: true, id: result.lastInsertRowid });
});

app.put('/api/admin/users/:id', requireAdmin, (req, res) => {
  const { role, enabled, password } = req.body;
  const user = pccDb.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (role && ['admin', 'viewer'].includes(role)) pccDb.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, req.params.id);
  if (enabled !== undefined) pccDb.prepare('UPDATE users SET enabled = ? WHERE id = ?').run(enabled ? 1 : 0, req.params.id);
  if (password) {
    const hash = bcrypt.hashSync(password, 10);
    pccDb.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.params.id);
  }
  // If disabling, kill their sessions
  if (enabled === false || enabled === 0) pccDb.prepare('DELETE FROM sessions WHERE user_id = ?').run(req.params.id);

  res.json({ success: true });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  if (String(req.params.id) === String(req.user.id)) return res.status(400).json({ error: 'Cannot delete yourself' });
  pccDb.prepare('DELETE FROM sessions WHERE user_id = ?').run(req.params.id);
  pccDb.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ============================================
// SECURITY - Connection Logging & Blocking
// ============================================

const geoCache = new Map(); // ip -> { data, expires }
const GEO_CACHE_TTL = 24 * 3600 * 1000; // 24 hours

async function lookupGeo(ip) {
  if (!ip || ip === 'Unknown' || ip === '127.0.0.1' || ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.') || ip === '::1') {
    return { country: 'Local', city: 'LAN', lat: 0, lon: 0, isp: 'Local Network' };
  }
  const cached = geoCache.get(ip);
  if (cached && Date.now() < cached.expires) return cached.data;
  try {
    const r = await axios.get(`http://ip-api.com/json/${ip}?fields=country,city,lat,lon,isp,status`, { timeout: 3000 });
    if (r.data.status === 'success') {
      const data = { country: r.data.country, city: r.data.city, lat: r.data.lat, lon: r.data.lon, isp: r.data.isp };
      geoCache.set(ip, { data, expires: Date.now() + GEO_CACHE_TTL });
      return data;
    }
  } catch(e) { /* ignore geo errors */ }
  return { country: 'Unknown', city: '', lat: 0, lon: 0, isp: '' };
}

// Block enforcement helper - terminates any sessions matching blocked entities
async function enforceBlocks() {
  if (!config.plex.token) return;
  const blocked = pccDb.prepare('SELECT * FROM blocked_entities').all();
  if (blocked.length === 0) return;
  try {
    const sessRes = await axios.get(`${config.plex.url}/status/sessions`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { Accept: 'application/json' },
      timeout: 5000
    });
    const sessions = sessRes.data?.MediaContainer?.Metadata || [];
    for (const s of sessions) {
      const user = s.User?.title || 'Unknown';
      const ip = s.Player?.remotePublicAddress || s.Player?.address || s.Session?.address || '';
      const device = s.Player?.device || s.Player?.product || '';
      const sessionId = s.Session?.id || s.sessionKey || '';
      const isBlocked = blocked.some(b =>
        (b.entity_type === 'user' && b.entity_value === user) ||
        (b.entity_type === 'ip' && b.entity_value === ip) ||
        (b.entity_type === 'device' && b.entity_value === device)
      );
      if (isBlocked) {
        await axios.get(`${config.plex.url}/status/sessions/terminate`, {
          params: { sessionId, reason: 'Blocked by administrator', 'X-Plex-Token': config.plex.token },
          timeout: 3000
        }).catch(() => {});
        console.log(`[SECURITY] Terminated blocked session: user=${user} ip=${ip} device=${device}`);
      }
    }
  } catch(e) { /* ignore */ }
}

// Fast block enforcement - every 5 seconds when blocks exist
setInterval(() => {
  const blockCount = pccDb.prepare('SELECT COUNT(*) as cnt FROM blocked_entities').get().cnt;
  if (blockCount > 0) enforceBlocks();
}, 5000);

// Background session logger - polls Plex sessions every 30s for connection history
setInterval(async () => {
  if (!config.plex.token) return;
  try {
    const sessRes = await axios.get(`${config.plex.url}/status/sessions`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { Accept: 'application/json' },
      timeout: 5000
    });
    const sessions = sessRes.data?.MediaContainer?.Metadata || [];

    for (const s of sessions) {
      const user = s.User?.title || 'Unknown';
      const ip = s.Player?.remotePublicAddress || s.Player?.address || s.Session?.address || '';
      const device = s.Player?.device || s.Player?.product || '';
      const platform = s.Player?.platform || '';
      const product = s.Player?.product || '';
      const content = s.type === 'episode' ? `${s.grandparentTitle || ''} - ${s.title}` : (s.title || '');
      const sessionId = s.Session?.id || s.sessionKey || '';

      // Geo lookup
      const geo = await lookupGeo(ip);

      // Upsert connection log. Plex reuses Session.id across all streams from the same client
      // device, so a returning client looks "known" forever. To make the geo check actually fire
      // when a device's IP changes (e.g. user goes abroad / VPN flips countries), we re-evaluate
      // any time we see the same session_id with a different ip_address.
      const existing = pccDb.prepare('SELECT id, ip_address FROM connection_log WHERE session_id = ?').get(sessionId);
      if (existing && existing.ip_address === ip) {
        pccDb.prepare(`UPDATE connection_log SET last_seen = datetime('now'), content_title = ?,
          geo_country = COALESCE(?, geo_country), geo_city = COALESCE(?, geo_city),
          geo_lat = COALESCE(?, geo_lat), geo_lon = COALESCE(?, geo_lon), geo_isp = COALESCE(?, geo_isp)
          WHERE id = ?`).run(content, geo.country, geo.city, geo.lat, geo.lon, geo.isp, existing.id);
      } else {
        if (existing) {
          // Same session_id, different IP — overwrite the row so its country reflects the new IP.
          pccDb.prepare(`UPDATE connection_log SET ip_address = ?, geo_country = ?, geo_city = ?,
            geo_lat = ?, geo_lon = ?, geo_isp = ?, content_title = ?, last_seen = datetime('now')
            WHERE id = ?`).run(ip, geo.country, geo.city, geo.lat, geo.lon, geo.isp, content, existing.id);
        } else {
          pccDb.prepare(`INSERT INTO connection_log (plex_user, ip_address, device, platform, player_product, geo_country, geo_city, geo_lat, geo_lon, geo_isp, content_title, session_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(user, ip, device, platform, product, geo.country, geo.city, geo.lat, geo.lon, geo.isp, content, sessionId);
        }
      }
      // Always run the regional policy on every poll — the internal dedupe inside
      // evaluateRegionalSession decides whether to actually fire an alert. The previous code only
      // evaluated on new sessions, so when Plex re-used the session_id after an auto-terminate
      // the block never re-fired (and the alert log went silent past the first kick).
      try { await evaluateRegionalSession(s); } catch(e) { console.warn('[REGIONAL] eval error:', e.message); }
    }
  } catch(e) { /* silent fail on session poll */ }
}, 30000);

// --- Security Endpoints ---
app.get('/api/security/connections', requireAdmin, (req, res) => {
  const { user, ip, days } = req.query;
  let sql = 'SELECT * FROM connection_log WHERE 1=1';
  const params = [];
  if (user) { sql += ' AND plex_user = ?'; params.push(user); }
  if (ip) { sql += ' AND ip_address = ?'; params.push(ip); }
  if (days) { sql += ` AND last_seen > datetime('now', '-${parseInt(days)} days')`; }
  sql += ' ORDER BY last_seen DESC LIMIT 500';
  res.json(pccDb.prepare(sql).all(...params));
});

app.get('/api/security/connections/live', requireAdmin, async (req, res) => {
  try {
    const sessRes = await axios.get(`${config.plex.url}/status/sessions`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { Accept: 'application/json' },
      timeout: 5000
    });
    const sessions = sessRes.data?.MediaContainer?.Metadata || [];
    const blocked = pccDb.prepare('SELECT * FROM blocked_entities').all();
    const result = [];
    for (const s of sessions) {
      const ip = s.Player?.remotePublicAddress || s.Player?.address || s.Session?.address || '';
      const user = s.User?.title || 'Unknown';
      const device = s.Player?.device || s.Player?.product || '';
      const geo = await lookupGeo(ip);
      const isBlocked = blocked.some(b =>
        (b.entity_type === 'user' && b.entity_value === user) ||
        (b.entity_type === 'ip' && b.entity_value === ip) ||
        (b.entity_type === 'device' && b.entity_value === device)
      );
      result.push({
        sessionId: s.Session?.id || s.sessionKey,
        user, ip, device,
        platform: s.Player?.platform || '',
        product: s.Player?.product || '',
        content: s.type === 'episode' ? `${s.grandparentTitle || ''} - ${s.title}` : (s.title || ''),
        quality: s.Media?.[0]?.videoResolution || 'SD',
        transcoding: !!s.TranscodeSession,
        bandwidth: Math.round((s.Session?.bandwidth || 0) / 1024),
        state: s.Player?.state || 'playing',
        geo, isBlocked
      });
    }
    res.json(result);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/security/blocked', requireAdmin, (req, res) => {
  res.json(pccDb.prepare('SELECT * FROM blocked_entities ORDER BY created_at DESC').all());
});

app.post('/api/security/block', requireAdmin, async (req, res) => {
  const { entity_type, entity_value, reason } = req.body;
  if (!entity_type || !entity_value) return res.status(400).json({ error: 'entity_type and entity_value required' });
  if (!['ip', 'user', 'device'].includes(entity_type)) return res.status(400).json({ error: 'entity_type must be ip, user, or device' });

  try {
    pccDb.prepare('INSERT OR REPLACE INTO blocked_entities (entity_type, entity_value, reason, blocked_by) VALUES (?,?,?,?)')
      .run(entity_type, entity_value, reason || null, req.user?.username || 'admin');
  } catch(e) {
    return res.status(500).json({ error: e.message });
  }

  // Terminate any active sessions matching this block
  try {
    const sessRes = await axios.get(`${config.plex.url}/status/sessions`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { Accept: 'application/json' },
      timeout: 5000
    });
    const sessions = sessRes.data?.MediaContainer?.Metadata || [];
    for (const s of sessions) {
      const match = (entity_type === 'user' && (s.User?.title === entity_value)) ||
                    (entity_type === 'ip' && ((s.Player?.remotePublicAddress || s.Player?.address || s.Session?.address) === entity_value)) ||
                    (entity_type === 'device' && ((s.Player?.device || s.Player?.product) === entity_value));
      if (match) {
        const sid = s.Session?.id || s.sessionKey;
        await axios.get(`${config.plex.url}/status/sessions/terminate`, {
          params: { sessionId: sid, reason: 'Blocked by administrator', 'X-Plex-Token': config.plex.token },
          timeout: 3000
        }).catch(() => {});
        console.log(`[SECURITY] Terminated session ${sid} for blocked ${entity_type}: ${entity_value}`);
      }
    }
  } catch(e) { /* ignore */ }

  res.json({ success: true });
});

app.delete('/api/security/block/:id', requireAdmin, (req, res) => {
  pccDb.prepare('DELETE FROM blocked_entities WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// --- Regional security helpers ---

function readRegionalSettings() {
  const rows = pccDb.prepare('SELECT key, value FROM regional_settings').all();
  const map = {};
  for (const r of rows) map[r.key] = r.value;
  let allowed = ['Israel', 'Local'];
  try { allowed = JSON.parse(map.allowed_countries || '["Israel","Local"]'); } catch(e) {}
  return {
    enabled: map.enabled === '1',
    allowed_countries: allowed,
    action: map.action || 'alert_only', // 'alert_only' or 'auto_terminate'
    telegram_bot_token: map.telegram_bot_token || '',
    telegram_chat_id: map.telegram_chat_id || '',
    telegram_webhook_secret: map.telegram_webhook_secret || ''
  };
}

function isIpRegionallyWhitelisted(ip) {
  if (!ip) return false;
  const row = pccDb.prepare('SELECT 1 FROM regional_whitelist WHERE ip_address = ?').get(ip);
  return !!row;
}

async function sendTelegramAlert(settings, alert) {
  if (!settings.telegram_bot_token || !settings.telegram_chat_id) return null;
  const text = [
    '🚨 *Foreign Plex session detected*',
    '',
    `*User:* ${alert.plex_user || 'Unknown'}`,
    `*IP:* \`${alert.ip_address || '?'}\``,
    `*Location:* ${alert.geo_city || ''}, ${alert.geo_country || '?'} (${alert.geo_isp || 'unknown ISP'})`,
    `*Device:* ${alert.device || 'Unknown'}`,
    `*Platform / app:* ${alert.platform || ''} / ${alert.product || ''}`,
    `*Time:* ${new Date().toUTCString()}`,
    '',
    settings.action === 'auto_terminate'
      ? 'Session was *auto-terminated*. Use the buttons below to whitelist this IP for future sign-ins or to keep it blocked.'
      : 'Tap a button below to allow (whitelist this IP) or block (terminate now and on every future sign-in).'
  ].join('\n');
  const reply_markup = {
    inline_keyboard: [[
      { text: '✅ Allow this IP', callback_data: `allow:${alert.alert_uuid}` },
      { text: '🚫 Block this IP', callback_data: `block:${alert.alert_uuid}` }
    ]]
  };
  try {
    const r = await axios.post(`https://api.telegram.org/bot${settings.telegram_bot_token}/sendMessage`, {
      chat_id: settings.telegram_chat_id,
      text,
      parse_mode: 'Markdown',
      reply_markup
    }, { timeout: 8000 });
    return r.data?.result?.message_id ? String(r.data.result.message_id) : null;
  } catch(e) {
    console.warn('[REGIONAL] Telegram sendMessage failed:', e.message);
    return null;
  }
}

async function editTelegramAlertResolution(settings, messageId, decisionText) {
  if (!settings.telegram_bot_token || !settings.telegram_chat_id || !messageId) return;
  try {
    await axios.post(`https://api.telegram.org/bot${settings.telegram_bot_token}/editMessageReplyMarkup`, {
      chat_id: settings.telegram_chat_id,
      message_id: Number(messageId),
      reply_markup: { inline_keyboard: [[{ text: decisionText, callback_data: 'noop' }]] }
    }, { timeout: 5000 });
  } catch(e) { /* best-effort */ }
}

async function terminatePlexSessionById(sessionId, reason) {
  if (!sessionId || !config.plex.token) return;
  try {
    await axios.get(`${config.plex.url}/status/sessions/terminate`, {
      params: { sessionId, reason: reason || 'Region policy', 'X-Plex-Token': config.plex.token },
      timeout: 3000
    });
  } catch(e) { /* ignore */ }
}

async function evaluateRegionalSession(s) {
  const settings = readRegionalSettings();
  if (!settings.enabled) return;
  const ip = s.Player?.remotePublicAddress || s.Player?.address || s.Session?.address || '';
  if (!ip) return;
  if (isIpRegionallyWhitelisted(ip)) return;

  const geo = await lookupGeo(ip);
  if (!geo || !geo.country) return;
  if (settings.allowed_countries.includes(geo.country)) return;
  // Don't re-alert on the same (session_id, ip) within a short window — a client streaming
  // continuously shouldn't spam new rows on every 30s poll. Time-windowed instead of
  // decision='pending' so that a re-stream after auto-terminate still re-fires after 5 minutes,
  // keeping the audit log honest for repeated attempts.
  const sessionId = s.Session?.id || s.sessionKey || '';
  if (sessionId) {
    const existing = pccDb.prepare(
      "SELECT id FROM region_alert_log WHERE session_id = ? AND ip_address = ? AND created_at > datetime('now', '-5 minutes')"
    ).get(sessionId, ip);
    if (existing) {
      // Still inside the dedup window. Re-enforce termination silently — Plex may have re-issued
      // the session after the previous kick and we want it dead again, not just logged.
      if (settings.action === 'auto_terminate') {
        await terminatePlexSessionById(sessionId, `Region policy: ${geo.country} not allowed (re-enforce)`);
      }
      return;
    }
  }

  const alert = {
    alert_uuid: crypto.randomUUID(),
    session_id: sessionId,
    plex_user: s.User?.title || 'Unknown',
    ip_address: ip,
    geo_country: geo.country,
    geo_city: geo.city || '',
    geo_isp: geo.isp || '',
    device: s.Player?.device || s.Player?.product || '',
    platform: s.Player?.platform || '',
    product: s.Player?.product || ''
  };
  pccDb.prepare(`INSERT INTO region_alert_log
    (alert_uuid, session_id, plex_user, ip_address, geo_country, geo_city, geo_isp, device, platform, product)
    VALUES (?,?,?,?,?,?,?,?,?,?)`).run(
      alert.alert_uuid, alert.session_id, alert.plex_user, alert.ip_address,
      alert.geo_country, alert.geo_city, alert.geo_isp, alert.device, alert.platform, alert.product
    );

  if (settings.action === 'auto_terminate') {
    await terminatePlexSessionById(sessionId, `Region policy: ${geo.country} not allowed`);
    // Auto-terminated alerts shouldn't sit forever in 'pending' — the decision was effectively
    // 'block' the moment we killed the session. Stamp it so the history view reads correctly.
    pccDb.prepare("UPDATE region_alert_log SET decision='block', decided_by='auto_terminate', decided_at=datetime('now') WHERE alert_uuid = ?").run(alert.alert_uuid);
    console.log(`[REGIONAL] Auto-terminated session from ${geo.country} (${ip}, user=${alert.plex_user})`);
  } else {
    console.log(`[REGIONAL] Alert queued for ${geo.country} session (${ip}, user=${alert.plex_user})`);
  }

  const msgId = await sendTelegramAlert(settings, alert);
  if (msgId) {
    pccDb.prepare("UPDATE region_alert_log SET telegram_message_id = ? WHERE alert_uuid = ?").run(msgId, alert.alert_uuid);
  }
}

// --- Regional security endpoints ---

app.get('/api/security/regional-settings', requireAdmin, (req, res) => {
  const s = readRegionalSettings();
  // Mask the bot token so it isn't broadcast in admin panels
  res.json({
    enabled: s.enabled,
    allowed_countries: s.allowed_countries,
    action: s.action,
    telegram_chat_id: s.telegram_chat_id,
    telegram_bot_token_set: !!s.telegram_bot_token,
    telegram_webhook_secret_set: !!s.telegram_webhook_secret
  });
});

app.put('/api/security/regional-settings', requireAdmin, (req, res) => {
  const body = req.body || {};
  const updates = [];
  const setKey = (k, v) => updates.push([k, v]);
  if (body.enabled !== undefined) setKey('enabled', (body.enabled === true || body.enabled === '1' || body.enabled === 1) ? '1' : '0');
  if (body.allowed_countries !== undefined) {
    if (!Array.isArray(body.allowed_countries)) return res.status(400).json({ error: 'allowed_countries must be an array' });
    setKey('allowed_countries', JSON.stringify(body.allowed_countries.slice(0, 100).map(s => String(s))));
  }
  if (body.action !== undefined) {
    if (!['alert_only', 'auto_terminate'].includes(body.action)) return res.status(400).json({ error: "action must be 'alert_only' or 'auto_terminate'" });
    setKey('action', body.action);
  }
  if (body.telegram_bot_token !== undefined) setKey('telegram_bot_token', String(body.telegram_bot_token));
  if (body.telegram_chat_id !== undefined) setKey('telegram_chat_id', String(body.telegram_chat_id));
  if (body.telegram_webhook_secret !== undefined) setKey('telegram_webhook_secret', String(body.telegram_webhook_secret));
  const stmt = pccDb.prepare("INSERT OR REPLACE INTO regional_settings (key, value) VALUES (?, ?)");
  const tx = pccDb.transaction((rows) => { for (const [k, v] of rows) stmt.run(k, v); });
  tx(updates);
  res.json({ success: true });
});

// Send a test Telegram message — useful when first wiring up the bot
app.post('/api/security/regional-settings/test-telegram', requireAdmin, async (req, res) => {
  const s = readRegionalSettings();
  if (!s.telegram_bot_token || !s.telegram_chat_id) return res.status(400).json({ error: 'telegram_bot_token and telegram_chat_id must be configured first' });
  try {
    const r = await axios.post(`https://api.telegram.org/bot${s.telegram_bot_token}/sendMessage`, {
      chat_id: s.telegram_chat_id,
      text: '✅ Plex Command Center test alert — Telegram integration is working.'
    }, { timeout: 8000 });
    if (r.data?.ok) return res.json({ success: true });
    return res.status(502).json({ error: 'Telegram API returned: ' + JSON.stringify(r.data) });
  } catch(e) {
    return res.status(502).json({ error: 'Telegram send failed: ' + e.message });
  }
});

app.get('/api/security/regional-whitelist', requireAdmin, (req, res) => {
  res.json(pccDb.prepare('SELECT * FROM regional_whitelist ORDER BY created_at DESC').all());
});

app.post('/api/security/regional-whitelist', requireAdmin, (req, res) => {
  const { ip_address, reason } = req.body || {};
  if (!ip_address) return res.status(400).json({ error: 'ip_address required' });
  pccDb.prepare("INSERT OR REPLACE INTO regional_whitelist (ip_address, reason, added_by) VALUES (?,?,?)")
    .run(String(ip_address), reason || null, req.user?.username || 'admin');
  res.json({ success: true });
});

app.delete('/api/security/regional-whitelist/:id', requireAdmin, (req, res) => {
  pccDb.prepare('DELETE FROM regional_whitelist WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.get('/api/security/alerts', requireAdmin, (req, res) => {
  const decision = req.query.decision; // 'pending' | 'allow' | 'block'
  let sql = 'SELECT * FROM region_alert_log';
  const params = [];
  if (decision && ['pending', 'allow', 'block'].includes(String(decision))) {
    sql += ' WHERE decision = ?';
    params.push(decision);
  }
  sql += ' ORDER BY created_at DESC LIMIT 200';
  res.json(pccDb.prepare(sql).all(...params));
});

// Resolve an alert from the web UI (admin panel). Telegram callbacks also funnel through here.
async function resolveAlert(alertUuid, decision, decidedBy) {
  if (!['allow', 'block'].includes(decision)) throw new Error("decision must be 'allow' or 'block'");
  const alert = pccDb.prepare("SELECT * FROM region_alert_log WHERE alert_uuid = ?").get(alertUuid);
  if (!alert) throw new Error('alert not found');
  if (alert.decision !== 'pending') return alert; // idempotent
  pccDb.prepare("UPDATE region_alert_log SET decision = ?, decided_by = ?, decided_at = datetime('now') WHERE alert_uuid = ?")
    .run(decision, decidedBy || 'system', alertUuid);
  if (decision === 'allow') {
    pccDb.prepare("INSERT OR REPLACE INTO regional_whitelist (ip_address, reason, added_by) VALUES (?,?,?)")
      .run(alert.ip_address, `Allowed via alert ${alertUuid}`, decidedBy || 'telegram');
  } else if (decision === 'block') {
    pccDb.prepare('INSERT OR REPLACE INTO blocked_entities (entity_type, entity_value, reason, blocked_by) VALUES (?,?,?,?)')
      .run('ip', alert.ip_address, `Blocked via alert ${alertUuid}`, decidedBy || 'telegram');
    await terminatePlexSessionById(alert.session_id, 'Region-blocked');
  }
  // Reflect in Telegram if the message exists
  const settings = readRegionalSettings();
  await editTelegramAlertResolution(settings, alert.telegram_message_id, decision === 'allow' ? '✅ Allowed' : '🚫 Blocked');
  return pccDb.prepare("SELECT * FROM region_alert_log WHERE alert_uuid = ?").get(alertUuid);
}

app.post('/api/security/alerts/:uuid/resolve', requireAdmin, async (req, res) => {
  try {
    const { decision } = req.body || {};
    const updated = await resolveAlert(req.params.uuid, decision, req.user?.username || 'admin');
    res.json({ success: true, alert: updated });
  } catch(e) { res.status(400).json({ error: e.message }); }
});

// Telegram webhook receiver — tied to a per-install secret in the URL so an attacker can't spam
// resolutions. Set the webhook on Telegram's side via:
//   curl -F "url=https://YOUR_HOST/api/security/telegram-webhook?secret=<s>" \
//        https://api.telegram.org/bot<TOKEN>/setWebhook
// The endpoint must be reachable from the public Internet over HTTPS.
app.post('/api/security/telegram-webhook', async (req, res) => {
  const settings = readRegionalSettings();
  const secret = req.query.secret || req.headers['x-telegram-bot-api-secret-token'] || '';
  if (!settings.telegram_webhook_secret || String(secret) !== settings.telegram_webhook_secret) {
    return res.status(403).json({ error: 'forbidden' });
  }
  try {
    const update = req.body || {};
    const cb = update.callback_query;
    if (!cb || !cb.data) return res.json({ ok: true });
    const [action, alertUuid] = String(cb.data).split(':');
    if (!alertUuid || !['allow', 'block'].includes(action)) return res.json({ ok: true });
    const tgUser = cb.from?.username || cb.from?.id || 'telegram';
    try { await resolveAlert(alertUuid, action, `tg:${tgUser}`); } catch(e) { console.warn('[REGIONAL] resolve via webhook:', e.message); }
    // ACK the callback so the spinner clears in the user's Telegram client
    try {
      await axios.post(`https://api.telegram.org/bot${settings.telegram_bot_token}/answerCallbackQuery`, {
        callback_query_id: cb.id,
        text: action === 'allow' ? 'Whitelisted' : 'Blocked'
      }, { timeout: 4000 });
    } catch(e) { /* best-effort ack */ }
    res.json({ ok: true });
  } catch(e) {
    console.warn('[REGIONAL] webhook handler error:', e.message);
    res.json({ ok: true });
  }
});

// Migration: add new columns if missing
try { pccDb.exec("ALTER TABLE auto_collection_settings ADD COLUMN seasonal_enabled INTEGER NOT NULL DEFAULT 1"); } catch(e) {}
try { pccDb.exec("ALTER TABLE auto_collection_settings ADD COLUMN max_seasonal INTEGER NOT NULL DEFAULT 1"); } catch(e) {}
// Fix old default: max_collections 5 -> 3
const curSettings = pccDb.prepare('SELECT max_collections FROM auto_collection_settings WHERE id = 1').get();
if (curSettings && curSettings.max_collections === 5) {
  pccDb.prepare('UPDATE auto_collection_settings SET max_collections = 3 WHERE id = 1').run();
}

// Get auto-collection settings
app.get('/api/plex/collections/auto/settings', (req, res) => {
  const settings = pccDb.prepare('SELECT * FROM auto_collection_settings WHERE id = 1').get();
  const active = pccDb.prepare('SELECT * FROM auto_collections ORDER BY created_at DESC').all();
  res.json({ settings, active });
});

// Update auto-collection settings
app.post('/api/plex/collections/auto/settings', (req, res) => {
  const { enabled, interval_hours, duration_hours, max_collections, pin_to_home, seasonal_enabled, max_seasonal } = req.body;
  pccDb.prepare(`
    UPDATE auto_collection_settings SET
      enabled = COALESCE(?, enabled),
      interval_hours = COALESCE(?, interval_hours),
      duration_hours = COALESCE(?, duration_hours),
      max_collections = COALESCE(?, max_collections),
      pin_to_home = COALESCE(?, pin_to_home),
      seasonal_enabled = COALESCE(?, seasonal_enabled),
      max_seasonal = COALESCE(?, max_seasonal)
    WHERE id = 1
  `).run(enabled ?? null, interval_hours ?? null, duration_hours ?? null, max_collections ?? null, pin_to_home ?? null, seasonal_enabled ?? null, max_seasonal ?? null);

  const settings = pccDb.prepare('SELECT * FROM auto_collection_settings WHERE id = 1').get();
  // Restart timer if settings changed
  scheduleAutoCollections();
  res.json({ success: true, settings });
});

// Run auto-create now (manual trigger)
app.post('/api/plex/collections/auto/run', async (req, res) => {
  try {
    const result = await runAutoCollectionCycle();
    res.json({ success: true, ...result });
  } catch (error) {
    console.error('Auto-collection run error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete a tracked auto-collection (unpin + delete from Plex + remove from DB)
app.delete('/api/plex/collections/auto/:id', async (req, res) => {
  try {
    const row = pccDb.prepare('SELECT * FROM auto_collections WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ success: false, error: 'Not found' });

    // Unpin from Plex Home
    try {
      await axios.delete(`${config.plex.url}/hubs/sections/${row.library_key}/manage`, {
        params: { 'X-Plex-Token': config.plex.token, metadataItemId: row.plex_key },
        headers: { 'Accept': 'application/json' }, timeout: 5000
      });
    } catch(e) {}

    // Delete collection from Plex
    try {
      await axios.delete(`${config.plex.url}/library/collections/${row.plex_key}`, {
        params: { 'X-Plex-Token': config.plex.token }, timeout: 5000
      });
    } catch(e) {}

    pccDb.prepare('DELETE FROM auto_collections WHERE id = ?').run(req.params.id);
    res.json({ success: true, message: `Removed "${row.title}"` });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Core: auto-create cycle
async function runAutoCollectionCycle() {
  const settings = pccDb.prepare('SELECT * FROM auto_collection_settings WHERE id = 1').get();
  const result = { created: [], expired: [], errors: [] };

  // Step 1: Clean up expired collections
  const expired = pccDb.prepare("SELECT * FROM auto_collections WHERE expires_at <= datetime('now')").all();
  for (const row of expired) {
    try {
      // Unpin
      try {
        await axios.delete(`${config.plex.url}/hubs/sections/${row.library_key}/manage`, {
          params: { 'X-Plex-Token': config.plex.token, metadataItemId: row.plex_key },
          headers: { 'Accept': 'application/json' }, timeout: 5000
        });
      } catch(e) {}
      // Delete from Plex
      await axios.delete(`${config.plex.url}/library/collections/${row.plex_key}`, {
        params: { 'X-Plex-Token': config.plex.token }, timeout: 5000
      });
      result.expired.push(row.title);
    } catch(e) {
      result.errors.push({ title: row.title, error: e.message });
    }
    pccDb.prepare('DELETE FROM auto_collections WHERE id = ?').run(row.id);
  }

  // Step 1b: Clean orphaned DB entries (Plex collection was deleted externally)
  const activeRows = pccDb.prepare("SELECT * FROM auto_collections WHERE expires_at > datetime('now')").all();
  for (const row of activeRows) {
    try {
      await axios.get(`${config.plex.url}/library/collections/${row.plex_key}`, {
        params: { 'X-Plex-Token': config.plex.token },
        headers: { 'Accept': 'application/json' }, timeout: 3000
      });
    } catch(e) {
      // Collection no longer exists in Plex — remove DB entry
      pccDb.prepare('DELETE FROM auto_collections WHERE id = ?').run(row.id);
      result.expired.push(`${row.title} (orphaned)`);
    }
  }

  // Step 2: Count active (non-expired) auto-collections
  const activeCount = pccDb.prepare("SELECT COUNT(*) as cnt FROM auto_collections WHERE expires_at > datetime('now')").get().cnt;
  const slotsAvailable = (settings.max_collections || 5) - activeCount;

  if (slotsAvailable <= 0) {
    pccDb.prepare("UPDATE auto_collection_settings SET last_run = datetime('now') WHERE id = 1").run();
    return { ...result, message: `Max collections reached (${activeCount}/${settings.max_collections})` };
  }

  // Step 3: Get fresh suggestions
  let suggestions = [];
  try {
    // Call our own suggestions engine internally
    const sugResponse = await axios.post(`http://localhost:${PORT}/api/plex/collections/suggestions`, {}, { timeout: 30000 });
    suggestions = sugResponse.data || [];
  } catch(e) {
    result.errors.push({ error: 'Failed to get suggestions: ' + e.message });
  }

  // Filter out suggestions that already have active auto-collections or existing Plex collections
  const activeTitles = new Set(
    pccDb.prepare("SELECT title FROM auto_collections WHERE expires_at > datetime('now')").all().map(r => r.title)
  );
  // Also check existing Plex collections to avoid duplicates
  let existingColTitles = new Set();
  try {
    const existingRes = await axios.get(`http://localhost:${PORT}/api/plex/collections`, { timeout: 10000 });
    existingColTitles = new Set((existingRes.data || []).map(c => c.title));
  } catch(e) {}
  suggestions = suggestions.filter(s => !activeTitles.has(s.title) && !existingColTitles.has(s.title));

  // Step 4: Create new collections — respect seasonal toggle and slot limits
  const seasonalEnabled = settings.seasonal_enabled !== 0;
  const maxSeasonal = settings.max_seasonal || 1;
  let seasonal = seasonalEnabled ? suggestions.filter(s => s.seasonal) : [];
  const personal = suggestions.filter(s => !s.seasonal);
  // Count how many active seasonal/personal we already have
  const activeSeasonal = pccDb.prepare("SELECT COUNT(*) as cnt FROM auto_collections WHERE create_type = 'seasonal' AND expires_at > datetime('now')").get().cnt;
  const seasonalSlots = Math.max(0, maxSeasonal - activeSeasonal);
  seasonal.sort((a, b) => (a.priority ?? 99) - (b.priority ?? 99));
  seasonal = seasonal.slice(0, seasonalSlots);
  const personalSlots = slotsAvailable - seasonal.length;
  const toCreate = [...seasonal, ...personal.slice(0, Math.max(0, personalSlots))];
  const globalDurationHours = settings.duration_hours || 168;
  const machineId = await getPlexMachineId();

  const createdTitles = new Set(); // Track titles created in this cycle to prevent dupes
  for (const sug of toCreate) {
    try {
      // Skip if we already created a collection with this title in this cycle
      if (createdTitles.has(sug.title)) continue;

      const libraryKey = sug.libraryKey;
      const createType = sug.createType || 'genre';
      const createValue = sug.createValue || '';
      // Seasonal collections use their own duration; personal uses global setting
      const durationHours = (sug.seasonal && sug.seasonalDurationHours) ? sug.seasonalDurationHours : globalDurationHours;

      // Build the items query. For multi-genre seasonal (e.g. "Movies for Mom" = Drama+Family)
      // and "X & Y Mix" suggestions, we pass repeated `genre=` params so Plex AND-intersects
      // server-side. Plex's section listing truncates the Genre array, so we cannot reliably
      // post-filter from it — but the server-side query handles the intersection correctly.
      const andGenres = [
        ...(Array.isArray(sug.extraGenres) ? sug.extraGenres : []),
        ...(sug.intersectGenre ? [sug.intersectGenre] : [])
      ].filter(Boolean);

      const qs = new URLSearchParams();
      qs.append('X-Plex-Token', config.plex.token);
      if (createType === 'genre' || createType === 'seasonal') {
        qs.append('genre', createValue);
        for (const g of andGenres) qs.append('genre', g);
      } else if (createType === 'actor') qs.append('actor', createValue);
      else if (createType === 'director') qs.append('director', createValue);
      else if (createType === 'studio') qs.append('studio', createValue);

      const itemsRes = await axios.get(`${config.plex.url}/library/sections/${libraryKey}/all?${qs.toString()}`, {
        headers: { 'Accept': 'application/json' }, timeout: 10000
      });
      let items = (itemsRes.data.MediaContainer.Metadata || []).slice(0, 150);
      if (items.length === 0) {
        if (andGenres.length) console.log(`[AutoCollections] "${sug.title}" — no items match all of [${[createValue, ...andGenres].join(', ')}], skipping`);
        continue;
      }

      const plexType = await getLibraryType(libraryKey);

      // Create collection with first item, then add rest one by one
      const firstUri = `server://${machineId}/com.plexapp.plugins.library/library/metadata/${items[0].ratingKey}`;
      const cParams = new URLSearchParams();
      cParams.append('X-Plex-Token', config.plex.token);
      cParams.append('type', String(plexType));
      cParams.append('title', sug.title);
      cParams.append('smart', '0');
      cParams.append('sectionId', String(libraryKey));
      cParams.append('summary', `[PCC-Auto] Auto-created collection. Expires after ${durationHours}h. Source: ${sug.sourceTitle || 'watch history'}`);
      cParams.append('uri', firstUri);

      const createRes = await axios.post(
        `${config.plex.url}/library/collections?${cParams.toString()}`,
        null,
        { headers: { 'Accept': 'application/json' }, timeout: 15000 }
      );

      // Find the new collection's ratingKey
      const newColMeta = createRes.data?.MediaContainer?.Metadata?.[0];
      let plexKey = newColMeta?.ratingKey;

      // Fallback: search collections for matching title
      if (!plexKey) {
        try {
          const colsRes = await axios.get(`${config.plex.url}/library/sections/${libraryKey}/collections`, {
            params: { 'X-Plex-Token': config.plex.token },
            headers: { 'Accept': 'application/json' }, timeout: 5000
          });
          const match = (colsRes.data.MediaContainer.Metadata || []).find(c => c.title === sug.title);
          if (match) plexKey = match.ratingKey;
        } catch(e) {}
      }

      if (!plexKey) {
        result.errors.push({ title: sug.title, error: 'Created but could not find ratingKey' });
        continue;
      }

      // Add remaining items one by one
      for (const item of items.slice(1)) {
        try {
          const addUri = `server://${machineId}/com.plexapp.plugins.library/library/metadata/${item.ratingKey}`;
          await axios.put(
            `${config.plex.url}/library/collections/${plexKey}/items?X-Plex-Token=${config.plex.token}&uri=${encodeURIComponent(addUri)}`,
            null,
            { headers: { 'Accept': 'application/json' }, timeout: 5000 }
          );
        } catch(e) {}
      }

      // Pin to home if enabled
      if (settings.pin_to_home) {
        try {
          await axios.post(`${config.plex.url}/hubs/sections/${libraryKey}/manage`, null, {
            params: { 'X-Plex-Token': config.plex.token, metadataItemId: plexKey, promotedToOwnHome: 1, promotedToRecommended: 1, promotedToSharedHome: 1 },
            headers: { 'Accept': 'application/json' }, timeout: 5000
          });
        } catch(e) {
          result.errors.push({ title: sug.title, error: 'Pin failed: ' + e.message });
        }
      }

      // Track in DB
      pccDb.prepare(`
        INSERT INTO auto_collections (plex_key, library_key, title, create_type, create_value, source_title, pinned, duration_hours, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+' || ? || ' hours'))
      `).run(String(plexKey), String(libraryKey), sug.title, createType, createValue, sug.sourceTitle || null, settings.pin_to_home ? 1 : 0, durationHours, durationHours);

      createdTitles.add(sug.title);
      result.created.push({ title: sug.title, plexKey, expiresIn: `${durationHours}h`, seasonal: !!sug.seasonal });
    } catch(e) {
      result.errors.push({ title: sug.title, error: e.message });
    }
  }

  pccDb.prepare("UPDATE auto_collection_settings SET last_run = datetime('now') WHERE id = 1").run();
  console.log(`[AutoCollections] Cycle complete: ${result.created.length} created, ${result.expired.length} expired, ${result.errors.length} errors`);
  return result;
}

// Background timer
let autoCollectionTimer = null;
function scheduleAutoCollections() {
  if (autoCollectionTimer) { clearInterval(autoCollectionTimer); autoCollectionTimer = null; }

  const settings = pccDb.prepare('SELECT * FROM auto_collection_settings WHERE id = 1').get();
  if (!settings.enabled) {
    console.log('[AutoCollections] Disabled');
    return;
  }

  const intervalMs = (settings.interval_hours || 12) * 60 * 60 * 1000;
  console.log(`[AutoCollections] Scheduled every ${settings.interval_hours || 12}h, duration ${settings.duration_hours || 168}h, max ${settings.max_collections || 5}`);

  // Run cleanup immediately on start (expired collections)
  runAutoCollectionCycle().catch(e => console.error('[AutoCollections] Startup cycle error:', e.message));

  autoCollectionTimer = setInterval(() => {
    runAutoCollectionCycle().catch(e => console.error('[AutoCollections] Timer cycle error:', e.message));
  }, intervalMs);
}

// Start on boot (delayed so server is ready)
setTimeout(() => scheduleAutoCollections(), 5000);

// Unwatched report
app.get('/api/plex/library/:key/unwatched', async (req, res) => {
  try {
    const response = await axios.get(`${config.plex.url}/library/sections/${req.params.key}/all`, {
      params: { 'X-Plex-Token': config.plex.token, unwatched: 1 },
      headers: { 'Accept': 'application/json' },
      timeout: 10000
    });

    const items = (response.data.MediaContainer.Metadata || []).map(item => ({
      title: item.title, type: item.type,
      added: new Date(item.addedAt * 1000).toISOString().split('T')[0],
      size: item.Media?.[0]?.Part?.[0]?.size || 0,
      lastWatched: item.lastViewedAt ? new Date(item.lastViewedAt * 1000).toISOString().split('T')[0] : 'Never',
      year: item.year
    }));

    res.json({ library: req.params.key, totalItems: items.length, totalSize: items.reduce((s, i) => s + i.size, 0), items });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// TAUTULLI API - FIXED
// ============================================

// Watch history with proper filters
app.get('/api/tautulli/history', async (req, res) => {
  try {
    const { user = '', length = 50, start = 0, search = '' } = req.query;

    const params = {
      apikey: config.tautulli.apiKey,
      cmd: 'get_history',
      length, start, search,
      order_column: 'date', order_dir: 'desc'
    };

    if (user && user !== 'all') params.user_id = user;

    const response = await axios.get(`${config.tautulli.url}/api/v2`, { params, timeout: 10000 });
    const data = response.data.response.data;

    if (data && data.data) {
      data.data = data.data.map(item => ({
        ...item,
        date_formatted: new Date(item.date * 1000).toLocaleString(),
        duration_formatted: formatDuration(item.duration)
      }));
    }

    res.json(data || { data: [], recordsFiltered: 0, recordsTotal: 0 });
  } catch (error) {
    console.error('History error:', error.message);
    res.json({ data: [], recordsFiltered: 0, recordsTotal: 0 });
  }
});

// Users table - top users with play counts
app.get('/api/tautulli/user-stats', async (req, res) => {
  try {
    const response = await axios.get(`${config.tautulli.url}/api/v2`, {
      params: {
        apikey: config.tautulli.apiKey,
        cmd: 'get_users_table',
        length: 25,
        order_column: 'plays',  // Tautulli uses 'plays' not 'total_plays'
        order_dir: 'desc'
      },
      timeout: 5000
    });

    const raw = response.data.response.data?.data || [];
    // Map Tautulli field names to consistent names used in frontend
    const data = raw.map(u => ({
      ...u,
      total_plays: u.plays || u.total_plays || 0,
      total_duration: u.duration || u.total_duration || 0,
      friendly_name: u.friendly_name || u.username || u.title || 'Unknown',
      last_seen: u.last_seen,
      last_played: u.last_played,
      ip_address: u.ip_address || '',
      user_thumb: u.user_thumb || ''
    }));
    res.json(data);
  } catch (error) {
    console.error('User stats error:', error.message);
    res.json([]);
  }
});

// Single user watch stats
app.get('/api/tautulli/user/:userId', async (req, res) => {
  try {
    const response = await axios.get(`${config.tautulli.url}/api/v2`, {
      params: {
        apikey: config.tautulli.apiKey,
        cmd: 'get_user',
        user_id: req.params.userId
      },
      timeout: 5000
    });
    
    const userData = response.data.response.data || {};
    
    // Check if this user is the Plex server owner (is_admin in Plex, not Tautulli)
    // The server owner in Tautulli usually has is_home_user = 1 or is the first user
    if (userData.is_home_user === 1 || userData.user_id === userData.server_id || userData.is_allow_sync === 1) {
      userData.is_plex_owner = true;
    }
    
    res.json(userData);
  } catch (error) {
    res.json({});
  }
});

// Get users list (for dropdowns)
app.get('/api/tautulli/users', async (req, res) => {
  try {
    const response = await axios.get(`${config.tautulli.url}/api/v2`, {
      params: { apikey: config.tautulli.apiKey, cmd: 'get_users' },
      timeout: 5000
    });
    res.json(response.data.response.data || []);
  } catch (error) {
    console.error('Users error:', error.message);
    res.json([]);
  }
});

// ============================================
// JELLYSEERR - FULLY FIXED
// ============================================

// Get requests - fetch media details to get title
app.get('/api/jellyseerr/requests', async (req, res) => {
  try {
    const { take = 20, skip = 0, filter = 'all' } = req.query;

    const response = await axios.get(`${config.jellyseerr.url}/api/v1/request`, {
      params: { take, skip, sort: 'added', filter },
      headers: { 'X-Api-Key': config.jellyseerr.apiKey },
      timeout: 5000
    });

    const requests = response.data.results || [];

    // Jellyseerr media object has NO title - must fetch from movie/tv endpoint
    const formatted = await Promise.all(requests.map(async r => {
      const tmdbId = r.media?.tmdbId;
      const mType = r.type === 'movie' ? 'movie' : 'tv';
      let title = '';
      let year = '';
      let posterPath = r.media?.posterPath || null;

      if (tmdbId) {
        try {
          const md = await axios.get(
            `${config.jellyseerr.url}/api/v1/${mType}/${tmdbId}`,
            { headers: { 'X-Api-Key': config.jellyseerr.apiKey }, timeout: 4000 }
          );
          const d = md.data;
          title = d.title || d.name || d.originalTitle || d.originalName || '';
          year = (d.releaseDate || d.firstAirDate || '').substring(0, 4);
          posterPath = posterPath || d.posterPath;
        } catch(e) {
          console.log(`Failed to fetch ${mType}/${tmdbId}:`, e.message);
        }
      }

      return {
        id: r.id,
        title: title || `${mType === 'movie' ? '🎬' : '📺'} TMDB #${tmdbId || r.id}`,
        year,
        requestedBy: r.requestedBy?.displayName || r.requestedBy?.username || r.modifiedBy?.displayName || r.modifiedBy?.username || (r.isAutoRequest ? 'Auto' : 'Unknown'),
        createdAt: r.createdAt,
        status: r.status === 2 ? 'approved' : r.status === 3 ? 'declined' : r.status === 4 ? 'available' : 'pending',
        type: r.type,
        posterPath: posterPath ? `https://image.tmdb.org/t/p/w185${posterPath}` : null,
        tmdbId,
        mediaStatus: r.media?.status,
        canRemove: r.canRemove !== false  // Jellyseerr provides this field
      };
    }));

    res.json(formatted);
  } catch (error) {
    console.error('Jellyseerr requests error:', error.message);
    res.json([]);
  }
});

// Search Jellyseerr
app.get('/api/jellyseerr/search', async (req, res) => {
  try {
    const { query, page = 1 } = req.query;
    if (!query) return res.json({ results: [] });

    const response = await axios.get(`${config.jellyseerr.url}/api/v1/search`, {
      params: { query, page },
      headers: { 'X-Api-Key': config.jellyseerr.apiKey },
      timeout: 5000
    });

    res.json(response.data);
  } catch (error) {
    res.json({ results: [] });
  }
});

// Request media - properly formatted for Jellyseerr
app.post('/api/jellyseerr/request', async (req, res) => {
  try {
    console.log('Jellyseerr request received:', JSON.stringify(req.body));
    const { mediaType, mediaId, tvdbId, seasons } = req.body;

    // Jellyseerr API format:
    // For movies: { mediaType: 'movie', mediaId: <tmdb_id> }
    // For TV: { mediaType: 'tv', mediaId: <tmdb_id>, seasons: 'all' or [1,2,3], tvdbId: <optional> }
    const payload = { 
      mediaType: mediaType,
      mediaId: parseInt(mediaId)  // Ensure it's a number
    };
    
    if (mediaType === 'tv') {
      payload.seasons = 'all';
      if (tvdbId) payload.tvdbId = parseInt(tvdbId);
    }
    
    console.log('Sending to Jellyseerr:', JSON.stringify(payload));
    console.log('URL:', `${config.jellyseerr.url}/api/v1/request`);

    const response = await axios.post(
      `${config.jellyseerr.url}/api/v1/request`,
      payload,
      { 
        headers: { 
          'X-Api-Key': config.jellyseerr.apiKey,
          'Content-Type': 'application/json'
        },
        timeout: 5000,
        validateStatus: (status) => status < 500  // Don't throw on 4xx
      }
    );

    console.log('Jellyseerr response status:', response.status);
    console.log('Jellyseerr response:', JSON.stringify(response.data).substring(0, 200));

    if (response.status === 200 || response.status === 201) {
      return res.json({ success: true, data: response.data });
    }

    // Non-success status - return error details
    res.status(response.status).json({ 
      success: false, 
      error: response.data?.message || `Jellyseerr returned ${response.status}`,
      details: response.data
    });
  } catch (error) {
    console.error('Jellyseerr request exception:', error.message);
    console.error('Error details:', error.response?.data || error.toString());
    res.status(500).json({ 
      success: false, 
      error: error.response?.data?.message || error.message,
      details: error.response?.data
    });
  }
});

// Approve request
app.post('/api/jellyseerr/request/:id/approve', async (req, res) => {
  try {
    const response = await axios.post(
      `${config.jellyseerr.url}/api/v1/request/${req.params.id}/approve`, {},
      { headers: { 'X-Api-Key': config.jellyseerr.apiKey }, timeout: 5000 }
    );
    res.json({ success: true, data: response.data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Decline request
app.post('/api/jellyseerr/request/:id/decline', async (req, res) => {
  try {
    const response = await axios.post(
      `${config.jellyseerr.url}/api/v1/request/${req.params.id}/decline`, {},
      { headers: { 'X-Api-Key': config.jellyseerr.apiKey }, timeout: 5000 }
    );
    res.json({ success: true, data: response.data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete request
app.delete('/api/jellyseerr/request/:id', async (req, res) => {
  try {
    const id = req.params.id;
    console.log('Deleting Jellyseerr request ID:', id);
    
    // Note: Jellyseerr may not allow deleting approved/available requests
    // The API will return 404 if request cannot be deleted
    const url = `${config.jellyseerr.url}/api/v1/request/${id}`;
    console.log('DELETE URL:', url);
    
    const response = await axios.delete(url, {
      headers: { 
        'X-Api-Key': config.jellyseerr.apiKey,
        'Content-Type': 'application/json'
      },
      timeout: 5000,
      validateStatus: (status) => status < 500 // Don't throw on 404
    });
    
    console.log('Delete response status:', response.status);
    
    if (response.status === 200 || response.status === 204) {
      return res.json({ success: true });
    }
    
    // 404 means request not found - log full response for debugging
    console.error('Delete failed:', response.status, JSON.stringify(response.data));
    res.status(response.status).json({ 
      success: false, 
      error: `Jellyseerr returned ${response.status}: ${JSON.stringify(response.data)}`,
      attempted_url: url,
      id: id
    });
  } catch (error) {
    console.error('Delete request exception:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// UTILITY & HEALTH
// ============================================

function formatDuration(seconds) {
  if (!seconds) return '0:00';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) return `${h}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  return `${m}:${String(s).padStart(2, '0')}`;
}


// ============================================
// VIRTUAL LINEAR TV
// ============================================

const LIVETV_ENABLED = process.env.LIVETV_ENABLED !== 'false';
const LIVETV_BASE_URL = process.env.LIVETV_BASE_URL || '';
const LIVETV_GUIDE_HOURS = parseInt(process.env.LIVETV_GUIDE_HOURS) || 48;
const LIVETV_FILLER_INTERVAL = parseInt(process.env.LIVETV_FILLER_INTERVAL) || 3;
const LIVETV_EPOCH = new Date('2025-01-01T00:00:00Z').getTime();

// --- Database Init ---
let db;
if (LIVETV_ENABLED) {
  const fs = require('fs');
  const dbDir = path.join(__dirname, 'data');
  if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });
  db = new Database(path.join(dbDir, 'livetv.db'));
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS channels (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      number INTEGER NOT NULL UNIQUE,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      logo_url TEXT,
      category TEXT NOT NULL DEFAULT 'general',
      source_type TEXT NOT NULL DEFAULT 'genre',
      source_value TEXT NOT NULL,
      library_key TEXT,
      enabled INTEGER NOT NULL DEFAULT 1,
      shuffle INTEGER NOT NULL DEFAULT 0,
      loop INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS programs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      plex_rating_key TEXT NOT NULL UNIQUE,
      title TEXT NOT NULL,
      type TEXT NOT NULL,
      show_title TEXT,
      season_num INTEGER,
      episode_num INTEGER,
      duration_ms INTEGER NOT NULL,
      genre TEXT,
      year INTEGER,
      thumb TEXT,
      art TEXT,
      content_rating TEXT,
      library_key TEXT NOT NULL,
      file_path TEXT,
      plex_key TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_programs_genre ON programs(genre);
    CREATE INDEX IF NOT EXISTS idx_programs_library ON programs(library_key);
    CREATE TABLE IF NOT EXISTS fillers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      plex_rating_key TEXT,
      duration_ms INTEGER NOT NULL,
      plex_key TEXT,
      weight INTEGER NOT NULL DEFAULT 1,
      channel_id INTEGER,
      enabled INTEGER NOT NULL DEFAULT 1,
      genre TEXT,
      parent_title TEXT,
      library_key TEXT,
      content_type TEXT,
      FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS channel_programming (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      channel_id INTEGER NOT NULL,
      position INTEGER NOT NULL,
      program_id INTEGER,
      filler_id INTEGER,
      duration_ms INTEGER NOT NULL,
      FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE,
      FOREIGN KEY (program_id) REFERENCES programs(id) ON DELETE CASCADE,
      FOREIGN KEY (filler_id) REFERENCES fillers(id) ON DELETE SET NULL
    );
    CREATE INDEX IF NOT EXISTS idx_cp_channel_pos ON channel_programming(channel_id, position);
    CREATE TABLE IF NOT EXISTS schedule_rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      channel_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      rule_type TEXT NOT NULL,
      start_month INTEGER,
      end_month INTEGER,
      start_hour INTEGER,
      end_hour INTEGER,
      days_of_week TEXT,
      genre_boost TEXT,
      boost_pct INTEGER NOT NULL DEFAULT 20,
      enabled INTEGER NOT NULL DEFAULT 1,
      FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS channel_logos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      channel_id INTEGER NOT NULL UNIQUE,
      mime_type TEXT NOT NULL,
      data BLOB NOT NULL,
      FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS livetv_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);
  // Migrate: add new filler columns if missing
  try {
    const cols = db.pragma('table_info(fillers)').map(c => c.name);
    if (!cols.includes('genre')) db.exec("ALTER TABLE fillers ADD COLUMN genre TEXT");
    if (!cols.includes('parent_title')) db.exec("ALTER TABLE fillers ADD COLUMN parent_title TEXT");
    if (!cols.includes('library_key')) db.exec("ALTER TABLE fillers ADD COLUMN library_key TEXT");
    if (!cols.includes('content_type')) db.exec("ALTER TABLE fillers ADD COLUMN content_type TEXT");
    if (!cols.includes('part_key')) db.exec("ALTER TABLE fillers ADD COLUMN part_key TEXT");
    if (!cols.includes('verified')) db.exec("ALTER TABLE fillers ADD COLUMN verified INTEGER DEFAULT 0");
  } catch(e) { /* columns already exist */ }

  // Migrate: add excluded_programs column to channels
  try {
    const chCols = db.pragma('table_info(channels)').map(c => c.name);
    if (!chCols.includes('excluded_programs')) {
      db.exec("ALTER TABLE channels ADD COLUMN excluded_programs TEXT DEFAULT '[]'");
    }
    if (!chCols.includes('pad_to_minutes')) {
      db.exec("ALTER TABLE channels ADD COLUMN pad_to_minutes INTEGER DEFAULT 0");
    }
    if (!chCols.includes('anchor_timeslot')) {
      db.exec("ALTER TABLE channels ADD COLUMN anchor_timeslot INTEGER DEFAULT 0");
    }
    if (!chCols.includes('skip_watched')) {
      db.exec("ALTER TABLE channels ADD COLUMN skip_watched INTEGER DEFAULT 0");
    }
    if (!chCols.includes('fallback_filler_id')) {
      db.exec("ALTER TABLE channels ADD COLUMN fallback_filler_id INTEGER");
    }
    if (!chCols.includes('shuffle_shows')) {
      db.exec("ALTER TABLE channels ADD COLUMN shuffle_shows TEXT DEFAULT '{}'");
    }
    if (!chCols.includes('offair_mode')) {
      db.exec("ALTER TABLE channels ADD COLUMN offair_mode TEXT DEFAULT 'schedule'");
    }
    if (!chCols.includes('nofiller_message')) {
      db.exec("ALTER TABLE channels ADD COLUMN nofiller_message TEXT");
    }
  } catch(e) { /* already exists */ }

  // Insert default off-air settings
  db.exec("INSERT OR IGNORE INTO livetv_settings (key, value) VALUES ('default_offair_mode', 'schedule')");
  db.exec("INSERT OR IGNORE INTO livetv_settings (key, value) VALUES ('default_nofiller_message', 'Coming up next: {title} at {time}')");
  // Subtitle settings for LiveTV. Empty language = off. Mode 'burn' burns into the video so any
  // client (Plex DVR / HDHR consumers) sees them; 'off' skips subtitle handling entirely.
  // Language is a 3-letter ISO 639-2 code (e.g. heb, eng, fre, spa).
  db.exec("INSERT OR IGNORE INTO livetv_settings (key, value) VALUES ('subtitle_language', '')");
  db.exec("INSERT OR IGNORE INTO livetv_settings (key, value) VALUES ('subtitle_mode', 'burn')");
  // Scheduling — controls how the daily rebuild rotates content. rerun_window_days excludes
  // items that aired on a channel within the last N days when there's enough pool depth.
  db.exec("INSERT OR IGNORE INTO livetv_settings (key, value) VALUES ('rerun_window_days', '7')");
  db.exec("INSERT OR IGNORE INTO livetv_settings (key, value) VALUES ('auto_rebuild_enabled', '1')");

  // channel_playlog records what each channel had in its playlist on a given day. Used by the
  // anti-rerun filter to spread movie content across days. Composite uniqueness prevents
  // duplicate rows when the same item appears multiple times in one playlist.
  db.exec(`
    CREATE TABLE IF NOT EXISTS channel_playlog (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      channel_id INTEGER NOT NULL,
      program_id INTEGER,
      filler_id INTEGER,
      aired_on TEXT NOT NULL,
      FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_playlog_channel_date ON channel_playlog(channel_id, aired_on);
    CREATE INDEX IF NOT EXISTS idx_playlog_prog ON channel_playlog(program_id);
  `);
  // channels.last_rebuilt_at tracks when each channel was last (re)built — drives the periodic
  // rebuild loop without needing to keep state in memory across restarts.
  try {
    const cols2 = db.pragma('table_info(channels)').map(c => c.name);
    if (!cols2.includes('last_rebuilt_at')) db.exec("ALTER TABLE channels ADD COLUMN last_rebuilt_at TEXT");
  } catch(e) {}

  // Migrate: add local_path to fillers for YouTube-downloaded content
  try {
    const fCols = db.pragma('table_info(fillers)').map(c => c.name);
    if (!fCols.includes('local_path')) db.exec("ALTER TABLE fillers ADD COLUMN local_path TEXT");
  } catch(e) {}

  // YouTube downloads table
  db.exec(`
    CREATE TABLE IF NOT EXISTS yt_downloads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      url TEXT NOT NULL,
      title TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      progress INTEGER DEFAULT 0,
      quality TEXT NOT NULL DEFAULT '480p',
      file_path TEXT,
      file_size_bytes INTEGER,
      duration_ms INTEGER,
      error_msg TEXT,
      filler_id INTEGER,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      completed_at TEXT,
      FOREIGN KEY (filler_id) REFERENCES fillers(id) ON DELETE SET NULL
    );
  `);


  // Migrate: add added_at column to programs
  try {
    const progCols = db.pragma('table_info(programs)').map(c => c.name);
    if (!progCols.includes('added_at')) {
      db.exec("ALTER TABLE programs ADD COLUMN added_at INTEGER");
    }
  } catch(e) { /* already exists */ }

  // Create channel_fillers junction table for per-channel filler assignment
  db.exec(`
    CREATE TABLE IF NOT EXISTS channel_fillers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      channel_id INTEGER NOT NULL,
      filler_id INTEGER NOT NULL,
      FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE,
      FOREIGN KEY (filler_id) REFERENCES fillers(id) ON DELETE CASCADE,
      UNIQUE(channel_id, filler_id)
    );
  `);

  // Add padding settings to livetv_settings
  try {
    db.exec("INSERT OR IGNORE INTO livetv_settings (key, value) VALUES ('pad_to_minutes', '30')");
    db.exec("INSERT OR IGNORE INTO livetv_settings (key, value) VALUES ('padding_enabled', '0')");
  } catch(e) { /* already exists */ }

  // Migrate: convert legacy source_type='genre' channels to JSON filter storage
  try {
    const legacyChannels = db.prepare("SELECT id, source_value, library_key FROM channels WHERE source_type = 'genre'").all();
    for (const ch of legacyChannels) {
      const filterData = JSON.stringify({
        genre: ch.source_value,
        content_type: 'all',
        genre_mode: 'primary',
        exclude_genres: []
      });
      db.prepare("UPDATE channels SET source_type = 'library', source_value = ?, updated_at = datetime('now') WHERE id = ?")
        .run(filterData, ch.id);
      console.log(`LiveTV: Migrated channel ${ch.id} from legacy genre to JSON filters`);
    }
  } catch(e) { console.error('LiveTV migration error:', e.message); }

  console.log('LiveTV database initialized');

  // Daily auto-rebuild — keeps the schedule fresh and applies the rerun filter. Runs every hour
  // and rebuilds any channel whose last_rebuilt_at is more than 24h old. Hourly polling is light
  // (a single SELECT) and is restart-safe: state lives in the DB, not in memory. Each tick also
  // runs a full Plex library scan if the last one was more than 24h ago — without this, Plex
  // re-indexing leaves stale rating keys in `programs` that cause stream 404s.
  setInterval(async () => {
    try {
      const enabled = db.prepare("SELECT value FROM livetv_settings WHERE key='auto_rebuild_enabled'").get();
      if (enabled && enabled.value === '0') return;

      const lastScan = db.prepare("SELECT value FROM livetv_settings WHERE key='last_library_scan_at'").get();
      const scanStale = !lastScan || !lastScan.value ||
        (Date.now() - new Date(lastScan.value + 'Z').getTime()) > 24 * 60 * 60 * 1000;
      if (scanStale) {
        try {
          console.log('[LiveTV] Auto-scan: refreshing Plex library…');
          const r = await scanPlexLibraries();
          db.prepare("INSERT OR REPLACE INTO livetv_settings (key, value) VALUES ('last_library_scan_at', datetime('now'))").run();
          console.log(`[LiveTV] Auto-scan complete: +${r.added} ~${r.updated} total=${r.total}`);
        } catch(e) { console.warn('[LiveTV] auto-scan failed:', e.message); }
      }

      const stale = db.prepare("SELECT id, name FROM channels WHERE enabled = 1 AND (last_rebuilt_at IS NULL OR last_rebuilt_at < datetime('now', '-24 hours'))").all();
      if (stale.length === 0) return;
      console.log(`[LiveTV] Auto-rebuild: ${stale.length} channel(s) stale, rebuilding…`);
      for (const ch of stale) {
        try { buildChannelPlaylist(ch.id); } catch(e) { console.warn(`[LiveTV] auto-rebuild failed for ch ${ch.id} (${ch.name}):`, e.message); }
      }
      _gcPlaylog();
    } catch(e) { console.warn('[LiveTV] auto-rebuild loop error:', e.message); }
  }, 60 * 60 * 1000);
}

// --- Virtual Clock Engine ---
const playlistCache = new Map();

function getPlaylistData(channelId) {
  if (playlistCache.has(channelId)) return playlistCache.get(channelId);
  const rows = db.prepare(`
    SELECT cp.position, cp.duration_ms, cp.program_id, cp.filler_id,
      p.title as prog_title, p.type as prog_type, p.show_title, p.thumb as prog_thumb,
      p.art as prog_art, p.added_at as prog_added_at,
      p.plex_rating_key as prog_rkey, p.plex_key as prog_pkey, p.genre as prog_genre,
      p.year as prog_year, p.season_num, p.episode_num, p.content_rating,
      f.name as filler_name, f.type as filler_type, f.plex_rating_key as filler_rkey, f.plex_key as filler_pkey,
      f.part_key as filler_part_key, f.verified as filler_verified, f.local_path as filler_local_path
    FROM channel_programming cp
    LEFT JOIN programs p ON cp.program_id = p.id
    LEFT JOIN fillers f ON cp.filler_id = f.id
    WHERE cp.channel_id = ?
    ORDER BY cp.position
  `).all(channelId);

  if (rows.length === 0) return null;

  const prefixSums = [0];
  let total = 0;
  for (const r of rows) {
    total += r.duration_ms;
    prefixSums.push(total);
  }
  const data = { playlist: rows, prefixSums, cycleDuration: total };
  playlistCache.set(channelId, data);
  return data;
}

function invalidatePlaylistCache(channelId) {
  if (channelId) playlistCache.delete(channelId);
  else playlistCache.clear();
}

// Track when each channel went on-air so playlist starts from beginning
const channelOnAirStart = new Map(); // channelId -> timestamp when channel last went on-air
const channelWasOnAir = new Map(); // channelId -> boolean

function getCurrentProgram(channelId, now) {
  now = now || Date.now();
  const data = getPlaylistData(channelId);
  if (!data || data.cycleDuration === 0) return null;

  // Track on-air transitions to reset playlist position
  const currentlyOnAir = isChannelOnAir(channelId);
  const wasOn = channelWasOnAir.get(channelId);
  channelWasOnAir.set(channelId, currentlyOnAir);

  if (currentlyOnAir && wasOn === false) {
    // Channel just went on-air - record start time so playlist begins from position 0
    channelOnAirStart.set(channelId, now);
    console.log(`[LiveTV] Channel ${channelId} went on-air, resetting playlist to start`);
  }

  // Use channel-specific epoch if available (set when channel goes on-air)
  const epoch = channelOnAirStart.get(channelId) || LIVETV_EPOCH;
  const elapsed = now - epoch;
  const posInCycle = ((elapsed % data.cycleDuration) + data.cycleDuration) % data.cycleDuration;

  // Binary search for the current slot
  let lo = 0, hi = data.playlist.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (data.prefixSums[mid + 1] <= posInCycle) lo = mid + 1;
    else hi = mid;
  }

  const item = data.playlist[lo];
  const offsetMs = posInCycle - data.prefixSums[lo];
  const remainingMs = item.duration_ms - offsetMs;

  return {
    item,
    offsetMs,
    remainingMs,
    positionIndex: lo,
    nextIndex: (lo + 1) % data.playlist.length,
    cyclePosition: posInCycle,
    cycleDuration: data.cycleDuration
  };
}

// Pick a specific playlist slot by position (instead of by wall-clock as getCurrentProgram does).
// Used by the stream loop to advance past a broken segment without waiting for wall-clock to catch
// up — a single 404'd movie was previously enough to lock the stream in a 5-second retry loop.
function getProgramAtPosition(channelId, posIdx) {
  const data = getPlaylistData(channelId);
  if (!data || data.cycleDuration === 0 || !data.playlist.length) return null;
  const len = data.playlist.length;
  const idx = ((posIdx % len) + len) % len;
  const item = data.playlist[idx];
  return {
    item, offsetMs: 0, remainingMs: item.duration_ms,
    positionIndex: idx, nextIndex: (idx + 1) % len,
    cyclePosition: data.prefixSums[idx] || 0, cycleDuration: data.cycleDuration
  };
}

// Find the next non-filler program in the playlist from current position
function getNextRealProgram(channelId) {
  const data = getPlaylistData(channelId);
  if (!data || data.cycleDuration === 0) return null;
  const current = getCurrentProgram(channelId);
  if (!current) return null;
  let cumulativeMs = current.remainingMs;
  for (let i = 1; i <= data.playlist.length; i++) {
    const idx = (current.positionIndex + i) % data.playlist.length;
    const item = data.playlist[idx];
    if (item.program_id) {
      return { item, startsInMs: cumulativeMs };
    }
    cumulativeMs += item.duration_ms;
  }
  return null;
}

function getBaseUrl(req) {
  if (LIVETV_BASE_URL) return LIVETV_BASE_URL;
  return `${req.protocol}://${req.get('host')}`;
}

function slugify(text) {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

// --- Library Scanner ---
// Walk every Plex library and upsert each item into the `programs` table. Returns counts.
// Extracted from the /api/livetv/scan endpoint so the auto-rebuild cron can call it too.
// Also prunes orphan rows: anything whose `updated_at` is older than this scan's start
// time wasn't touched by an upsert, meaning Plex no longer has that rating key. Those rows
// get deleted, along with any channel_programming entries pointing to them.
async function scanPlexLibraries() {
  const scanStartedAt = db.prepare("SELECT datetime('now') as ts").get().ts;
  const libRes = await axios.get(`${config.plex.url}/library/sections`, {
    params: { 'X-Plex-Token': config.plex.token },
    headers: { Accept: 'application/json' }, timeout: 10000
  });
  const libraries = libRes.data.MediaContainer.Directory || [];
  let added = 0, updated = 0;

  const upsert = db.prepare(`
    INSERT INTO programs (plex_rating_key, title, type, show_title, season_num, episode_num,
      duration_ms, genre, year, thumb, art, content_rating, library_key, file_path, plex_key, added_at, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, datetime('now'))
    ON CONFLICT(plex_rating_key) DO UPDATE SET
      title=excluded.title, duration_ms=excluded.duration_ms, genre=excluded.genre,
      year=excluded.year, thumb=excluded.thumb, art=excluded.art, content_rating=excluded.content_rating,
      file_path=excluded.file_path, added_at=COALESCE(programs.added_at, excluded.added_at), updated_at=datetime('now')
  `);

  for (const lib of libraries) {
      if (lib.type !== 'movie' && lib.type !== 'show') continue;
      console.log(`LiveTV scanning library: ${lib.title} (${lib.type})`);

      if (lib.type === 'movie') {
        const allRes = await axios.get(`${config.plex.url}/library/sections/${lib.key}/all`, {
          params: { 'X-Plex-Token': config.plex.token },
          headers: { Accept: 'application/json' }, timeout: 30000
        });
        for (const item of (allRes.data.MediaContainer.Metadata || [])) {
          const genres = (item.Genre || []).map(g => g.tag).join(',');
          const existing = db.prepare('SELECT id FROM programs WHERE plex_rating_key = ?').get(String(item.ratingKey));
          upsert.run(
            String(item.ratingKey), item.title, 'movie', null, null, null,
            item.duration || 0, genres, item.year || null,
            item.thumb || null, item.art || null, item.contentRating || null,
            lib.key, item.Media?.[0]?.Part?.[0]?.file || null,
            `/library/metadata/${item.ratingKey}`,
            item.addedAt ? item.addedAt * 1000 : null
          );
          if (existing) updated++; else added++;
        }
      } else if (lib.type === 'show') {
        const showsRes = await axios.get(`${config.plex.url}/library/sections/${lib.key}/all`, {
          params: { 'X-Plex-Token': config.plex.token },
          headers: { Accept: 'application/json' }, timeout: 30000
        });
        for (const show of (showsRes.data.MediaContainer.Metadata || [])) {
          try {
            const epsRes = await axios.get(`${config.plex.url}/library/metadata/${show.ratingKey}/allLeaves`, {
              params: { 'X-Plex-Token': config.plex.token },
              headers: { Accept: 'application/json' }, timeout: 30000
            });
            const showGenres = (show.Genre || []).map(g => g.tag).join(',');
            for (const ep of (epsRes.data.MediaContainer.Metadata || [])) {
              const existing = db.prepare('SELECT id FROM programs WHERE plex_rating_key = ?').get(String(ep.ratingKey));
              upsert.run(
                String(ep.ratingKey), ep.title, 'episode',
                ep.grandparentTitle || show.title, ep.parentIndex || null, ep.index || null,
                ep.duration || 0, showGenres, ep.year || show.year || null,
                ep.thumb || ep.grandparentThumb || null, ep.art || show.art || null,
                ep.contentRating || show.contentRating || null,
                lib.key, ep.Media?.[0]?.Part?.[0]?.file || null,
                `/library/metadata/${ep.ratingKey}`,
                ep.addedAt ? ep.addedAt * 1000 : null
              );
              if (existing) updated++; else added++;
            }
          } catch (e) {
            console.error(`Failed to scan show ${show.title}:`, e.message);
          }
        }
      }
    }

  // Prune orphans: any program row whose updated_at is older than this scan started wasn't
  // touched, so Plex no longer has that rating key. Also nuke channel_programming entries
  // referencing the deleted program rows — next channel rebuild refills them naturally.
  const pruned = db.prepare("DELETE FROM programs WHERE updated_at < ?").run(scanStartedAt).changes;
  let prunedSchedule = 0;
  if (pruned > 0) {
    prunedSchedule = db.prepare("DELETE FROM channel_programming WHERE program_id IS NOT NULL AND program_id NOT IN (SELECT id FROM programs)").run().changes;
  }
  const total = db.prepare('SELECT COUNT(*) as cnt FROM programs').get().cnt;
  console.log(`LiveTV scan complete: ${added} added, ${updated} updated, ${pruned} pruned (${prunedSchedule} schedule rows), ${total} total`);
  return { added, updated, pruned, prunedSchedule, total };
}

app.post('/api/livetv/scan', async (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  try {
    const result = await scanPlexLibraries();
    db.prepare("INSERT OR REPLACE INTO livetv_settings (key, value) VALUES ('last_library_scan_at', datetime('now'))").run();
    res.json({ success: true, ...result });
  } catch (error) {
    console.error('LiveTV scan error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/livetv/programs', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { genre, type, library, limit = 100, offset = 0 } = req.query;
  let sql = 'SELECT * FROM programs WHERE 1=1';
  const params = [];
  if (genre) { sql += ' AND genre LIKE ?'; params.push(`%${genre}%`); }
  if (type) { sql += ' AND type = ?'; params.push(type); }
  if (library) { sql += ' AND library_key = ?'; params.push(library); }
  sql += ' ORDER BY title LIMIT ? OFFSET ?';
  params.push(parseInt(limit), parseInt(offset));
  const rows = db.prepare(sql).all(...params);
  const total = db.prepare('SELECT COUNT(*) as cnt FROM programs').get().cnt;
  res.json({ programs: rows, total });
});

app.get('/api/livetv/genres', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const rows = db.prepare("SELECT DISTINCT genre FROM programs WHERE genre IS NOT NULL AND genre != ''").all();
  const genreSet = new Set();
  rows.forEach(r => r.genre.split(',').forEach(g => { if (g.trim()) genreSet.add(g.trim()); }));
  res.json([...genreSet].sort());
});

// --- Channel CRUD ---
app.get('/api/livetv/channels', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const channels = db.prepare('SELECT * FROM channels ORDER BY number').all();
  const result = channels.map(ch => {
    const progCount = db.prepare('SELECT COUNT(*) as cnt FROM channel_programming WHERE channel_id = ?').get(ch.id).cnt;
    const current = getCurrentProgram(ch.id);
    const rules = db.prepare('SELECT * FROM schedule_rules WHERE channel_id = ?').all(ch.id);
    return { ...ch, programCount: progCount, currentProgram: current, rules };
  });
  res.json(result);
});

app.post('/api/livetv/channels', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { number, name, category, source_type, source_value, library_key, shuffle, logo_url } = req.body;
  if (!number || !name || !source_value) return res.status(400).json({ error: 'number, name, and source_value required' });

  const slug = slugify(name);
  try {
    const result = db.prepare(`
      INSERT INTO channels (number, name, slug, category, source_type, source_value, library_key, shuffle, logo_url)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(number, name, slug, category || source_value, source_type || 'genre', source_value, library_key || null, shuffle ? 1 : 0, logo_url || null);

    const channelId = result.lastInsertRowid;
    buildChannelPlaylist(channelId);
    res.json({ success: true, id: channelId });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/livetv/channels/:id', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const channel = db.prepare('SELECT * FROM channels WHERE id = ?').get(req.params.id);
  if (!channel) return res.status(404).json({ error: 'Channel not found' });
  const programming = db.prepare(`
    SELECT cp.*, p.title as prog_title, p.type as prog_type, p.show_title, p.thumb as prog_thumb,
      f.name as filler_name, f.type as filler_type
    FROM channel_programming cp
    LEFT JOIN programs p ON cp.program_id = p.id
    LEFT JOIN fillers f ON cp.filler_id = f.id
    WHERE cp.channel_id = ? ORDER BY cp.position
  `).all(req.params.id);
  const rules = db.prepare('SELECT * FROM schedule_rules WHERE channel_id = ?').all(req.params.id);
  res.json({ ...channel, programming, rules, currentProgram: getCurrentProgram(channel.id) });
});

app.put('/api/livetv/channels/:id', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { name, number, category, source_type, source_value, library_key, enabled, shuffle, logo_url,
    pad_to_minutes, anchor_timeslot, skip_watched, fallback_filler_id, shuffle_shows } = req.body;
  const ch = db.prepare('SELECT * FROM channels WHERE id = ?').get(req.params.id);
  if (!ch) return res.status(404).json({ error: 'Channel not found' });

  db.prepare(`
    UPDATE channels SET name=?, number=?, slug=?, category=?, source_type=?, source_value=?,
      library_key=?, enabled=?, shuffle=?, logo_url=?,
      pad_to_minutes=?, anchor_timeslot=?, skip_watched=?, fallback_filler_id=?,
      shuffle_shows=?,
      updated_at=datetime('now')
    WHERE id=?
  `).run(
    name || ch.name, number || ch.number, slugify(name || ch.name),
    category || ch.category, source_type || ch.source_type, source_value || ch.source_value,
    library_key !== undefined ? library_key : ch.library_key,
    enabled !== undefined ? (enabled ? 1 : 0) : ch.enabled,
    shuffle !== undefined ? (shuffle ? 1 : 0) : ch.shuffle,
    logo_url !== undefined ? logo_url : ch.logo_url,
    pad_to_minutes !== undefined ? pad_to_minutes : (ch.pad_to_minutes || 0),
    anchor_timeslot !== undefined ? anchor_timeslot : (ch.anchor_timeslot || 0),
    skip_watched !== undefined ? (skip_watched ? 1 : 0) : (ch.skip_watched || 0),
    fallback_filler_id !== undefined ? fallback_filler_id : (ch.fallback_filler_id || null),
    shuffle_shows !== undefined ? (typeof shuffle_shows === 'string' ? shuffle_shows : JSON.stringify(shuffle_shows)) : (ch.shuffle_shows || '{}'),
    req.params.id
  );
  invalidatePlaylistCache(parseInt(req.params.id));
  res.json({ success: true });
});

app.delete('/api/livetv/channels/:id', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  db.prepare('DELETE FROM channels WHERE id = ?').run(req.params.id);
  invalidatePlaylistCache(parseInt(req.params.id));
  res.json({ success: true });
});

// Update channel filters and rebuild
app.put('/api/livetv/channels/:id/filters', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const ch = db.prepare('SELECT * FROM channels WHERE id = ?').get(req.params.id);
  if (!ch) return res.status(404).json({ error: 'Channel not found' });

  const { genre, content_type, year_from, year_to, genre_mode, exclude_genres, library_key, shuffle, name } = req.body;
  const filterData = JSON.stringify({
    genre: genre || 'Comedy',
    content_type: content_type || 'all',
    year_from: year_from || null,
    year_to: year_to || null,
    genre_mode: genre_mode || 'primary',
    exclude_genres: exclude_genres || []
  });

  db.prepare(`
    UPDATE channels SET name=?, source_type='library', source_value=?, library_key=?, shuffle=?, category=?, updated_at=datetime('now')
    WHERE id=?
  `).run(
    name || ch.name,
    filterData,
    library_key || null,
    shuffle !== undefined ? (shuffle ? 1 : 0) : ch.shuffle,
    genre || ch.category,
    req.params.id
  );

  const count = buildChannelPlaylist(ch.id);
  res.json({ success: true, programCount: count });
});

// Update per-show shuffle settings
app.put('/api/livetv/channels/:id/shuffle-shows', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const ch = db.prepare('SELECT * FROM channels WHERE id = ?').get(req.params.id);
  if (!ch) return res.status(404).json({ error: 'Channel not found' });

  const { shuffleShows } = req.body; // { "Show Name": "order"|"shuffle"|"random" }
  db.prepare("UPDATE channels SET shuffle_shows = ?, updated_at = datetime('now') WHERE id = ?")
    .run(JSON.stringify(shuffleShows || {}), req.params.id);

  const count = buildChannelPlaylist(ch.id);
  res.json({ success: true, programCount: count });
});

// Update excluded programs
app.put('/api/livetv/channels/:id/exclusions', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const ch = db.prepare('SELECT * FROM channels WHERE id = ?').get(req.params.id);
  if (!ch) return res.status(404).json({ error: 'Channel not found' });

  const { excluded } = req.body; // array of program IDs
  db.prepare("UPDATE channels SET excluded_programs = ?, updated_at = datetime('now') WHERE id = ?")
    .run(JSON.stringify(excluded || []), req.params.id);

  const count = buildChannelPlaylist(ch.id);
  res.json({ success: true, programCount: count });
});

// Get channel's matching programs (for edit UI)
app.get('/api/livetv/channels/:id/programs', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const ch = db.prepare('SELECT * FROM channels WHERE id = ?').get(req.params.id);
  if (!ch) return res.status(404).json({ error: 'Channel not found' });

  // Get all programs that WOULD match (before exclusions)
  let programs = [];
  if (ch.source_value && ch.source_value.startsWith('{')) {
    try {
      const filters = JSON.parse(ch.source_value);
      const { sql, params } = buildGenreQuery({
        genre: filters.genre || null,
        content_type: filters.content_type || null,
        year_from: filters.year_from || null,
        year_to: filters.year_to || null,
        genre_mode: filters.genre_mode || 'any',
        exclude_genres: filters.exclude_genres || [],
        library_key: ch.library_key || null
      });
      programs = db.prepare(sql + ' ORDER BY show_title, season_num, episode_num, title').all(...params);
    } catch(e) {}
  }

  const excluded = ch.excluded_programs ? JSON.parse(ch.excluded_programs) : [];

  // Group by show for TV, list movies individually
  const shows = {};
  const movies = [];
  for (const p of programs) {
    if (p.type === 'episode' && p.show_title) {
      if (!shows[p.show_title]) shows[p.show_title] = { name: p.show_title, episodes: [], excluded: 0, total: 0 };
      shows[p.show_title].episodes.push({ id: p.id, title: p.title, season: p.season_num, episode: p.episode_num, excluded: excluded.includes(p.id) });
      shows[p.show_title].total++;
      if (excluded.includes(p.id)) shows[p.show_title].excluded++;
    } else {
      movies.push({ id: p.id, title: p.title, year: p.year, excluded: excluded.includes(p.id) });
    }
  }

  let shuffleShows = {};
  try { shuffleShows = JSON.parse(ch.shuffle_shows || '{}'); } catch(e) {}

  res.json({
    shows: Object.values(shows).sort((a, b) => a.name.localeCompare(b.name)),
    movies: movies.sort((a, b) => a.title.localeCompare(b.title)),
    totalPrograms: programs.length,
    excludedCount: excluded.length,
    filters: ch.source_value && ch.source_value.startsWith('{') ? JSON.parse(ch.source_value) : { genre: ch.source_value },
    shuffleShows,
    channelShuffle: !!ch.shuffle
  });
});

app.post('/api/livetv/channels/:id/rebuild', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const ch = db.prepare('SELECT * FROM channels WHERE id = ?').get(req.params.id);
  if (!ch) return res.status(404).json({ error: 'Channel not found' });
  const count = buildChannelPlaylist(ch.id);
  res.json({ success: true, programCount: count });
});

// --- Playlist Builder ---
//
// Anti-rerun + daily rotation: the original implementation used a static seed (`channelId * K`)
// so the same shuffle order persisted forever, and movies in particular would appear at the same
// times every day. We now (a) fold the day-number into the seed so each rebuild produces a fresh
// order, (b) exclude items that aired on this channel in the last N days when the pool is deep
// enough, and (c) log every rebuild's contents into channel_playlog for the next exclusion.
const DAY_MS = 86_400_000;
function _todayDayNumber() { return Math.floor(Date.now() / DAY_MS); }
function _todayDateStr() { return new Date().toISOString().slice(0, 10); }

function _recentlyAiredProgramIds(channelId, days) {
  if (!days || days <= 0) return new Set();
  const cutoff = new Date(Date.now() - days * DAY_MS).toISOString().slice(0, 10);
  const rows = db.prepare("SELECT DISTINCT program_id FROM channel_playlog WHERE channel_id = ? AND program_id IS NOT NULL AND aired_on > ?").all(channelId, cutoff);
  return new Set(rows.map(r => r.program_id));
}

function _readSchedSettings() {
  let rerunDays = 7;
  try {
    const v = db.prepare("SELECT value FROM livetv_settings WHERE key='rerun_window_days'").get();
    rerunDays = Math.max(0, parseInt((v?.value ?? '7'), 10) || 0);
  } catch(e) {}
  return { rerunDays };
}

function _writePlaylogForChannel(channelId, items, dateStr) {
  if (!items || items.length === 0) return;
  const stmt = db.prepare("INSERT INTO channel_playlog (channel_id, program_id, filler_id, aired_on) VALUES (?, ?, ?, ?)");
  const tx = db.transaction((items, dateStr) => {
    for (const it of items) {
      stmt.run(channelId, it.program_id || null, it.filler_id || null, dateStr);
    }
  });
  tx(items, dateStr);
}

// Garbage-collect playlog rows older than the longest rerun window we'd ever consult.
function _gcPlaylog() {
  try {
    const cutoff = new Date(Date.now() - 60 * DAY_MS).toISOString().slice(0, 10);
    db.prepare("DELETE FROM channel_playlog WHERE aired_on < ?").run(cutoff);
  } catch(e) {}
}

function buildChannelPlaylist(channelId) {
  const channel = db.prepare('SELECT * FROM channels WHERE id = ?').get(channelId);
  if (!channel) return 0;

  // Clear existing programming
  db.prepare('DELETE FROM channel_programming WHERE channel_id = ?').run(channelId);

  // Find matching programs
  let programs = [];
  if (channel.source_type === 'library' && channel.source_value && channel.source_value.startsWith('{')) {
    // New filter-based mode: source_value is JSON with filter criteria
    try {
      const filters = JSON.parse(channel.source_value);
      const { sql, params } = buildGenreQuery({
        genre: filters.genre || null,
        content_type: filters.content_type || null,
        year_from: filters.year_from || null,
        year_to: filters.year_to || null,
        genre_mode: filters.genre_mode || 'any',
        exclude_genres: filters.exclude_genres || [],
        library_key: channel.library_key || null
      });
      programs = db.prepare(sql + ' ORDER BY title').all(...params);
    } catch(e) {
      console.error('LiveTV: Failed to parse channel filters:', e.message);
      programs = db.prepare('SELECT * FROM programs WHERE library_key = ? AND duration_ms > 0 ORDER BY title')
        .all(channel.library_key || channel.source_value);
    }
  } else if (channel.source_type === 'genre') {
    // Legacy: primary genre matching
    programs = db.prepare("SELECT * FROM programs WHERE (genre = ? OR genre LIKE ?) AND duration_ms > 0 ORDER BY title")
      .all(channel.source_value, `${channel.source_value},%`);
  } else if (channel.source_type === 'library') {
    // Legacy: library-only (no JSON filters)
    programs = db.prepare('SELECT * FROM programs WHERE library_key = ? AND duration_ms > 0 ORDER BY title')
      .all(channel.library_key || channel.source_value);
  } else {
    programs = db.prepare('SELECT * FROM programs WHERE duration_ms > 0 ORDER BY title').all();
  }

  // Apply exclusions
  const excluded = channel.excluded_programs ? JSON.parse(channel.excluded_programs) : [];
  if (excluded.length > 0) {
    programs = programs.filter(p => !excluded.includes(p.id));
  }

  // Anti-rerun: skip MOVIES that aired on this channel within the last N days. We don't apply
  // this to episodes (TV shows want to rotate through their full season list, not skip episodes
  // we just aired). We also bail out of filtering if it would leave the movie pool empty —
  // better to repeat than to have nothing to play.
  const { rerunDays } = _readSchedSettings();
  if (rerunDays > 0 && programs.length > 0) {
    const recentIds = _recentlyAiredProgramIds(channelId, rerunDays);
    if (recentIds.size > 0) {
      const movies = programs.filter(p => p.type !== 'episode');
      const episodes = programs.filter(p => p.type === 'episode');
      const moviesAfter = movies.filter(p => !recentIds.has(p.id));
      // Only apply the filter if it leaves at least 5 movies — small pools would otherwise
      // collapse to "nothing on" within a week.
      if (moviesAfter.length >= 5) {
        const removed = movies.length - moviesAfter.length;
        if (removed > 0) console.log(`[LiveTV] Channel ${channel.name}: skipping ${removed} movie(s) aired in last ${rerunDays}d (pool ${movies.length}→${moviesAfter.length})`);
        programs = episodes.concat(moviesAfter);
      } else if (movies.length > 0) {
        console.log(`[LiveTV] Channel ${channel.name}: rerun-filter would shrink movie pool to ${moviesAfter.length}, skipping filter`);
      }
    }
  }

  if (programs.length === 0) {
    invalidatePlaylistCache(channelId);
    return 0;
  }

  // Apply schedule rules (seasonal genre boost)
  const rules = db.prepare('SELECT * FROM schedule_rules WHERE channel_id = ? AND enabled = 1').all(channelId);
  const now = new Date();
  const currentMonth = now.getMonth() + 1;
  for (const rule of rules) {
    if (rule.rule_type === 'seasonal' && rule.genre_boost) {
      const inRange = rule.start_month <= rule.end_month
        ? (currentMonth >= rule.start_month && currentMonth <= rule.end_month)
        : (currentMonth >= rule.start_month || currentMonth <= rule.end_month);
      if (inRange) {
        const boostGenre = rule.genre_boost;
        const boostPct = rule.boost_pct / 100;
        const boostCount = Math.floor(programs.length * boostPct);
        const boostPrograms = db.prepare('SELECT * FROM programs WHERE genre LIKE ? AND duration_ms > 0 ORDER BY RANDOM() LIMIT ?')
          .all(`%${boostGenre}%`, boostCount);
        programs = programs.concat(boostPrograms);
      }
    }
  }

  // Per-show shuffle settings: { "Show Name": "shuffle" | "random" | "order" }
  // "order" = sequential (S01E01, S01E02...), "shuffle" = deterministic shuffle, "random" = random order
  // Channel-level shuffle=true acts as the default for shows not listed in shuffle_shows
  let shuffleShows = {};
  try { shuffleShows = JSON.parse(channel.shuffle_shows || '{}'); } catch(e) {}

  // Day-bucketed seed component — fold this into every deterministic shuffle so the rebuild
  // produces a different order each calendar day instead of the same order forever.
  const daySalt = _todayDayNumber();

  // Helper: deterministic shuffle for an array
  const deterministicShuffle = (arr, seed) => {
    const result = [...arr];
    for (let i = result.length - 1; i > 0; i--) {
      const j = Math.abs((seed * (i + 1) * 2246822519) % (i + 1));
      [result[i], result[j]] = [result[j], result[i]];
    }
    return result;
  };

  if (channel.shuffle) {
    // Default is shuffle: apply per-show overrides
    // Group episodes by show, apply show-specific settings
    const showGroups = {};
    const nonEpisodes = [];
    for (const p of programs) {
      if (p.type === 'episode' && p.show_title) {
        if (!showGroups[p.show_title]) showGroups[p.show_title] = [];
        showGroups[p.show_title].push(p);
      } else {
        nonEpisodes.push(p);
      }
    }

    // Process each show group according to its setting
    const processedShows = {};
    for (const [showName, eps] of Object.entries(showGroups)) {
      const mode = shuffleShows[showName] || 'shuffle'; // default to shuffle when channel shuffle is on
      if (mode === 'order') {
        // Keep in sequential order
        eps.sort((a, b) => {
          if ((a.season_num || 0) !== (b.season_num || 0)) return (a.season_num || 0) - (b.season_num || 0);
          return (a.episode_num || 0) - (b.episode_num || 0);
        });
        processedShows[showName] = eps;
      } else if (mode === 'random') {
        // True random (not deterministic)
        processedShows[showName] = eps.sort(() => Math.random() - 0.5);
      } else {
        // 'shuffle' - deterministic shuffle, salted with the current day so episode order rotates
        const seed = channelId * 2654435761 + showName.split('').reduce((s,c) => s + c.charCodeAt(0), 0) + daySalt;
        processedShows[showName] = deterministicShuffle(eps, seed);
      }
    }

    // Now interleave all shows + movies in shuffled order
    // Shuffle non-episodes (movies) — salted with the day so movie order rotates daily
    const seed = channelId * 2654435761 + daySalt;
    const shuffledMovies = deterministicShuffle(nonEpisodes, seed);

    // Interleave: round-robin from each show group + movies
    const showNames = Object.keys(processedShows);
    const showIdxs = {};
    showNames.forEach(s => showIdxs[s] = 0);
    let movieIdx = 0;

    // Shuffle the order shows appear
    const shuffledShowOrder = deterministicShuffle(showNames, seed + 1);

    programs = [];
    const totalItems = Object.values(processedShows).reduce((s, arr) => s + arr.length, 0) + shuffledMovies.length;
    let showOrderIdx = 0;

    for (let i = 0; i < totalItems; i++) {
      // Alternate between shows and movies
      if (shuffledShowOrder.length > 0 && (movieIdx >= shuffledMovies.length || i % 3 !== 2)) {
        // Pick next show in rotation
        let attempts = 0;
        while (attempts < shuffledShowOrder.length) {
          const show = shuffledShowOrder[showOrderIdx % shuffledShowOrder.length];
          showOrderIdx++;
          if (showIdxs[show] < processedShows[show].length) {
            programs.push(processedShows[show][showIdxs[show]]);
            showIdxs[show]++;
            break;
          }
          attempts++;
        }
        if (attempts >= shuffledShowOrder.length && movieIdx < shuffledMovies.length) {
          programs.push(shuffledMovies[movieIdx++]);
        }
      } else if (movieIdx < shuffledMovies.length) {
        programs.push(shuffledMovies[movieIdx++]);
      }
    }
  } else {
    // Default is sequential: apply per-show overrides
    // First sort everything sequentially
    programs.sort((a, b) => {
      if (a.type === 'episode' && b.type === 'episode') {
        const showCmp = (a.show_title || '').localeCompare(b.show_title || '');
        if (showCmp !== 0) return showCmp;
        if ((a.season_num || 0) !== (b.season_num || 0)) return (a.season_num || 0) - (b.season_num || 0);
        return (a.episode_num || 0) - (b.episode_num || 0);
      }
      return a.title.localeCompare(b.title);
    });

    // Apply per-show shuffle/random overrides
    const hasOverrides = Object.values(shuffleShows).some(v => v !== 'order');
    if (hasOverrides) {
      // Group by show, apply overrides, then reconstruct
      const showGroups = {};
      const result = [];
      let currentShow = null;
      let currentGroup = [];

      for (const p of programs) {
        const showKey = (p.type === 'episode' && p.show_title) ? p.show_title : null;
        if (showKey !== currentShow) {
          if (currentShow && currentGroup.length > 0) {
            const mode = shuffleShows[currentShow];
            if (mode === 'shuffle') {
              const seed = channelId * 2654435761 + currentShow.split('').reduce((s,c) => s + c.charCodeAt(0), 0) + daySalt;
              result.push(...deterministicShuffle(currentGroup, seed));
            } else if (mode === 'random') {
              result.push(...currentGroup.sort(() => Math.random() - 0.5));
            } else {
              result.push(...currentGroup);
            }
          } else if (currentGroup.length > 0) {
            result.push(...currentGroup);
          }
          currentShow = showKey;
          currentGroup = [p];
        } else {
          currentGroup.push(p);
        }
      }
      // Flush last group
      if (currentShow && currentGroup.length > 0) {
        const mode = shuffleShows[currentShow];
        if (mode === 'shuffle') {
          const seed = channelId * 2654435761 + currentShow.split('').reduce((s,c) => s + c.charCodeAt(0), 0) + daySalt;
          result.push(...deterministicShuffle(currentGroup, seed));
        } else if (mode === 'random') {
          result.push(...currentGroup.sort(() => Math.random() - 0.5));
        } else {
          result.push(...currentGroup);
        }
      } else if (currentGroup.length > 0) {
        result.push(...currentGroup);
      }
      programs = result;
    }
  }

  // Get available fillers - check per-channel assignment first, fall back to genre-matching
  const channelFillerIds = db.prepare('SELECT filler_id FROM channel_fillers WHERE channel_id = ?').all(channelId).map(r => r.filler_id);
  let fillers;

  if (channelFillerIds.length > 0) {
    // Use explicitly assigned fillers for this channel (only verified ones)
    fillers = db.prepare(`SELECT * FROM fillers WHERE id IN (${channelFillerIds.map(()=>'?').join(',')}) AND enabled = 1`).all(...channelFillerIds);
  } else {
    // Fall back to genre-matching logic
    const allFillers = db.prepare('SELECT * FROM fillers WHERE enabled = 1 AND (channel_id IS NULL OR channel_id = ?)').all(channelId);

    // Determine channel genres for matching
    const channelGenres = new Set();
    for (const p of programs.slice(0, 50)) {
      if (p.genre) p.genre.split(',').forEach(g => channelGenres.add(g.trim()));
    }

    // Split fillers into genre-matched and generic
    let matchedFillers = allFillers.filter(f => {
      if (!f.genre) return false;
      const fillerGenres = f.genre.split(',').map(g => g.trim());
      return fillerGenres.some(g => channelGenres.has(g));
    });
    // Also match content_type: movie channels get movie trailers, show channels get show trailers
    const mainType = programs.filter(p => p.type === 'episode').length > programs.length / 2 ? 'show' : 'movie';
    const typeMatched = matchedFillers.filter(f => f.content_type === mainType);
    // Use type+genre matched first, then genre matched, then all
    fillers = typeMatched.length >= 3 ? typeMatched : matchedFillers.length >= 3 ? matchedFillers : allFillers;
  }

  // Helper: select fillers to fill a time gap (greedy bin-packing)
  function selectFillersForGap(availableFillers, gapMs, maxFillers = 10) {
    if (availableFillers.length === 0 || gapMs <= 0) return { selected: [], totalMs: 0 };
    const sorted = [...availableFillers].sort((a, b) => b.duration_ms - a.duration_ms);
    const selected = [];
    let remaining = gapMs;
    for (let i = 0; i < maxFillers && remaining > 5000; i++) {
      // Find largest filler that fits
      const fit = sorted.find(f => f.duration_ms <= remaining);
      if (!fit) break;
      selected.push(fit);
      remaining -= fit.duration_ms;
    }
    return { selected, totalMs: gapMs - remaining };
  }

  // Build playlist with fillers interleaved
  const insert = db.prepare('INSERT INTO channel_programming (channel_id, position, program_id, filler_id, duration_ms) VALUES (?,?,?,?,?)');
  const padMinutes = channel.pad_to_minutes || 0;
  const anchorSlot = channel.anchor_timeslot || 0;

  const buildTx = db.transaction(() => {
    let pos = 0;
    let fillerIdx = 0;
    let cumulativeMs = 0;

    for (let i = 0; i < programs.length; i++) {
      // Insert filler using appropriate mode
      if (fillers.length > 0 && padMinutes > 0) {
        // Dynamic padding mode: pad to next time boundary after each program
        const progEnd = cumulativeMs + programs[i].duration_ms;
        const boundaryMs = padMinutes * 60000;
        const nextBoundary = Math.ceil(progEnd / boundaryMs) * boundaryMs;
        const gap = nextBoundary - progEnd;

        if (gap > 5000 && gap < boundaryMs) {
          // Fill the gap with fillers
          const { selected } = selectFillersForGap(fillers, gap);
          for (const f of selected) {
            insert.run(channelId, pos, null, f.id, f.duration_ms);
            pos++;
            cumulativeMs += f.duration_ms;
          }
        }
      } else if (fillers.length > 0 && anchorSlot > 0) {
        // Anchor timeslot mode: pad before programs to align to slot boundaries
        const slotMs = anchorSlot * 60000;
        const posInSlot = cumulativeMs % slotMs;
        if (posInSlot > 0 && i > 0) {
          const gap = slotMs - posInSlot;
          if (gap > 5000 && gap < slotMs) {
            const { selected } = selectFillersForGap(fillers, gap);
            for (const f of selected) {
              insert.run(channelId, pos, null, f.id, f.duration_ms);
              pos++;
              cumulativeMs += f.duration_ms;
            }
          }
        }
      } else if (fillers.length > 0 && i > 0 && i % LIVETV_FILLER_INTERVAL === 0) {
        // Legacy interval mode: insert filler every N programs
        const filler = fillers[fillerIdx % fillers.length];
        fillerIdx++;
        insert.run(channelId, pos, null, filler.id, filler.duration_ms);
        pos++;
        cumulativeMs += filler.duration_ms;
      }
      insert.run(channelId, pos, programs[i].id, null, programs[i].duration_ms);
      pos++;
      cumulativeMs += programs[i].duration_ms;
    }
  });
  buildTx();

  invalidatePlaylistCache(channelId);
  // Record what's in the playlist as today's playlog so future rebuilds skip these for the rerun
  // window. Then stamp last_rebuilt_at — the daily auto-rebuild loop uses this to skip channels
  // already rebuilt today.
  try {
    const items = db.prepare("SELECT program_id, filler_id FROM channel_programming WHERE channel_id = ?").all(channelId);
    _writePlaylogForChannel(channelId, items, _todayDateStr());
    db.prepare("UPDATE channels SET last_rebuilt_at = datetime('now') WHERE id = ?").run(channelId);
  } catch(e) { console.warn('[LiveTV] playlog write failed:', e.message); }
  const count = db.prepare('SELECT COUNT(*) as cnt FROM channel_programming WHERE channel_id = ?').get(channelId).cnt;
  console.log(`LiveTV: Built playlist for channel ${channel.name} with ${count} items`);
  return count;
}

// --- Genre Query Builder (shared) ---
function buildGenreQuery(opts) {
  const { genre, content_type, year_from, year_to, genre_mode, exclude_genres, library_key } = opts;
  let sql = 'SELECT * FROM programs WHERE duration_ms > 0';
  const params = [];

  if (library_key) {
    sql += ' AND library_key = ?';
    params.push(library_key);
  }

  // Genre matching mode
  if (genre) {
    if (genre_mode === 'primary') {
      // Match only when genre is the FIRST listed genre (before any comma)
      sql += " AND (genre = ? OR genre LIKE ?)";
      params.push(genre, `${genre},%`);
    } else {
      // Default: match if genre appears anywhere
      sql += ' AND genre LIKE ?';
      params.push(`%${genre}%`);
    }
  }

  // Exclude genres (filter out shows tagged with unwanted genres)
  if (exclude_genres && exclude_genres.length > 0) {
    for (const ex of exclude_genres) {
      sql += ' AND genre NOT LIKE ?';
      params.push(`%${ex}%`);
    }
  }

  if (content_type && content_type !== 'all') {
    sql += ' AND type = ?';
    params.push(content_type);
  }
  if (year_from) { sql += ' AND year >= ?'; params.push(parseInt(year_from)); }
  if (year_to) { sql += ' AND year <= ?'; params.push(parseInt(year_to)); }

  return { sql, params };
}

// --- Auto Build Channels ---
app.post('/api/livetv/auto-build', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { genre, content_type, year_from, year_to, shuffle, start_number, genre_mode, exclude_genres, library_key } = req.body;

  if (!genre) return res.status(400).json({ error: 'genre is required' });

  const { sql: baseSql, params } = buildGenreQuery({ genre, content_type, year_from, year_to, genre_mode, exclude_genres, library_key });
  let sql = baseSql;

  sql += ' ORDER BY ' + (content_type === 'episode'
    ? 'show_title, season_num, episode_num'
    : 'title');

  const programs = db.prepare(sql).all(...params);
  if (programs.length === 0) return res.json({ success: false, error: `No content found for genre "${genre}" with those filters` });

  // Find next available channel number
  const maxNum = db.prepare('SELECT MAX(number) as m FROM channels').get().m || 0;
  const channelNum = start_number ? parseInt(start_number) : maxNum + 1;

  // Check if number is taken
  const existing = db.prepare('SELECT id FROM channels WHERE number = ?').get(channelNum);
  if (existing) return res.status(400).json({ error: `Channel number ${channelNum} already exists` });

  const name = `${genre} ${content_type === 'episode' ? 'TV' : content_type === 'movie' ? 'Movies' : 'Mix'}`;
  const slug = slugify(name + '-' + channelNum);

  // Store all build filters as JSON so rebuilds preserve content_type, year range, etc.
  const filterData = JSON.stringify({
    genre,
    content_type: content_type || 'all',
    year_from: year_from || null,
    year_to: year_to || null,
    genre_mode: genre_mode || 'primary',
    exclude_genres: exclude_genres || []
  });

  try {
    const result = db.prepare(`
      INSERT INTO channels (number, name, slug, category, source_type, source_value, library_key, shuffle)
      VALUES (?, ?, ?, ?, 'library', ?, ?, ?)
    `).run(channelNum, name, slug, genre, filterData, library_key || null, shuffle ? 1 : 0);

    const channelId = result.lastInsertRowid;

    // Build playlist directly from the filtered programs
    db.prepare('DELETE FROM channel_programming WHERE channel_id = ?').run(channelId);
    const allFillers = db.prepare("SELECT * FROM fillers WHERE enabled = 1 AND (channel_id IS NULL OR channel_id = ?)").all(channelId);

    // Genre-match fillers for auto-built channels
    const chGenre = genre || '';
    const genreMatched = allFillers.filter(f => f.genre && f.genre.split(',').some(g => g.trim() === chGenre));
    const ctMatched = genreMatched.filter(f => f.content_type === (content_type === 'episode' ? 'show' : 'movie'));
    const fillers = ctMatched.length >= 3 ? ctMatched : genreMatched.length >= 3 ? genreMatched : allFillers;

    let finalPrograms = [...programs];
    if (shuffle) {
      // Day-salted seed so the auto-built channel rotates content across days like the manual one.
      const seed = channelId * 2654435761 + Math.floor(Date.now() / 86400000);
      for (let i = finalPrograms.length - 1; i > 0; i--) {
        const j = Math.abs((seed * (i + 1) * 2246822519) % (i + 1));
        [finalPrograms[i], finalPrograms[j]] = [finalPrograms[j], finalPrograms[i]];
      }
    }

    const insert = db.prepare('INSERT INTO channel_programming (channel_id, position, program_id, filler_id, duration_ms) VALUES (?,?,?,?,?)');
    const buildTx = db.transaction(() => {
      let pos = 0;
      let fillerIdx = 0;
      for (let i = 0; i < finalPrograms.length; i++) {
        if (fillers.length > 0 && i > 0 && i % LIVETV_FILLER_INTERVAL === 0) {
          const filler = fillers[fillerIdx % fillers.length];
          fillerIdx++;
          insert.run(channelId, pos, null, filler.id, filler.duration_ms);
          pos++;
        }
        insert.run(channelId, pos, finalPrograms[i].id, null, finalPrograms[i].duration_ms);
        pos++;
      }
    });
    buildTx();
    invalidatePlaylistCache(channelId);

    const count = db.prepare('SELECT COUNT(*) as cnt FROM channel_programming WHERE channel_id = ?').get(channelId).cnt;
    const totalDurationMs = db.prepare('SELECT SUM(duration_ms) as total FROM channel_programming WHERE channel_id = ?').get(channelId).total || 0;
    const totalHours = Math.round(totalDurationMs / 3600000 * 10) / 10;

    res.json({
      success: true,
      channel: { id: channelId, number: channelNum, name },
      stats: { programs: count, matchedContent: programs.length, totalHours }
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// --- Preview what auto-build would find ---
app.post('/api/livetv/auto-build/preview', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { genre, content_type, year_from, year_to, genre_mode, exclude_genres, library_key } = req.body;

  if (!genre) return res.status(400).json({ error: 'genre is required' });

  const { sql: baseSql, params } = buildGenreQuery({ genre, content_type, year_from, year_to, genre_mode, exclude_genres, library_key });
  let sql = baseSql;
  sql += ' ORDER BY show_title, season_num, episode_num, title';

  const programs = db.prepare(sql).all(...params);
  const totalMs = programs.reduce((s, p) => s + p.duration_ms, 0);

  // Group by show for TV episodes
  const shows = {};
  programs.forEach(p => {
    if (p.type === 'episode' && p.show_title) {
      if (!shows[p.show_title]) shows[p.show_title] = 0;
      shows[p.show_title]++;
    }
  });

  res.json({
    totalPrograms: programs.length,
    totalHours: Math.round(totalMs / 3600000 * 10) / 10,
    shows: Object.entries(shows).sort((a,b) => b[1] - a[1]).map(([name, count]) => ({ name, episodes: count })),
    movies: programs.filter(p => p.type === 'movie').length,
    episodes: programs.filter(p => p.type === 'episode').length,
    sample: programs.slice(0, 20).map(p => ({
      title: p.title, type: p.type, showTitle: p.show_title,
      year: p.year, duration: Math.round(p.duration_ms / 60000) + 'min'
    }))
  });
});

// --- Now Playing ---
app.get('/api/livetv/now-playing', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const channels = db.prepare('SELECT * FROM channels WHERE enabled = 1 ORDER BY number').all();
  const baseUrl = getBaseUrl(req);
  const result = channels.map(ch => {
    const onAir = isChannelEffectivelyOnAir(ch.id);
    const rules = db.prepare('SELECT * FROM schedule_rules WHERE channel_id = ?').all(ch.id);
    const nextOnAirTime = onAir ? null : getNextOnAirTime(ch.id);
    // When off-air, don't return current program info
    if (!onAir) return { channel: { id: ch.id, number: ch.number, name: ch.name, slug: ch.slug, logo_url: ch.logo_url || `${baseUrl}/api/livetv/logos/${ch.id}`, category: ch.category, rules }, current: null, next: null, onAir, nextOnAirTime };
    const current = getCurrentProgram(ch.id);
    if (!current) return { channel: { id: ch.id, number: ch.number, name: ch.name, slug: ch.slug, logo_url: ch.logo_url || `${baseUrl}/api/livetv/logos/${ch.id}`, category: ch.category, rules }, current: null, next: null, onAir, nextOnAirTime };
    const data = getPlaylistData(ch.id);
    const nextItem = data.playlist[current.nextIndex];
    return {
      channel: { id: ch.id, number: ch.number, name: ch.name, slug: ch.slug, logo_url: ch.logo_url || `${baseUrl}/api/livetv/logos/${ch.id}`, category: ch.category, rules },
      onAir,
      nextOnAirTime,
      current: {
        title: current.item.prog_title || current.item.filler_name || 'Unknown',
        type: current.item.program_id ? (current.item.prog_type || 'program') : 'filler',
        showTitle: current.item.show_title || null,
        thumb: current.item.prog_thumb ? `${config.plex.url}${current.item.prog_thumb}?X-Plex-Token=${config.plex.token}` : null,
        genre: current.item.prog_genre || null,
        year: current.item.prog_year || null,
        seasonNum: current.item.season_num || null,
        episodeNum: current.item.episode_num || null,
        ratingKey: current.item.prog_rkey || current.item.filler_rkey || null,
        durationMs: current.item.duration_ms,
        offsetMs: current.offsetMs,
        remainingMs: current.remainingMs,
        progress: Math.round((current.offsetMs / current.item.duration_ms) * 100)
      },
      next: nextItem ? {
        title: nextItem.prog_title || nextItem.filler_name || 'Unknown',
        type: nextItem.program_id ? (nextItem.prog_type || 'program') : 'filler',
        showTitle: nextItem.show_title || null
      } : null
    };
  });
  res.json(result);
});

// --- Watch Session Tracking ---
// Tracks active watch sessions with heartbeat for auto-cleanup of orphaned sessions
const watchSessions = new Map(); // sessionId/watchId -> { sessionId, channelId, channelName, title, streamType, lastHeartbeat, startedAt }

function stopPlexSession(sessionId) {
  if (!sessionId) return;
  axios.get(`${config.plex.url}/video/:/transcode/universal/stop`, {
    params: { session: sessionId, 'X-Plex-Token': config.plex.token },
    timeout: 3000
  }).catch(() => {});
}

function removeWatchSession(watchId) {
  const session = watchSessions.get(watchId);
  if (session) {
    stopPlexSession(session.sessionId);
    watchSessions.delete(watchId);
    console.log(`[LiveTV] Removed watch session ${watchId} (${session.title})`);
  }
}

// Reap stale sessions every 15 seconds (stale = no heartbeat for 30s)
const WATCH_SESSION_TIMEOUT = 30000;
setInterval(() => {
  const now = Date.now();
  for (const [watchId, session] of watchSessions) {
    if (now - session.lastHeartbeat > WATCH_SESSION_TIMEOUT) {
      console.log(`[LiveTV] Reaping stale watch session ${watchId} (${session.title}) - no heartbeat for ${Math.round((now - session.lastHeartbeat) / 1000)}s`);
      removeWatchSession(watchId);
    }
  }
}, 15000);

// List active watch sessions (must be before :channelId route)
app.get('/api/livetv/watch/sessions', (req, res) => {
  const sessions = [];
  for (const [watchId, s] of watchSessions) {
    sessions.push({
      watchId,
      channelId: s.channelId,
      channelName: s.channelName,
      channelNumber: s.channelNumber,
      title: s.title,
      showTitle: s.showTitle,
      streamType: s.streamType,
      startedAt: s.startedAt,
      lastHeartbeat: s.lastHeartbeat,
      staleSec: Math.round((Date.now() - s.lastHeartbeat) / 1000)
    });
  }
  res.json(sessions);
});

// --- Watch endpoint: returns Plex stream URL for in-app playback ---
app.get('/api/livetv/watch/:channelId', async (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const channelId = parseInt(req.params.channelId);
  const ch = db.prepare('SELECT * FROM channels WHERE id = ?').get(channelId);
  if (!ch) return res.status(404).json({ error: 'Channel not found' });

  // Enforce schedule rules - don't serve content when off air
  // Use effectivelyOnAir so a program that started during on-air time can finish
  if (!isChannelEffectivelyOnAir(channelId)) {
    const nextOn = getNextOnAirTime(channelId);
    const nextProg = getNextRealProgram(channelId);
    return res.json({
      offAir: true,
      nextOnAirTime: nextOn,
      nextProgram: nextProg ? { title: nextProg.item.prog_title, showTitle: nextProg.item.show_title } : null,
      channelName: ch.name,
      channelNumber: ch.number
    });
  }

  let current = getCurrentProgram(channelId);
  if (!current) return res.json({ offAir: true, noContent: true, channelName: ch.name, channelNumber: ch.number });

  const isFiller = !!current.item.filler_id && !current.item.program_id;
  let ratingKey = current.item.prog_rkey || current.item.filler_rkey;

  // Handle local filler (YouTube downloaded)
  if (isFiller && current.item.filler_local_path && require('fs').existsSync(current.item.filler_local_path)) {
    const offsetSec = Math.floor(current.offsetMs / 1000);
    const baseUrl = getBaseUrl(req);
    const localUrl = `${baseUrl}/fillers/${encodeURIComponent(path.basename(current.item.filler_local_path))}`;
    return res.json({
      streamUrl: localUrl, streamType: 'direct',
      title: current.item.filler_name || 'Filler', isFiller: true,
      channelId, channelName: ch.name, channelNumber: ch.number,
      offsetSec, contentType: 'filler'
    });
  }

  if (!ratingKey) return res.status(503).json({ error: 'No playable content' });

  const offsetSec = Math.floor(current.offsetMs / 1000);
  let title = current.item.prog_title || current.item.filler_name || 'Unknown';

  // Look up media info from Plex to determine best playback method
  let streamUrl, streamType = 'direct', sessionId = null;
  try {
    const metaRes = await axios.get(`${config.plex.url}/library/metadata/${ratingKey}`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { Accept: 'application/json' },
      timeout: 5000
    });
    const media = metaRes.data?.MediaContainer?.Metadata?.[0]?.Media?.[0];
    const part = media?.Part?.[0];
    const videoCodec = media?.videoCodec || '';
    const container = media?.container || '';
    const partKey = part?.key || '';

    // If this is a filler and has no playable part, skip to next non-filler program
    if (isFiller && !partKey) {
      console.log(`[LiveTV] Filler "${title}" has no playable media, skipping to next program`);
      // Find the next program in the playlist that is not this broken filler
      const data = getPlaylistData(channelId);
      if (data) {
        let nextIdx = current.nextIndex;
        let attempts = 0;
        while (attempts < data.playlist.length) {
          const nextItem = data.playlist[nextIdx];
          if (nextItem.program_id) {
            // Found a real program - use it
            ratingKey = nextItem.prog_rkey;
            title = nextItem.prog_title || 'Unknown';
            current = { ...current, item: nextItem, offsetMs: 0 };
            break;
          }
          nextIdx = (nextIdx + 1) % data.playlist.length;
          attempts++;
        }
        if (!ratingKey || attempts >= data.playlist.length) {
          const nextProg = getNextRealProgram(channelId);
          return res.json({
            noFiller: true,
            nextProgram: nextProg ? { title: nextProg.item.prog_title, showTitle: nextProg.item.show_title, startsInMs: nextProg.startsInMs } : null,
            channelName: ch.name, channelNumber: ch.number
          });
        }
      }
      // Re-fetch metadata for the replacement program
      const replaceMeta = await axios.get(`${config.plex.url}/library/metadata/${ratingKey}`, {
        params: { 'X-Plex-Token': config.plex.token },
        headers: { Accept: 'application/json' },
        timeout: 5000
      });
      const replMeta = replaceMeta.data?.MediaContainer?.Metadata?.[0];
      // Continue with the replacement program's metadata below
    }

    // Check client type from query param
    const isDesktopApp = req.query.client === 'desktop';

    // Chromium can only decode AAC, MP3, Opus, FLAC, Vorbis audio
    // AC3, EAC3, DTS, TrueHD etc. are NOT supported (licensed codecs)
    const audioCodec = (media?.audioCodec || '').toLowerCase();
    const chromiumSafeAudio = ['aac', 'mp3', 'opus', 'flac', 'vorbis'];
    const audioOk = chromiumSafeAudio.includes(audioCodec);

    // Desktop app (Electron/Chromium) can direct-play H264 and HEVC in MP4/MKV
    // Browser can only direct-play H264 in MP4/M4V/MOV
    // Both require Chromium-compatible audio
    // Direct play bypasses Plex's transcoder entirely, so it can't burn in subtitles. When the
    // user has a sub language configured we force transcode so the sub picker logic below can run.
    const _subPref = readSubtitleSettings();
    const subsRequested = !!(_subPref.language && _subPref.mode === 'burn');
    const canDirectPlay = !subsRequested && audioOk && (isDesktopApp
      ? ['h264', 'hevc', 'h265'].includes(videoCodec) && ['mp4', 'm4v', 'mov', 'mkv'].includes(container)
      : videoCodec === 'h264' && ['mp4', 'm4v', 'mov'].includes(container));

    if (canDirectPlay && partKey) {
      // Direct play - fastest, no transcoding at all
      streamUrl = `${config.plex.url}${partKey}?X-Plex-Token=${config.plex.token}`;
      streamType = 'direct';
      console.log(`LiveTV Watch: Direct play for ${title} (${videoCodec}/${container}/${audioCodec}) client=${isDesktopApp?'desktop':'browser'}`);
    } else {
      // Need transcoding - use Plex universal transcode
      sessionId = `PCC-Watch-${Date.now()}`;
      // Only allow direct stream for Chromium-safe audio; otherwise full transcode
      const chromiumAudio = ['aac', 'mp3', 'opus', 'flac', 'vorbis'];
      const audioSafe = chromiumAudio.includes((media?.audioCodec || '').toLowerCase());
      const subSettings = readSubtitleSettings();
      const subStreamId = (subSettings.language && subSettings.mode === 'burn')
        ? pickPlexSubtitleStreamId(media, subSettings.language)
        : null;
      const transcodeParams = {
        path: `/library/metadata/${ratingKey}`,
        mediaIndex: '0',
        partIndex: '0',
        protocol: 'http',
        fastSeek: '1',
        directPlay: '0',
        directStream: audioSafe ? '1' : '0',
        directStreamAudio: audioSafe ? '1' : '0',
        videoQuality: '100',
        maxVideoBitrate: '20000',
        subtitleSize: '100',
        audioBoost: '100',
        location: 'lan',
        offset: String(offsetSec),
        hasMDE: '1',
        session: sessionId,
        'X-Plex-Product': 'Plex Web',
        'X-Plex-Platform': 'Chrome',
        'X-Plex-Client-Identifier': sessionId,
        'X-Plex-Token': config.plex.token
      };
      if (subStreamId) {
        transcodeParams.subtitleStream = String(subStreamId);
        // `subtitles=burn` forces Plex to render the sub into the video frame. Without this,
        // Plex picks per-client capability and for browsers defaults to sidecar SRT — which
        // <video> can't display. Burning is the only way to guarantee subs in our web/desktop
        // player.
        transcodeParams.subtitles = 'burn';
        console.log(`LiveTV Watch: Burning '${subSettings.language}' subtitle (Plex stream id=${subStreamId}) for ${title}`);
      }
      // Call decision endpoint first to set up the transcode session (required by Plex)
      try {
        await axios.get(`${config.plex.url}/video/:/transcode/universal/decision`, {
          params: transcodeParams, headers: { Accept: 'application/json' }, timeout: 10000
        });
      } catch(de) { console.log(`LiveTV Watch: Decision call note: ${de.message}`); }
      streamUrl = `${config.plex.url}/video/:/transcode/universal/start?` + new URLSearchParams(transcodeParams).toString();
      streamType = 'transcode';
      console.log(`LiveTV Watch: Transcode for ${title} (${videoCodec}/${container}) client=${isDesktopApp?'desktop':'browser'}`);
    }
  } catch(e) {
    // If this is a filler that failed, return skipFiller flag
    if (isFiller) {
      console.log(`[LiveTV] Filler "${title}" failed to play: ${e.message}, signaling skip`);
      return res.json({ skipFiller: true, error: 'Filler not playable', channelId: ch.id, channelName: ch.name, channelNumber: ch.number });
    }
    // Fallback to full transcode if metadata lookup fails
    sessionId = `PCC-Watch-${Date.now()}`;
    const fallbackParams = {
      path: `/library/metadata/${ratingKey}`,
      mediaIndex: '0',
      partIndex: '0',
      protocol: 'http',
      fastSeek: '1',
      directPlay: '0',
      directStream: '0',
      directStreamAudio: '0',
      videoQuality: '100',
      maxVideoBitrate: '20000',
      location: 'lan',
      offset: String(offsetSec),
      session: sessionId,
      'X-Plex-Product': 'Plex Web',
      'X-Plex-Platform': 'Chrome',
      'X-Plex-Client-Identifier': sessionId,
      'X-Plex-Token': config.plex.token
    };
    // Call decision first to set up transcode session
    try {
      await axios.get(`${config.plex.url}/video/:/transcode/universal/decision`, {
        params: fallbackParams, headers: { Accept: 'application/json' }, timeout: 10000
      });
    } catch(de) {}
    streamUrl = `${config.plex.url}/video/:/transcode/universal/start?` + new URLSearchParams(fallbackParams).toString();
    streamType = 'transcode';
    console.log(`LiveTV Watch: Fallback transcode for ${title}:`, e.message);
  }

  // Generate a watchId for tracking (used for both direct and transcode sessions)
  const watchId = sessionId || `PCC-Direct-${Date.now()}`;

  // Register the watch session for heartbeat tracking
  watchSessions.set(watchId, {
    sessionId,
    channelId: ch.id,
    channelName: ch.name,
    channelNumber: ch.number,
    title,
    showTitle: current.item.show_title || null,
    streamType,
    lastHeartbeat: Date.now(),
    startedAt: Date.now()
  });
  console.log(`[LiveTV] Registered watch session ${watchId} (${title}) [${watchSessions.size} active]`);

  res.json({
    streamUrl,
    streamType,
    title,
    showTitle: current.item.show_title || null,
    seasonNum: current.item.season_num || null,
    episodeNum: current.item.episode_num || null,
    channelId: ch.id,
    channelName: ch.name,
    channelNumber: ch.number,
    offsetSec,
    sessionId,
    watchId,
    isFiller,
    contentType: current.item.program_id ? (current.item.prog_type || 'program') : 'filler'
  });
});

// Watch from Start - plays the current program from beginning (offset=0)
app.get('/api/livetv/watch/:channelId/from-start', async (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const channelId = parseInt(req.params.channelId);
  const ch = db.prepare('SELECT * FROM channels WHERE id = ?').get(channelId);
  if (!ch) return res.status(404).json({ error: 'Channel not found' });

  const current = getCurrentProgram(channelId);
  if (!current) return res.status(503).json({ error: 'No programming available' });

  const ratingKey = current.item.prog_rkey || current.item.filler_rkey;
  if (!ratingKey) return res.status(503).json({ error: 'No playable content' });

  const title = current.item.prog_title || current.item.filler_name || 'Unknown';

  // ALWAYS transcode with directStreamAudio=0 from offset 0. Direct play of the raw part URL
  // returned silent video for AC3/EAC3/DTS-encoded MKVs (which is most of the library) because
  // <video> can't decode those audio codecs. Forcing Plex to transcode audio to AAC fixes that.
  let streamUrl, streamType = 'transcode', sessionId = `PCC-WFS-${Date.now()}`;
  let media = null;
  try {
    const metaRes = await axios.get(`${config.plex.url}/library/metadata/${ratingKey}`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { Accept: 'application/json' }, timeout: 5000
    });
    media = metaRes.data?.MediaContainer?.Metadata?.[0]?.Media?.[0];
  } catch(e) { /* fall through — we can still build a transcode URL without metadata */ }

  const subSettings = readSubtitleSettings();
  const subStreamId = (subSettings.language && subSettings.mode === 'burn')
    ? pickPlexSubtitleStreamId(media, subSettings.language)
    : null;

  const params = {
    path: `/library/metadata/${ratingKey}`, mediaIndex: '0', partIndex: '0',
    protocol: 'http', fastSeek: '1',
    directPlay: '0', directStream: '1', directStreamAudio: '0',
    videoQuality: '100', maxVideoBitrate: '20000',
    subtitleSize: '100', audioBoost: '100',
    location: 'lan', offset: '0', hasMDE: '1',
    session: sessionId,
    'X-Plex-Product': 'Plex Web', 'X-Plex-Platform': 'Chrome',
    'X-Plex-Client-Identifier': sessionId, 'X-Plex-Token': config.plex.token
  };
  if (subStreamId) {
    params.subtitleStream = String(subStreamId);
    params.subtitles = 'burn';
    console.log(`[LiveTV/from-start] Burning '${subSettings.language}' subtitle (Plex stream id=${subStreamId}) for "${title}"`);
  }
  try { await axios.get(`${config.plex.url}/video/:/transcode/universal/decision`, { params, headers: { Accept: 'application/json' }, timeout: 10000 }); } catch(de) {}
  streamUrl = `${config.plex.url}/video/:/transcode/universal/start?` + new URLSearchParams(params).toString();

  const watchId = sessionId || `PCC-WFS-Direct-${Date.now()}`;
  watchSessions.set(watchId, {
    sessionId, channelId: ch.id, channelName: ch.name, channelNumber: ch.number,
    title, showTitle: current.item.show_title || null, streamType,
    lastHeartbeat: Date.now(), startedAt: Date.now()
  });

  res.json({
    streamUrl, streamType, title,
    showTitle: current.item.show_title || null,
    seasonNum: current.item.season_num || null,
    episodeNum: current.item.episode_num || null,
    channelId: ch.id, channelName: ch.name, channelNumber: ch.number,
    offsetSec: 0, sessionId, watchId, fromStart: true
  });
});

// Stop a watch session
app.post('/api/livetv/watch/stop', express.json(), (req, res) => {
  const { sessionId, watchId } = req.body;
  const id = watchId || sessionId;
  if (id) {
    removeWatchSession(id);
  } else if (sessionId) {
    stopPlexSession(sessionId);
  }
  res.json({ success: true });
});

// Heartbeat - keeps a watch session alive
app.post('/api/livetv/watch/heartbeat', express.json(), (req, res) => {
  const { watchId } = req.body;
  if (watchId && watchSessions.has(watchId)) {
    watchSessions.get(watchId).lastHeartbeat = Date.now();
    res.json({ success: true, active: watchSessions.size });
  } else {
    res.json({ success: false, error: 'Session not found' });
  }
});


// Stop ALL watch sessions
app.post('/api/livetv/watch/stop-all', (req, res) => {
  const count = watchSessions.size;
  for (const [watchId] of watchSessions) {
    removeWatchSession(watchId);
  }
  console.log(`[LiveTV] Stopped all ${count} watch sessions`);
  res.json({ success: true, stopped: count });
});

// --- EPG Guide ---
app.get('/api/livetv/guide', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const hours = parseInt(req.query.hours) || LIVETV_GUIDE_HOURS;
  const channels = db.prepare('SELECT * FROM channels WHERE enabled = 1 ORDER BY number').all();
  const now = Date.now();
  const endTime = now + hours * 3600000;
  const baseUrl = getBaseUrl(req);

  const guide = channels.map(ch => {
    const data = getPlaylistData(ch.id);
    if (!data) return { channel: { id: ch.id, number: ch.number, name: ch.name, slug: ch.slug, logo_url: ch.logo_url || `${baseUrl}/api/livetv/logos/${ch.id}`, category: ch.category }, programs: [] };

    // Get on-air ranges for this channel (respects time_block rules)
    const onAirRanges = getOnAirRanges(ch.id, now - 3600000, endTime);
    const hasTimeRules = db.prepare("SELECT COUNT(*) as cnt FROM schedule_rules WHERE channel_id = ? AND rule_type = 'time_block' AND enabled = 1").get(ch.id).cnt > 0;

    const entries = [];

    if (!hasTimeRules) {
      // No time rules — show full continuous schedule
      const startProg = getCurrentProgram(ch.id, now);
      if (startProg) {
        let idx = startProg.positionIndex;
        let currentTime = now - startProg.offsetMs;
        while (currentTime < endTime) {
          const item = data.playlist[idx];
          const startAt = currentTime;
          const stopAt = currentTime + item.duration_ms;
          if (stopAt > now - 3600000) {
            entries.push({
              start: new Date(Math.max(startAt, now - 3600000)).toISOString(),
              stop: new Date(stopAt).toISOString(),
              startMs: startAt, stopMs: stopAt,
              title: item.prog_title || item.filler_name || 'Unknown',
              type: item.program_id ? 'program' : 'filler',
              showTitle: item.show_title || null, genre: item.prog_genre || null,
              year: item.prog_year || null, seasonNum: item.season_num || null,
              episodeNum: item.episode_num || null,
              thumb: item.prog_thumb ? `${config.plex.url}${item.prog_thumb}?X-Plex-Token=${config.plex.token}` : null,
              durationMs: item.duration_ms
            });
          }
          currentTime = stopAt;
          idx = (idx + 1) % data.playlist.length;
        }
      }
    } else {
      // Has time rules — only show programs during on-air ranges, add Off Air blocks
      let lastEnd = now - 3600000;
      for (const range of onAirRanges) {
        // Add Off Air block for gap before this on-air range
        if (range.start > lastEnd) {
          entries.push({
            start: new Date(lastEnd).toISOString(),
            stop: new Date(range.start).toISOString(),
            startMs: lastEnd, stopMs: range.start,
            title: 'Off Air', type: 'offair',
            showTitle: null, genre: null, year: null,
            seasonNum: null, episodeNum: null, thumb: null,
            durationMs: range.start - lastEnd
          });
        }
        // Fill this on-air range with programs from the virtual clock
        // If the last program started during on-air time but extends past range.end,
        // show its full duration (it will be allowed to finish before going off-air)
        const progAtStart = getCurrentProgram(ch.id, range.start);
        let effectiveEnd = range.end; // may extend past range.end for overrun program
        if (progAtStart) {
          let idx = progAtStart.positionIndex;
          let currentTime = range.start - progAtStart.offsetMs;
          while (currentTime < range.end) {
            const item = data.playlist[idx];
            const startAt = Math.max(currentTime, range.start);
            const naturalStop = currentTime + item.duration_ms;
            // If program started before off-air time but extends past it, show full duration
            const stopAt = (currentTime < range.end && naturalStop > range.end)
              ? naturalStop : Math.min(naturalStop, range.end);
            if (stopAt > startAt) {
              entries.push({
                start: new Date(startAt).toISOString(),
                stop: new Date(stopAt).toISOString(),
                startMs: startAt, stopMs: stopAt,
                title: item.prog_title || item.filler_name || 'Unknown',
                type: item.program_id ? 'program' : 'filler',
                showTitle: item.show_title || null, genre: item.prog_genre || null,
                year: item.prog_year || null, seasonNum: item.season_num || null,
                episodeNum: item.episode_num || null,
                thumb: item.prog_thumb ? `${config.plex.url}${item.prog_thumb}?X-Plex-Token=${config.plex.token}` : null,
                durationMs: stopAt - startAt
              });
              if (stopAt > effectiveEnd) effectiveEnd = stopAt;
            }
            currentTime += item.duration_ms;
            idx = (idx + 1) % data.playlist.length;
          }
        }
        lastEnd = effectiveEnd;
      }
      // Add trailing Off Air block if needed
      if (lastEnd < endTime) {
        entries.push({
          start: new Date(lastEnd).toISOString(),
          stop: new Date(endTime).toISOString(),
          startMs: lastEnd, stopMs: endTime,
          title: 'Off Air', type: 'offair',
          showTitle: null, genre: null, year: null,
          seasonNum: null, episodeNum: null, thumb: null,
          durationMs: endTime - lastEnd
        });
      }
    }

    return {
      channel: { id: ch.id, number: ch.number, name: ch.name, slug: ch.slug, logo_url: ch.logo_url || `${baseUrl}/api/livetv/logos/${ch.id}`, category: ch.category },
      programs: entries
    };
  });
  res.json(guide);
});

app.get('/api/livetv/channels/:id/guide', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const ch = db.prepare('SELECT * FROM channels WHERE id = ?').get(req.params.id);
  if (!ch) return res.status(404).json({ error: 'Channel not found' });

  const hours = parseInt(req.query.hours) || 6;
  const data = getPlaylistData(ch.id);
  if (!data) return res.json([]);

  const now = Date.now();
  const endTime = now + hours * 3600000;
  const entries = [];

  const hasTimeRules = db.prepare("SELECT COUNT(*) as cnt FROM schedule_rules WHERE channel_id = ? AND rule_type = 'time_block' AND enabled = 1").get(ch.id).cnt > 0;

  if (!hasTimeRules) {
    // No time rules — show full continuous schedule
    const startProg = getCurrentProgram(ch.id, now);
    if (!startProg) return res.json([]);
    let idx = startProg.positionIndex;
    let currentTime = now - startProg.offsetMs;
    while (currentTime < endTime) {
      const item = data.playlist[idx];
      entries.push({
        start: new Date(currentTime).toISOString(),
        stop: new Date(currentTime + item.duration_ms).toISOString(),
        title: item.prog_title || item.filler_name || 'Unknown',
        type: item.program_id ? 'program' : 'filler',
        showTitle: item.show_title || null,
        durationMs: item.duration_ms
      });
      currentTime += item.duration_ms;
      idx = (idx + 1) % data.playlist.length;
    }
  } else {
    // Has time rules — only show programs during on-air ranges, add Off Air blocks
    const onAirRanges = getOnAirRanges(ch.id, now - 3600000, endTime);
    let lastEnd = now - 3600000;
    for (const range of onAirRanges) {
      if (range.start > lastEnd) {
        entries.push({
          start: new Date(lastEnd).toISOString(),
          stop: new Date(range.start).toISOString(),
          title: 'Off Air', type: 'offair',
          showTitle: null, durationMs: range.start - lastEnd
        });
      }
      const progAtStart = getCurrentProgram(ch.id, range.start);
      let effectiveEnd = range.end;
      if (progAtStart) {
        let idx = progAtStart.positionIndex;
        let currentTime = range.start - progAtStart.offsetMs;
        while (currentTime < range.end) {
          const item = data.playlist[idx];
          const startAt = Math.max(currentTime, range.start);
          const naturalStop = currentTime + item.duration_ms;
          // If program started before off-air time but extends past it, show full duration
          const stopAt = (currentTime < range.end && naturalStop > range.end)
            ? naturalStop : Math.min(naturalStop, range.end);
          if (stopAt > startAt) {
            entries.push({
              start: new Date(startAt).toISOString(),
              stop: new Date(stopAt).toISOString(),
              title: item.prog_title || item.filler_name || 'Unknown',
              type: item.program_id ? 'program' : 'filler',
              showTitle: item.show_title || null,
              durationMs: stopAt - startAt
            });
            if (stopAt > effectiveEnd) effectiveEnd = stopAt;
          }
          currentTime += item.duration_ms;
          idx = (idx + 1) % data.playlist.length;
        }
      }
      lastEnd = effectiveEnd;
    }
    if (lastEnd < endTime) {
      entries.push({
        start: new Date(lastEnd).toISOString(),
        stop: new Date(endTime).toISOString(),
        title: 'Off Air', type: 'offair',
        showTitle: null, durationMs: endTime - lastEnd
      });
    }
  }
  res.json(entries);
});

// --- HDHomeRun Emulation (matching ErsatzTV/Tunarr implementation) ---
const HDHR_DEVICE_ID = '12345678';
const HDHR_TUNER_COUNT = Math.max(1, Number(process.env.HDHR_TUNER_COUNT) || 4);

function hdhrDiscover(req) {
  const baseUrl = getBaseUrl(req);
  return {
    FriendlyName: 'PlexCommandCenter LiveTV',
    Manufacturer: 'Silicondust',
    ModelNumber: 'HDTC-2US',
    FirmwareName: 'hdhomeruntc_atsc',
    FirmwareVersion: '20170930',
    DeviceID: HDHR_DEVICE_ID,
    DeviceAuth: '',
    BaseURL: baseUrl,
    LineupURL: `${baseUrl}/lineup.json`,
    TunerCount: HDHR_TUNER_COUNT
  };
}

// Log all tuner-related requests so we can debug Plex connectivity
app.use((req, res, next) => {
  const tunerPaths = ['/discover.json', '/lineup.json', '/lineup_status.json', '/lineup.post', '/device.xml'];
  if (tunerPaths.includes(req.path) || req.path.startsWith('/api/livetv/stream')) {
    console.log(`[LiveTV-Tuner] ${req.method} ${req.url} from ${req.ip}`);
  }
  next();
});

// --- LiveTV subtitle pipeline ---
//
// Why this exists: the /api/livetv/stream/:id endpoint pipes raw MPEG-TS to Plex DVR via ffmpeg
// and historically dropped subtitle tracks (only video+audio were mapped). MPEG-TS subtitle
// passthrough is unreliable across DVR clients, so when the user opts in, we burn the matching
// language sub into the picture — that's the only way to guarantee it shows up.
function readSubtitleSettings() {
  if (!LIVETV_ENABLED || !db) return { language: '', mode: 'burn' };
  try {
    const lang = db.prepare("SELECT value FROM livetv_settings WHERE key='subtitle_language'").get();
    const mode = db.prepare("SELECT value FROM livetv_settings WHERE key='subtitle_mode'").get();
    return { language: (lang?.value || '').trim().toLowerCase(), mode: (mode?.value || 'burn').toLowerCase() };
  } catch(e) { return { language: '', mode: 'burn' }; }
}

// Cache (rkey -> { found, expiresAt }) so we don't ffprobe every program transition.
// Pick a subtitle stream's Plex `id` from the media metadata for a given 2- or 3-letter language
// code. Returns the Plex Stream id or null. This is used to drive `subtitleStream=<id>` on the
// Plex /video/:/transcode/universal/start URL so Plex burns the chosen sub into the video stream
// (the only way to get subtitles into a <video> element via Plex's direct transcode pipeline).
function pickPlexSubtitleStreamId(media, langCode) {
  if (!langCode) return null;
  const target = String(langCode).toLowerCase();
  for (const part of (media?.Part || [])) {
    for (const s of (part.Stream || [])) {
      if (s.streamType !== 3) continue; // 1=video, 2=audio, 3=subtitle
      const lang = (s.languageCode || s.language || s.languageTag || '').toLowerCase();
      if (lang === target || lang.startsWith(target) || target.startsWith(lang)) return s.id;
    }
  }
  return null;
}

// --- OpenSubtitles fallback ---
// When Plex has no native sub track in the requested language, we query opensubtitles.com,
// download a match once, and cache it on disk. Activated only when OPENSUBTITLES_API_KEY,
// OPENSUBTITLES_USERNAME, and OPENSUBTITLES_PASSWORD env vars are set; otherwise no-op.
// API docs: https://opensubtitles.stoplight.io/docs/opensubtitles-api/
const OPENSUBTITLES_API = 'https://api.opensubtitles.com/api/v1';
const SUBS_CACHE_DIR = '/app/data/subs';
const OS_USER_AGENT = 'PlexCommandCenter v3.0';
let _osTokenCache = { token: null, expiresAt: 0 };

// OpenSubtitles uses ISO 639-1 (2-letter); Plex uses 639-2 (3-letter). Map the common ones.
function osLangCode(code) {
  const map = { eng:'en', heb:'he', spa:'es', fre:'fr', fra:'fr', ger:'de', deu:'de', ita:'it',
                por:'pt', rus:'ru', jpn:'ja', chi:'zh', zho:'zh', ara:'ar', nld:'nl', dut:'nl',
                swe:'sv', nor:'no', dan:'da', fin:'fi', pol:'pl', tur:'tr', kor:'ko' };
  const c = String(code || '').toLowerCase();
  return map[c] || c.slice(0, 2);
}

async function osLogin() {
  if (_osTokenCache.token && _osTokenCache.expiresAt > Date.now()) return _osTokenCache.token;
  const { OPENSUBTITLES_API_KEY: apiKey, OPENSUBTITLES_USERNAME: u, OPENSUBTITLES_PASSWORD: p } = process.env;
  if (!apiKey || !u || !p) return null;
  const r = await axios.post(`${OPENSUBTITLES_API}/login`, { username: u, password: p },
    { headers: { 'Api-Key': apiKey, 'Content-Type': 'application/json', 'User-Agent': OS_USER_AGENT }, timeout: 10000 });
  _osTokenCache = { token: r.data.token, expiresAt: Date.now() + 23 * 3600 * 1000 };
  return _osTokenCache.token;
}

async function osSearch(program, langCode) {
  const apiKey = process.env.OPENSUBTITLES_API_KEY;
  if (!apiKey) return null;
  const params = { languages: osLangCode(langCode), query: program.show_title || program.title };
  if (program.type === 'episode') {
    params.type = 'episode';
    if (program.season_num) params.season_number = program.season_num;
    if (program.episode_num) params.episode_number = program.episode_num;
  } else {
    params.type = 'movie';
    if (program.year) params.year = program.year;
  }
  const r = await axios.get(`${OPENSUBTITLES_API}/subtitles`, {
    params, headers: { 'Api-Key': apiKey, 'User-Agent': OS_USER_AGENT, Accept: 'application/json' },
    timeout: 10000
  });
  const data = r.data?.data || [];
  if (!data.length) return null;
  data.sort((a, b) => (b.attributes?.ratings || 0) - (a.attributes?.ratings || 0));
  return data[0]?.attributes?.files?.[0]?.file_id || null;
}

async function osDownload(fileId, destPath) {
  const apiKey = process.env.OPENSUBTITLES_API_KEY;
  const token = await osLogin();
  if (!apiKey || !token) return false;
  const r = await axios.post(`${OPENSUBTITLES_API}/download`, { file_id: fileId },
    { headers: { 'Api-Key': apiKey, 'Authorization': `Bearer ${token}`, 'User-Agent': OS_USER_AGENT, 'Content-Type': 'application/json' }, timeout: 10000 });
  if (!r.data?.link) return false;
  const fileRes = await axios.get(r.data.link, { responseType: 'arraybuffer', timeout: 15000 });
  await fs.promises.mkdir(path.dirname(destPath), { recursive: true });
  await fs.promises.writeFile(destPath, Buffer.from(fileRes.data));
  console.log(`[OpenSubtitles] cached -> ${destPath} (${fileRes.data.length}b, quota remaining today: ${r.data.remaining})`);
  return true;
}

async function findOpenSubtitlesSubtitle(rkey, langCode) {
  if (!process.env.OPENSUBTITLES_API_KEY) return null;
  const destPath = `${SUBS_CACHE_DIR}/${rkey}.${osLangCode(langCode)}.srt`;
  if (fs.existsSync(destPath)) return { kind: 'external', url: destPath, codec: 'srt' };
  const program = db.prepare('SELECT * FROM programs WHERE plex_rating_key = ?').get(String(rkey));
  if (!program) return null;
  try {
    const fileId = await osSearch(program, langCode);
    if (!fileId) {
      console.log(`[OpenSubtitles] no match: "${program.show_title || program.title}" S${program.season_num || '?'}E${program.episode_num || '?'} lang=${osLangCode(langCode)}`);
      return null;
    }
    const ok = await osDownload(fileId, destPath);
    return ok ? { kind: 'external', url: destPath, codec: 'srt' } : null;
  } catch (e) {
    console.warn(`[OpenSubtitles] fetch failed for rk=${rkey}:`, e.response?.status || e.message);
    return null;
  }
}

const _subtitleProbeCache = new Map();
const SUBTITLE_PROBE_TTL_MS = 5 * 60 * 1000;
function _subtitleProbeKey(rkey, lang) { return `${rkey}|${lang}`; }
function _bumpProbeCache() {
  if (_subtitleProbeCache.size <= 200) return;
  const now = Date.now();
  for (const [k, v] of _subtitleProbeCache) {
    if (v.expiresAt < now) _subtitleProbeCache.delete(k);
  }
}

// findPlexSubtitleStream: ffprobes the Plex media URL for subtitle streams whose language tag
// matches `langCode`. Returns one of:
//   { kind: 'embedded', relIdx, codec }   — embedded sub at the given subtitle-relative index
//   { kind: 'external', url, codec }      — external sidecar (e.g. .srt) reachable as a URL
//   null                                   — no match
// We try ffprobe first (cheap, no extra HTTP) and fall back to Plex metadata when ffprobe sees
// nothing — that covers the common AVI-with-sidecar-SRT case where the video file itself has
// no embedded sub tracks but Plex knows about a companion .srt in the same folder.
async function findPlexSubtitleStream(rkey, fileUrl, langCode) {
  if (!langCode) return null;
  const cacheKey = _subtitleProbeKey(rkey, langCode);
  const cached = _subtitleProbeCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) return cached.found;

  let result = null;
  const target = String(langCode).toLowerCase();

  // 1) ffprobe of the video URL — finds EMBEDDED subs only.
  const r = spawnSync('ffprobe', [
    '-v', 'error', '-select_streams', 's',
    '-show_entries', 'stream=index,codec_name:stream_tags=language',
    '-of', 'json', fileUrl
  ], { timeout: 10000, maxBuffer: 2 * 1024 * 1024 });
  if (!r.error && r.status === 0) {
    try {
      const parsed = JSON.parse((r.stdout || '').toString());
      const streams = Array.isArray(parsed.streams) ? parsed.streams : [];
      for (let i = 0; i < streams.length; i++) {
        const s = streams[i];
        const lang = (s.tags && (s.tags.language || s.tags.LANGUAGE)) || '';
        if (String(lang).toLowerCase() === target) {
          result = { kind: 'embedded', relIdx: i, codec: s.codec_name || 'unknown' };
          break;
        }
      }
    } catch(e) { /* ignore parse errors */ }
  }

  // 2) Fallback: Plex metadata. Catches external sidecar SRTs that ffprobe of the video can't see.
  if (!result) {
    try {
      const metaRes = await axios.get(`${config.plex.url}/library/metadata/${rkey}`, {
        params: { 'X-Plex-Token': config.plex.token },
        headers: { Accept: 'application/json' }, timeout: 5000
      });
      const media = metaRes.data?.MediaContainer?.Metadata?.[0]?.Media?.[0];
      for (const part of (media?.Part || [])) {
        for (const s of (part.Stream || [])) {
          if (s.streamType !== 3) continue;
          const lang = (s.languageCode || s.language || '').toLowerCase();
          if (lang !== target && !lang.startsWith(target) && !target.startsWith(lang)) continue;
          // External streams have a `key` like `/library/streams/<id>`; embedded ones don't.
          // For embedded matches we still need ffmpeg's si= index, but since ffprobe didn't find
          // one above, treating it as external+key won't make matters worse.
          if (s.key) {
            const url = `${config.plex.url}${s.key}?X-Plex-Token=${config.plex.token}`;
            result = { kind: 'external', url, codec: (s.codec || s.format || 'srt').toLowerCase() };
            break;
          }
        }
        if (result) break;
      }
    } catch(e) { /* ignore — fall through with result=null */ }
  }

  // 3) Final fallback: OpenSubtitles (only if env keys configured). Caches SRT to disk so
  // re-airs of the same episode are instant.
  if (!result) {
    result = await findOpenSubtitlesSubtitle(rkey, langCode);
  }

  _subtitleProbeCache.set(cacheKey, { found: result, expiresAt: Date.now() + SUBTITLE_PROBE_TTL_MS });
  _bumpProbeCache();
  return result;
}

// Subset of subtitle codecs that are *text-based*. These render via the `subtitles` filter cleanly.
// Bitmap codecs (PGS / DVD / DVB) need overlay filters which add complexity — we treat those as
// not-burnable for now and skip them (returning null lets the stream fall back to no subs).
const TEXT_SUB_CODECS = new Set(['mov_text', 'subrip', 'srt', 'ass', 'ssa', 'webvtt']);
const BITMAP_SUB_CODECS = new Set(['hdmv_pgs_subtitle', 'dvd_subtitle', 'dvb_subtitle', 'pgssub']);

// Build the ffmpeg burn-in arguments for a given matched subtitle stream. Returns:
//   { vfArgs: ['-vf', 'subtitles=...'], forceTranscode: true } if burnable
//   null otherwise
function buildSubtitleBurnArgs(fileUrl, sub) {
  if (!sub) return null;
  if (BITMAP_SUB_CODECS.has(sub.codec)) {
    console.log(`[LiveTV] Subtitle stream is bitmap (${sub.codec}); skipping burn-in.`);
    return null;
  }
  if (!TEXT_SUB_CODECS.has(sub.codec)) {
    console.log(`[LiveTV] Subtitle stream codec '${sub.codec}' isn't in the known-text list; trying burn-in anyway.`);
  }
  // ffmpeg's `subtitles` filter takes a file/URL and optional stream index. For embedded we use
  // `si=<rel>` to select the Nth subtitle stream of the input. For external (sidecar SRTs Plex
  // serves at /library/streams/<id>) the file is single-track so no si= is needed.
  let filterValue;
  if (sub.kind === 'external') {
    filterValue = `subtitles='${sub.url}'`;
  } else {
    filterValue = `subtitles='${fileUrl}':si=${sub.relIdx}`;
  }
  return { vfArgs: ['-vf', filterValue], forceTranscode: true };
}

app.get('/discover.json', (req, res) => {
  res.json(hdhrDiscover(req));
});

app.get('/lineup_status.json', (req, res) => {
  res.json({
    ScanInProgress: 0,
    ScanPossible: 1,
    Source: 'Cable',
    SourceList: ['Cable']
  });
});

app.get('/lineup.json', (req, res) => {
  if (!LIVETV_ENABLED) return res.json([]);
  // Plex DVR caches the lineup and re-fetches infrequently. If we omit off-air channels here,
  // they vanish from the DVR's channel list entirely until the next refresh — a channel that
  // only airs evenings would never show up unless the user happened to scan at the right hour.
  // We list every enabled channel; the /api/livetv/stream/<id>.ts endpoint already plays an
  // off-air screen for channels outside their schedule, so tuning still does something sensible.
  const channels = db.prepare('SELECT * FROM channels WHERE enabled = 1 ORDER BY number').all();
  const baseUrl = getBaseUrl(req);
  const lineup = channels.map(ch => ({
    GuideNumber: String(ch.number),
    GuideName: ch.name,
    URL: `${baseUrl}/api/livetv/stream/${ch.id}.ts`
  }));
  res.json(lineup);
});

app.post('/lineup.post', (req, res) => {
  res.sendStatus(200);
});

app.get('/device.xml', (req, res) => {
  const baseUrl = getBaseUrl(req);
  const xml = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <URLBase>${escapeXml(baseUrl)}</URLBase>
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>
    <friendlyName>PlexCommandCenter LiveTV</friendlyName>
    <manufacturer>Silicondust</manufacturer>
    <modelName>HDTC-2US</modelName>
    <modelNumber>HDTC-2US</modelNumber>
    <serialNumber>${HDHR_DEVICE_ID}</serialNumber>
    <UDN>uuid:${HDHR_DEVICE_ID}-PCC-LiveTV</UDN>
  </device>
</root>`;
  res.set('Content-Type', 'application/xml');
  res.send(xml);
});

app.get('/api/livetv/discover', (req, res) => {
  res.json(hdhrDiscover(req));
});

// --- M3U Generator ---
app.get('/api/livetv/m3u', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const channels = db.prepare('SELECT * FROM channels WHERE enabled = 1 ORDER BY number').all();
  const baseUrl = getBaseUrl(req);

  let m3u = '#EXTM3U\n';
  for (const ch of channels) {
    const logoUrl = ch.logo_url || `${baseUrl}/api/livetv/logos/${ch.id}`;
    let groupTitle = ch.category || 'General';
    try { const parsed = JSON.parse(groupTitle); groupTitle = parsed.genre || 'General'; } catch(e) {}
    const safeName = ch.name.replace(/,/g, ' ');
    m3u += `#EXTINF:-1 tvg-id="ch-${ch.number}" tvg-name="${safeName}" tvg-logo="${logoUrl}" group-title="${groupTitle}",${safeName}\n`;
    m3u += `${baseUrl}/api/livetv/stream/${ch.id}.ts\n`;
  }

  res.set('Content-Type', 'application/x-mpegurl');
  res.set('Content-Disposition', 'attachment; filename="livetv.m3u"');
  res.send(m3u);
});

// --- XMLTV Generator ---
app.get('/api/livetv/xmltv', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const channels = db.prepare('SELECT * FROM channels WHERE enabled = 1 ORDER BY number').all();
  const baseUrl = getBaseUrl(req);
  const hours = parseInt(req.query.hours) || LIVETV_GUIDE_HOURS;
  const now = Date.now();
  const endTime = now + hours * 3600000;

  const xmlDate = (ms) => {
    const d = new Date(ms);
    return d.toISOString().replace(/[-:T]/g, '').replace(/\.\d+Z/, ' +0000');
  };

  let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
  xml += '<tv generator-info-name="PlexCommandCenter-LiveTV">\n';

  // Channel definitions
  for (const ch of channels) {
    const logoUrl = ch.logo_url || `${baseUrl}/api/livetv/logos/${ch.id}`;
    xml += `  <channel id="ch-${ch.number}">\n`;
    xml += `    <display-name>${escapeXml(ch.name)}</display-name>\n`;
    xml += `    <icon src="${escapeXml(logoUrl)}"/>\n`;
    xml += `  </channel>\n`;
  }

  // Programme listings
  for (const ch of channels) {
    const data = getPlaylistData(ch.id);
    if (!data) continue;
    const startProg = getCurrentProgram(ch.id, now);
    if (!startProg) continue;

    let idx = startProg.positionIndex;
    let currentTime = now - startProg.offsetMs;

    while (currentTime < endTime) {
      const item = data.playlist[idx];
      const startAt = currentTime;
      const stopAt = currentTime + item.duration_ms;

      if (stopAt > now) {
        const showName = item.show_title || item.prog_title || item.filler_name || 'Programming';
        const epTitle = item.show_title ? (item.prog_title || '') : '';
        const sNum = item.season_num;
        const eNum = item.episode_num;
        xml += `  <programme start="${xmlDate(startAt)}" stop="${xmlDate(stopAt)}" channel="ch-${ch.number}">\n`;
        xml += `    <title>${escapeXml(showName)}</title>\n`;
        if (epTitle) {
          // Enhanced sub-title with episode numbering
          const epLabel = (sNum && eNum) ? `S${String(sNum).padStart(2,'0')}E${String(eNum).padStart(2,'0')} - ${epTitle}` : epTitle;
          xml += `    <sub-title>${escapeXml(epLabel)}</sub-title>\n`;
        }
        if (item.prog_thumb) {
          const thumbUrl = `${config.plex.url}${item.prog_thumb}?X-Plex-Token=${config.plex.token}`;
          xml += `    <icon src="${escapeXml(thumbUrl)}"/>\n`;
        }
        if (item.prog_art) {
          const artUrl = `${config.plex.url}${item.prog_art}?X-Plex-Token=${config.plex.token}`;
          xml += `    <icon src="${escapeXml(artUrl)}"/>\n`;
        }
        if (item.prog_genre) xml += `    <category>${escapeXml(item.prog_genre.split(',')[0])}</category>\n`;
        if (item.prog_year) xml += `    <date>${item.prog_year}</date>\n`;
        if (sNum && eNum) {
          xml += `    <episode-num system="onscreen">S${String(sNum).padStart(2,'0')}E${String(eNum).padStart(2,'0')}</episode-num>\n`;
          // xmltv_ns format: season-1.episode-1. (0-indexed)
          xml += `    <episode-num system="xmltv_ns">${sNum - 1}.${eNum - 1}.</episode-num>\n`;
        }
        // "New" tag for recently added content (within 7 days)
        if (item.prog_added_at && (now - item.prog_added_at) < 7 * 86400000) {
          xml += `    <new />\n`;
        }
        if (item.content_rating) {
          xml += `    <rating><value>${escapeXml(item.content_rating)}</value></rating>\n`;
        }
        xml += `    <length units="minutes">${Math.round(item.duration_ms / 60000)}</length>\n`;
        xml += `  </programme>\n`;
      }
      currentTime = stopAt;
      idx = (idx + 1) % data.playlist.length;
    }
  }

  xml += '</tv>\n';
  res.set('Content-Type', 'text/xml');
  res.set('Content-Disposition', 'inline; filename="xmltv.xml"');
  res.send(xml);
});

// Alias with .xml extension for Plex compatibility
app.get('/api/livetv/xmltv.xml', (req, res) => {
  // Forward to the main xmltv handler
  req.url = '/api/livetv/xmltv';
  app.handle(req, res);
});

function escapeXml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

// --- Channel On/Off Air Scheduling ---
function isChannelOnAir(channelId, atTime) {
  if (!db) return true;
  const rules = db.prepare("SELECT * FROM schedule_rules WHERE channel_id = ? AND rule_type = 'time_block' AND enabled = 1").all(channelId);
  if (rules.length === 0) return true; // no rules = always on
  const d = atTime ? new Date(atTime) : new Date();
  const hour = d.getHours();
  const day = d.getDay(); // 0=Sun
  for (const rule of rules) {
    const days = rule.days_of_week ? rule.days_of_week.split(',').map(Number) : [0,1,2,3,4,5,6];
    if (!days.includes(day)) continue;
    if (rule.start_hour <= rule.end_hour) {
      if (hour >= rule.start_hour && hour < rule.end_hour) return true;
    } else {
      // Overnight: e.g., 22-6 means 22,23,0,1,2,3,4,5
      if (hour >= rule.start_hour || hour < rule.end_hour) return true;
    }
  }
  return false; // has time rules but none match now
}

// Check if channel is effectively on-air, allowing a currently-playing program
// that started during on-air time to finish before going off-air.
function isChannelEffectivelyOnAir(channelId) {
  if (isChannelOnAir(channelId)) return true;

  // Channel is technically off-air — check if a program started during on-air time
  // and hasn't finished yet (so we let it complete instead of cutting mid-content)
  try {
    const current = getCurrentProgram(channelId);
    if (!current || !current.offsetMs || current.offsetMs <= 0) return false;

    // When did this program start in real time?
    const programStartTime = Date.now() - current.offsetMs;
    return isChannelOnAir(channelId, programStartTime);
  } catch (e) {
    return false;
  }
}

// Get the next on-air time for a channel (looks ahead up to 7 days)
function getNextOnAirTime(channelId) {
  if (!db) return null;
  const rules = db.prepare("SELECT * FROM schedule_rules WHERE channel_id = ? AND rule_type = 'time_block' AND enabled = 1").all(channelId);
  if (rules.length === 0) return null; // always on
  const now = new Date();
  // Check each hour for the next 7 days
  for (let offset = 1; offset <= 168; offset++) {
    const t = new Date(now.getTime() + offset * 3600000);
    t.setMinutes(0, 0, 0);
    const hour = t.getHours();
    const day = t.getDay();
    for (const rule of rules) {
      const days = rule.days_of_week ? rule.days_of_week.split(',').map(Number) : [0,1,2,3,4,5,6];
      if (!days.includes(day)) continue;
      if (rule.start_hour <= rule.end_hour) {
        if (hour >= rule.start_hour && hour < rule.end_hour) return t.toISOString();
      } else {
        if (hour >= rule.start_hour || hour < rule.end_hour) return t.toISOString();
      }
    }
  }
  return null;
}

// Get the on-air time ranges for a channel within a time window
function getOnAirRanges(channelId, startMs, endMs) {
  const rules = db.prepare("SELECT * FROM schedule_rules WHERE channel_id = ? AND rule_type = 'time_block' AND enabled = 1").all(channelId);
  if (rules.length === 0) return [{ start: startMs, end: endMs }]; // no rules = always on

  const ranges = [];
  // Walk hour by hour through the time window
  let t = new Date(startMs);
  t.setMinutes(0, 0, 0); // snap to start of hour
  let rangeStart = null;

  while (t.getTime() < endMs) {
    const hour = t.getHours();
    const day = t.getDay();
    let onAir = false;
    for (const rule of rules) {
      const days = rule.days_of_week ? rule.days_of_week.split(',').map(Number) : [0,1,2,3,4,5,6];
      if (!days.includes(day)) continue;
      if (rule.start_hour <= rule.end_hour) {
        if (hour >= rule.start_hour && hour < rule.end_hour) { onAir = true; break; }
      } else {
        if (hour >= rule.start_hour || hour < rule.end_hour) { onAir = true; break; }
      }
    }
    const hourStart = Math.max(t.getTime(), startMs);
    const hourEnd = Math.min(t.getTime() + 3600000, endMs);
    if (onAir) {
      if (rangeStart === null) rangeStart = hourStart;
    } else {
      if (rangeStart !== null) {
        ranges.push({ start: rangeStart, end: hourStart });
        rangeStart = null;
      }
    }
    t = new Date(t.getTime() + 3600000);
  }
  if (rangeStart !== null) ranges.push({ start: rangeStart, end: endMs });
  return ranges;
}

// Get channel schedule
app.get('/api/livetv/channels/:id/schedule', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const ch = db.prepare('SELECT * FROM channels WHERE id = ?').get(req.params.id);
  if (!ch) return res.status(404).json({ error: 'Channel not found' });
  const timeRules = db.prepare("SELECT * FROM schedule_rules WHERE channel_id = ? AND rule_type = 'time_block'").all(req.params.id);
  const onAir = isChannelEffectivelyOnAir(ch.id);
  res.json({ channelId: ch.id, channelName: ch.name, onAir, timeRules });
});

// --- Stream via ffmpeg MPEG-TS (continuous - chains programs automatically) ---
// Handle both /api/livetv/stream/2 and /api/livetv/stream/2.ts
app.get('/api/livetv/stream/:channelId', async (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const channelId = parseInt(req.params.channelId.replace(/\.ts$/, ''));
  const ch = db.prepare('SELECT * FROM channels WHERE id = ?').get(channelId);
  if (!ch) return res.status(404).json({ error: 'Channel not found' });

  if (!isChannelEffectivelyOnAir(channelId)) {
    const nextOn = getNextOnAirTime(channelId);
    const nextOnFmt = nextOn ? new Date(nextOn).toLocaleString('en-US', {hour:'numeric',minute:'2-digit',weekday:'short'}) : 'TBD';
    // Strict allowlist: only ASCII letters/digits/space/_-./. Removes all chars with meaning in
    // ffmpeg filter syntax (':', ',', '\\', '%', '{', '}', '\'', '"') so name cannot break out
    // of the drawtext text= argument or trigger %{...} expansions.
    const safeChName = (ch.name || 'Channel').replace(/[^A-Za-z0-9 _.\-]/g, '').slice(0, 40) || 'Channel';
    // Generate off-air card as MPEG-TS video using ffmpeg lavfi
    res.writeHead(200, {
      'Content-Type': 'video/mp2t',
      'Transfer-Encoding': 'chunked',
      'Cache-Control': 'no-cache, no-store',
      'Access-Control-Allow-Origin': '*'
    });
    const ff = spawn('ffmpeg', [
      '-f', 'lavfi', '-i',
      `color=c=0x0a0e27:s=1280x720:d=60,drawtext=text='${safeChName}':fontcolor=white:fontsize=52:x=(w-text_w)/2:y=(h/2)-60,drawtext=text='Off Air':fontcolor=0x94a3b8:fontsize=36:x=(w-text_w)/2:y=(h/2)+10,drawtext=text='Resumes ${nextOnFmt}':fontcolor=0x60a5fa:fontsize=28:x=(w-text_w)/2:y=(h/2)+70`,
      '-f', 'lavfi', '-i', 'anullsrc=r=44100:cl=stereo',
      '-c:v', 'libx264', '-preset', 'ultrafast', '-tune', 'stillimage',
      '-c:a', 'aac', '-shortest',
      '-f', 'mpegts', 'pipe:1'
    ]);
    ff.on('error', (err) => {
      console.error('[LiveTV off-air] ffmpeg spawn error:', err.message);
      if (!res.writableEnded) res.end();
    });
    ff.stdout.pipe(res);
    ff.stderr.on('data', () => {});
    ff.on('close', () => { if (!res.writableEnded) res.end(); });
    req.on('close', () => { ff.kill('SIGTERM'); });
    return;
  }

  const current = getCurrentProgram(channelId);
  if (!current) return res.status(503).json({ error: 'No programming available' });

  const ratingKey = current.item.prog_rkey || current.item.filler_rkey;
  if (!ratingKey) return res.status(503).json({ error: 'No playable content' });

  res.writeHead(200, {
    'Content-Type': 'video/mp2t',
    'Transfer-Encoding': 'chunked',
    'Connection': 'keep-alive',
    'Cache-Control': 'no-cache, no-store',
    'X-Accel-Buffering': 'no',
    'Access-Control-Allow-Origin': '*'
  });

  // Disable socket timeout for long-running stream
  req.socket.setTimeout(0);
  res.socket.setTimeout(0);

  const streamStart = Date.now();
  let totalBytesSent = 0;
  let clientDisconnected = false;
  let cumulativeDurationSec = 0; // Track total duration for TS offset continuity

  req.on('close', () => {
    clientDisconnected = true;
    console.log(`[LiveTV] Client disconnected after ${Date.now() - streamStart}ms, ${totalBytesSent} bytes total`);
  });

  // When a segment fails (e.g. Plex 404 from a stale rating key), we set this to the failed
  // slot's `nextIndex` so the next iteration jumps forward by playlist position instead of
  // re-picking the same broken slot by wall-clock. Reset on every wall-clock pick.
  let forceFromPosition = null;
  let consecutiveFailures = 0;
  const MAX_CONSECUTIVE_FAILURES = 20;

  // Stream programs continuously until client disconnects or channel goes off air
  const streamNextProgram = async () => {
    if (clientDisconnected || res.writableEnded) return;

    if (!isChannelEffectivelyOnAir(channelId)) {
      console.log(`[LiveTV] Channel ${ch.number} went off air (current program finished), ending stream`);
      if (!res.writableEnded) res.end();
      return;
    }

    let prog;
    if (forceFromPosition !== null) {
      prog = getProgramAtPosition(channelId, forceFromPosition);
      forceFromPosition = null;
    } else {
      prog = getCurrentProgram(channelId);
      consecutiveFailures = 0;
    }
    if (!prog) {
      console.log(`[LiveTV] No more programming for ch=${ch.number}, ending stream`);
      if (!res.writableEnded) res.end();
      return;
    }

    const progRkey = prog.item.prog_rkey || prog.item.filler_rkey;
    const localPath = prog.item.filler_local_path;

    // Handle local filler files (YouTube downloads)
    if (localPath && require('fs').existsSync(localPath)) {
      const offsetSec = Math.floor(prog.offsetMs / 1000);
      const segmentDurationSec = Math.round(prog.item.duration_ms / 1000);
      const title = prog.item.filler_name || 'Local Filler';
      console.log(`[LiveTV] Stream ch=${ch.number} local filler "${title}" offset=${offsetSec}s`);

      const ffArgs = [
        '-hide_banner', '-loglevel', 'error',
        '-ss', String(offsetSec), '-i', localPath,
        '-c:v', 'libx264', '-preset', 'ultrafast', '-tune', 'zerolatency',
        '-c:a', 'aac', '-b:a', '192k', '-ac', '2', '-ar', '44100',
        '-f', 'mpegts',
        '-mpegts_flags', 'resend_headers',
        '-mpegts_copyts', '1',
        '-output_ts_offset', String(cumulativeDurationSec),
        'pipe:1'
      ];
      const ff = spawn('ffmpeg', ffArgs);
      ff.on('error', (err) => {
        console.error('[LiveTV local filler] ffmpeg spawn error:', err.message);
        if (!clientDisconnected && !res.writableEnded) {
          // Advance to next program rather than crashing the stream
          setTimeout(() => streamNextProgram().catch(e => console.error('[LiveTV] streamNextProgram error:', e.message)), 50);
        }
      });
      ff.stdout.on('data', (chunk) => { if (!clientDisconnected && !res.writableEnded) res.write(chunk); });
      ff.stderr.on('data', () => {});
      ff.on('close', () => {
        cumulativeDurationSec += segmentDurationSec;
        if (!clientDisconnected && !res.writableEnded) {
          setTimeout(() => streamNextProgram().catch(e => console.error('[LiveTV] streamNextProgram error:', e.message)), 50);
        }
      });
      req.on('close', () => { ff.kill('SIGTERM'); });
      return;
    }

    if (!progRkey) {
      // No Plex rating key AND no local file — typically an empty filler stub. Treat it as a
      // failed segment so we advance by playlist position. Ending the stream here used to make
      // the channel go dark whenever wall-clock landed on such an item.
      const title = prog.item.filler_name || prog.item.prog_title || 'Unknown';
      consecutiveFailures++;
      if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
        console.error(`[LiveTV] ${MAX_CONSECUTIVE_FAILURES} consecutive empty slots on ch=${ch.number}, ending stream`);
        if (!res.writableEnded) res.end();
        return;
      }
      console.log(`[LiveTV] Empty slot "${title}" at pos ${prog.positionIndex} (#${consecutiveFailures}), advancing to position ${prog.nextIndex}`);
      forceFromPosition = prog.nextIndex;
      if (!clientDisconnected && !res.writableEnded) {
        setTimeout(() => streamNextProgram().catch(e => {
          console.error('[LiveTV] streamNextProgram error:', e.message);
          if (!res.writableEnded) res.end();
        }), 50);
      } else {
        if (!res.writableEnded) res.end();
      }
      return;
    }

    const offsetSec = Math.floor(prog.offsetMs / 1000);

    try {
      const metaRes = await axios.get(`${config.plex.url}/library/metadata/${progRkey}`, {
        params: { 'X-Plex-Token': config.plex.token },
        headers: { Accept: 'application/json' },
        timeout: 5000
      });

      const metadata = metaRes.data.MediaContainer.Metadata?.[0];
      const partKey = metadata?.Media?.[0]?.Part?.[0]?.key;
      const isFillerItem = !!prog.item.filler_id && !prog.item.program_id;
      if (!partKey) {
        if (isFillerItem) {
          console.log(`[LiveTV] Filler "${title}" has no media part, skipping to next`);
          // Don't wait - just advance immediately
          if (!clientDisconnected && !res.writableEnded) {
            streamNextProgram().catch(e => console.error('[LiveTV] streamNextProgram error:', e.message));
          }
          return;
        }
        throw new Error('No media part found');
      }

      const fileUrl = `${config.plex.url}${partKey}?X-Plex-Token=${config.plex.token}`;
      const videoCodec = metadata?.Media?.[0]?.videoCodec || 'unknown';
      const audioCodec = metadata?.Media?.[0]?.audioCodec || 'unknown';

      const segStart = Date.now();
      let segBytes = 0;
      const title = prog.item.prog_title || prog.item.filler_name || 'Unknown';
      console.log(`[LiveTV] Stream ch=${ch.number} "${title}" rk=${progRkey} offset=${offsetSec}s video=${videoCodec} audio=${audioCodec}`);

      // Pick a subtitle stream matching the user's preferred language, if configured. When found
      // and burnable, this forces the video encode path (libx264) — pixels are the only universal
      // delivery for subs in raw MPEG-TS to Plex DVR.
      const subSettings = readSubtitleSettings();
      let burnArgs = null;
      if (subSettings.language && subSettings.mode === 'burn') {
        const sub = await findPlexSubtitleStream(progRkey, fileUrl, subSettings.language);
        if (sub) {
          burnArgs = buildSubtitleBurnArgs(fileUrl, sub);
          if (burnArgs) console.log(`[LiveTV] Burning ${subSettings.language} subtitle (codec=${sub.codec}, si=${sub.relIdx})`);
        } else {
          console.log(`[LiveTV] No '${subSettings.language}' subtitle stream found for rk=${progRkey}, streaming without subs`);
        }
      }
      const needsTranscode = ['hevc', 'h265', 'vp9', 'av1'].includes(videoCodec) || !!burnArgs;
      const videoArgs = needsTranscode
        ? ['-c:v', 'libx264', '-preset', 'ultrafast', '-tune', 'zerolatency',
           '-crf', '23', '-profile:v', 'main', '-level', '4.0', '-pix_fmt', 'yuv420p',
           '-b:v', '4M', '-maxrate', '5M', '-bufsize', '8M',
           '-g', '48', '-keyint_min', '48', '-sc_threshold', '0']
        : ['-c:v', 'copy'];
      const audioArgs = ['-c:a', 'aac', '-b:a', '192k', '-ac', '2'];

      console.log(`[LiveTV] Video: ${needsTranscode ? 'transcode' : 'copy'} (${videoCodec})${burnArgs ? ' +subs' : ''}, Audio: transcode to aac`);

      // Calculate expected segment duration for TS offset tracking
      const segmentDurationSec = Math.max(0, Math.floor(prog.item.duration_ms / 1000) - offsetSec);

      const ffArgs = [
        '-nostdin',
        '-hide_banner', '-loglevel', 'error',
        '-fflags', '+genpts+discardcorrupt+igndts',
        '-reconnect', '1', '-reconnect_streamed', '1', '-reconnect_delay_max', '5',
        '-ss', String(offsetSec),
        '-i', fileUrl,
        '-threads', '0',
        '-map', '0:v:0', '-map', '0:a:0?',
        ...videoArgs,
        // Subtitle filter must come AFTER the video codec is chosen (it implies transcode).
        // The filter reads from the Plex media URL itself via libavformat — no extra fetch.
        ...(burnArgs ? burnArgs.vfArgs : []),
        ...audioArgs,
        '-avoid_negative_ts', 'make_zero',
        '-muxdelay', '0', '-muxpreload', '0',
        '-f', 'mpegts',
        '-mpegts_flags', 'resend_headers',
        '-mpegts_copyts', '1',
        '-mpegts_service_id', '1',
        '-output_ts_offset', String(cumulativeDurationSec),
        'pipe:1'
      ];

      const ffmpeg = spawn('ffmpeg', ffArgs);

      // Spawn-level error (e.g. ENOENT) emits 'error' instead of throwing — handle it so it
      // doesn't escape as an unhandled exception. The 'close' handler in the Promise below
      // will still resolve and let us advance.
      ffmpeg.on('error', (err) => {
        console.error('[LiveTV] ffmpeg spawn error:', err.message);
      });

      // Kill ffmpeg if client disconnects mid-segment
      const onDisconnect = () => { ffmpeg.kill('SIGTERM'); };
      if (clientDisconnected) { ffmpeg.kill('SIGTERM'); return; }
      req.on('close', onDisconnect);

      ffmpeg.stdout.on('data', (chunk) => {
        if (segBytes === 0) {
          console.log(`[LiveTV] First data after ${Date.now() - segStart}ms (${chunk.length} bytes)`);
        }
        segBytes += chunk.length;
        totalBytesSent += chunk.length;
        if (!res.writableEnded) {
          const ok = res.write(chunk);
          if (!ok) ffmpeg.stdout.pause();
        }
      });

      res.on('drain', () => {
        if (ffmpeg.stdout) ffmpeg.stdout.resume();
      });

      ffmpeg.stderr.on('data', (data) => {
        const msg = data.toString().trim();
        if (msg) console.error(`[LiveTV ffmpeg] ${msg}`);
      });

      // Wait for ffmpeg to finish this segment, then chain to next
      await new Promise((resolve) => {
        ffmpeg.on('error', (err) => {
          console.error('[LiveTV] ffmpeg error:', err.message);
          resolve();
        });
        ffmpeg.on('close', (code) => {
          console.log(`[LiveTV] Segment ended: "${title}" ${segBytes} bytes in ${Date.now() - segStart}ms, exit=${code}`);
          req.removeListener('close', onDisconnect);
          // Accumulate duration for next segment's TS offset
          cumulativeDurationSec += segmentDurationSec;
          resolve();
        });
      });

      // Small delay to allow player to process the transition
      await new Promise(r => setTimeout(r, 50));

      // Chain to next program
      streamNextProgram().catch(e => console.error('[LiveTV] streamNextProgram error:', e.message));
    } catch (error) {
      console.error('[LiveTV] Stream segment error:', error.message);
      const title = prog?.item?.prog_title || prog?.item?.filler_name || 'Unknown';
      consecutiveFailures++;
      // Hard cap: if too many slots in a row are broken (e.g. whole playlist stale), give up so
      // we don't loop forever pummeling Plex with metadata lookups.
      if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
        console.error(`[LiveTV] ${MAX_CONSECUTIVE_FAILURES} consecutive failed segments on ch=${ch.number}, ending stream`);
        if (!res.writableEnded) res.end();
        return;
      }
      // Advance by playlist *position*, not wall-clock. A single 404 used to lock us in a 5s
      // retry loop because the wall-clock barely moved — same slot, same 404, forever.
      const nextIdx = (prog && typeof prog.nextIndex === 'number') ? prog.nextIndex : null;
      console.log(`[LiveTV] Skipping failed segment "${title}" (#${consecutiveFailures}), advancing to position ${nextIdx}`);
      if (nextIdx !== null) forceFromPosition = nextIdx;
      if (!clientDisconnected && !res.writableEnded) {
        // Tiny delay so we don't tight-loop if the next slot also 404s; the counter cap above
        // bounds total time anyway.
        setTimeout(() => {
          streamNextProgram().catch(e => {
            console.error('[LiveTV] streamNextProgram error:', e.message);
            if (!res.writableEnded) res.end();
          });
        }, 100);
      } else {
        if (!res.writableEnded) res.end();
      }
    }
  };

  // Top-level catch — if anything escapes, end the response cleanly so we don't crash the process.
  streamNextProgram().catch(e => {
    console.error('[LiveTV] streamNextProgram top-level error:', e.message);
    if (!res.writableEnded) res.end();
  });
});

// --- Filler CRUD ---
app.get('/api/livetv/fillers', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const fillers = db.prepare('SELECT * FROM fillers ORDER BY name').all();
  // Enrich with channel assignment info
  const channelAssignments = db.prepare('SELECT cf.filler_id, cf.channel_id, c.name as channel_name FROM channel_fillers cf JOIN channels c ON cf.channel_id = c.id').all();
  const assignmentMap = {};
  for (const a of channelAssignments) {
    if (!assignmentMap[a.filler_id]) assignmentMap[a.filler_id] = [];
    assignmentMap[a.filler_id].push({ id: a.channel_id, name: a.channel_name });
  }
  for (const f of fillers) {
    f.assignedChannels = assignmentMap[f.id] || [];
  }
  res.json(fillers);
});

app.post('/api/livetv/fillers', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { name, type, plex_rating_key, duration_ms, plex_key, weight, channel_id } = req.body;
  if (!name || !type || !duration_ms) return res.status(400).json({ error: 'name, type, and duration_ms required' });

  const result = db.prepare(`
    INSERT INTO fillers (name, type, plex_rating_key, duration_ms, plex_key, weight, channel_id)
    VALUES (?,?,?,?,?,?,?)
  `).run(name, type, plex_rating_key || null, duration_ms, plex_key || null, weight || 1, channel_id || null);
  res.json({ success: true, id: result.lastInsertRowid });
});

app.delete('/api/livetv/fillers/:id', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  db.prepare('DELETE FROM fillers WHERE id = ?').run(req.params.id);
  invalidatePlaylistCache();
  res.json({ success: true });
});

app.post('/api/livetv/fillers/scan-trailers', async (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  try {
    const libRes = await axios.get(`${config.plex.url}/library/sections`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { Accept: 'application/json' }, timeout: 10000
    });
    const libraries = libRes.data.MediaContainer.Directory || [];
    let added = 0, scanned = 0;

    const insertFiller = db.prepare(`
      INSERT OR IGNORE INTO fillers (name, type, plex_rating_key, duration_ms, plex_key, genre, parent_title, library_key, content_type, part_key, verified)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)
    `);
    // Ensure unique constraint on plex_rating_key for OR IGNORE
    try { db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_fillers_rkey ON fillers(plex_rating_key)'); } catch(e) {}

    let skippedNoMedia = 0;

    for (const lib of libraries) {
      if (lib.type !== 'movie' && lib.type !== 'show') continue;
      const contentType = lib.type === 'movie' ? 'movie' : 'show';

      // Fetch all items in library
      let start = 0;
      const pageSize = 100;
      while (true) {
        const allRes = await axios.get(`${config.plex.url}/library/sections/${lib.key}/all`, {
          params: { 'X-Plex-Token': config.plex.token, 'X-Plex-Container-Start': start, 'X-Plex-Container-Size': pageSize },
          headers: { Accept: 'application/json' }, timeout: 30000
        });
        const items = allRes.data.MediaContainer.Metadata || [];
        if (items.length === 0) break;

        // Process items in batches of 10 concurrent requests
        for (let b = 0; b < items.length; b += 10) {
          const batch = items.slice(b, b + 10);
          const results = await Promise.allSettled(batch.map(async (item) => {
            const genre = (item.Genre || []).map(g => g.tag).join(',');
            try {
              const extrasRes = await axios.get(`${config.plex.url}/library/metadata/${item.ratingKey}/extras`, {
                params: { 'X-Plex-Token': config.plex.token },
                headers: { Accept: 'application/json' }, timeout: 10000
              });
              const extras = extrasRes.data.MediaContainer.Metadata || [];
              let count = 0;
              for (const ex of extras) {
                // Only trailers (skip featurettes, behind-the-scenes, etc. unless short)
                if (ex.subtype !== 'trailer') continue;
                if (!ex.duration || ex.duration < 5000) continue;
                const rkey = String(ex.ratingKey);

                // Verify the extra has playable media by fetching its metadata
                let partKey = null;
                let verified = 0;
                try {
                  const exMetaRes = await axios.get(`${config.plex.url}/library/metadata/${rkey}`, {
                    params: { 'X-Plex-Token': config.plex.token },
                    headers: { Accept: 'application/json' }, timeout: 5000
                  });
                  const exMeta = exMetaRes.data?.MediaContainer?.Metadata?.[0];
                  partKey = exMeta?.Media?.[0]?.Part?.[0]?.key || null;
                  if (partKey) {
                    verified = 1;
                  } else {
                    // No playable media part - skip this filler
                    skippedNoMedia++;
                    continue;
                  }
                } catch(verifyErr) {
                  // Can't verify - skip to be safe
                  skippedNoMedia++;
                  continue;
                }

                const name = `${ex.title || item.title}`;
                const result = insertFiller.run(name, 'trailer', rkey, ex.duration, `/library/metadata/${rkey}`, genre, item.title, lib.key, contentType, partKey, verified);
                if (result.changes > 0) count++;
              }
              return count;
            } catch(e) { return 0; }
          }));
          for (const r of results) {
            if (r.status === 'fulfilled') added += r.value;
          }
          scanned += batch.length;
        }
        start += items.length;
        if (items.length < pageSize) break;
      }
    }
    console.log(`LiveTV: Trailer scan complete - scanned ${scanned} items, added ${added} trailers, skipped ${skippedNoMedia} (no media)`);
    res.json({ success: true, added, scanned, skippedNoMedia });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- YouTube Filler Downloads ---
const activeDownloads = new Map(); // downloadId -> child process

// Static serving for downloaded fillers
app.use('/fillers', express.static(path.join(__dirname, 'data', 'fillers')));

app.get('/api/livetv/fillers/disk-space', async (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  try {
    const disks = await si.fsSize();
    const main = disks.find(d => d.mount === '/') || disks[0];
    // Check fillers directory size (no shell, fixed path — sums files recursively)
    let fillersSize = 0;
    try {
      const fsLocal = require('fs');
      const walk = (dir) => {
        let total = 0;
        for (const entry of fsLocal.readdirSync(dir, { withFileTypes: true })) {
          const p = path.join(dir, entry.name);
          try {
            if (entry.isDirectory()) total += walk(p);
            else if (entry.isFile()) total += fsLocal.statSync(p).size;
          } catch(e) {}
        }
        return total;
      };
      const fillerDir = path.join(__dirname, 'data', 'fillers');
      if (fsLocal.existsSync(fillerDir)) fillersSize = walk(fillerDir);
    } catch(e) {}
    res.json({
      total: main?.size || 0,
      available: main?.available || 0,
      used: main?.used || 0,
      fillersSize,
      fillersFormatted: fillersSize > 1073741824 ? `${(fillersSize/1073741824).toFixed(2)} GB` : `${(fillersSize/1048576).toFixed(1)} MB`
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Scan channel programs and search YouTube for trailers
app.post('/api/livetv/fillers/yt-scan', async (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { channelId, limit } = req.body;
  const maxResults = Math.min(limit || 20, 50);

  // Get unique titles from channel programs (or all programs if no channel specified)
  let programs;
  if (channelId) {
    programs = db.prepare(`
      SELECT DISTINCT p.title, p.show_title, p.type, p.year FROM channel_programming cp
      JOIN programs p ON cp.program_id = p.id
      WHERE cp.channel_id = ? AND cp.program_id IS NOT NULL
      ORDER BY p.title LIMIT ?
    `).all(channelId, maxResults);
  } else {
    programs = db.prepare('SELECT DISTINCT title, show_title, type, year FROM programs ORDER BY title LIMIT ?').all(maxResults);
  }

  // Get already-downloaded filler names to skip
  const existingFillers = new Set(db.prepare('SELECT name FROM fillers').all().map(f => f.name.toLowerCase()));

  const results = [];

  for (const prog of programs) {
    const searchTitle = prog.type === 'episode' ? (prog.show_title || prog.title) : prog.title;
    if (!searchTitle) continue;

    // Skip if we already have a trailer for this
    const lowerTitle = searchTitle.toLowerCase();
    if (existingFillers.has(lowerTitle + ' - trailer') || existingFillers.has(searchTitle + ' - Trailer')) continue;

    const searchQuery = `${searchTitle} ${prog.year || ''} official trailer`.trim();
    try {
      // spawnSync with array args — no shell, query passed as a single literal arg
      const r = spawnSync('yt-dlp', [
        `ytsearch1:${searchQuery}`,
        '--dump-json', '--no-download', '--no-playlist'
      ], { timeout: 15000, maxBuffer: 5 * 1024 * 1024 });
      if (r.error || r.status !== 0) continue;
      const json = (r.stdout || '').toString().trim();
      if (!json) continue;
      const info = JSON.parse(json);
      if (info.duration > 600) continue; // skip videos longer than 10 minutes
      results.push({
        programTitle: searchTitle,
        programType: prog.type,
        programYear: prog.year,
        ytTitle: info.title,
        ytUrl: info.webpage_url || `https://www.youtube.com/watch?v=${info.id}`,
        ytId: info.id,
        duration: info.duration,
        thumbnail: info.thumbnail,
        uploader: info.uploader,
        alreadyHave: false
      });
    } catch(e) { /* skip failed searches */ }
  }

  // Also get disk space
  let diskSpace = null;
  try {
    const disks = await si.fsSize();
    const main = disks.find(d => d.mount === '/') || disks[0];
    diskSpace = { available: main?.available || 0 };
  } catch(e) {}

  res.json({ results, total: programs.length, searched: results.length, diskSpace });
});

// Manual URL info lookup (kept for manual paste option)
app.get('/api/livetv/fillers/yt-info', async (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  // Only allow http(s) URLs — protects spawn from non-URL injection vectors
  let parsed;
  try { parsed = new URL(url); } catch(e) { return res.status(400).json({ error: 'Invalid URL' }); }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return res.status(400).json({ error: 'Only http(s) URLs are allowed' });
  }
  try {
    const r = spawnSync('yt-dlp', ['--dump-json', '--no-download', parsed.toString()], {
      timeout: 30000, maxBuffer: 5 * 1024 * 1024
    });
    if (r.error) throw r.error;
    if (r.status !== 0) throw new Error((r.stderr || '').toString().substring(0, 200) || `yt-dlp exited ${r.status}`);
    const info = JSON.parse((r.stdout || '').toString());
    res.json({
      title: info.title, duration: info.duration, thumbnail: info.thumbnail,
      uploader: info.uploader, ytUrl: info.webpage_url || url, ytId: info.id
    });
  } catch(e) {
    res.status(500).json({ error: 'Failed to fetch video info: ' + (e.message || 'unknown error').substring(0, 200) });
  }
});

app.get('/api/livetv/fillers/yt-downloads', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  res.json(db.prepare('SELECT * FROM yt_downloads ORDER BY created_at DESC LIMIT 50').all());
});

// Start a single YouTube download. `meta` is an optional { genre, content_type } pair that gets
// stored on the resulting filler row so the legacy genre-match fallback in buildChannelPlaylist
// can pick it up across channels.
function startYtDownload(url, quality, channelIds, fillerName, meta) {
  const q = quality || '480p';
  const height = parseInt(q) || 480;

  const result = db.prepare('INSERT INTO yt_downloads (url, quality, title) VALUES (?, ?, ?)').run(url, q, fillerName || null);
  const dlId = result.lastInsertRowid;

  const fillerDir = path.join(__dirname, 'data', 'fillers');
  if (!require('fs').existsSync(fillerDir)) require('fs').mkdirSync(fillerDir, { recursive: true });

  const args = [
    '-f', `bestvideo[height<=${height}]+bestaudio/best[height<=${height}]`,
    '--merge-output-format', 'mp4',
    '-o', path.join(fillerDir, '%(title)s.%(ext)s'),
    '--progress', '--newline',
    '--no-playlist',
    url
  ];

  const proc = spawn('yt-dlp', args);
  activeDownloads.set(dlId, proc);
  // Keep the tail of stderr so a failure stores a useful reason in error_msg instead of just
  // "exit code 1". Plain progress lines get filtered out so we keep only the meaningful chatter.
  let stderrTail = '';

  proc.on('error', (err) => {
    console.error(`[YT-DL] spawn error for download ${dlId}:`, err.message);
    activeDownloads.delete(dlId);
    db.prepare('UPDATE yt_downloads SET status=?, error_msg=? WHERE id=?').run('error', `yt-dlp spawn error: ${err.message}`, dlId);
  });

  proc.stdout.on('data', (data) => {
    const line = data.toString();
    const match = line.match(/\[download\]\s+([\d.]+)%/);
    if (match) db.prepare('UPDATE yt_downloads SET progress = ?, status = ? WHERE id = ?').run(Math.round(parseFloat(match[1])), 'downloading', dlId);
    const destMatch = line.match(/\[download\] Destination: (.+)/);
    if (destMatch) db.prepare('UPDATE yt_downloads SET file_path = ? WHERE id = ?').run(destMatch[1].trim(), dlId);
    const mergeMatch = line.match(/Merging formats into "(.+)"/);
    if (mergeMatch) db.prepare('UPDATE yt_downloads SET file_path = ?, status = ? WHERE id = ?').run(mergeMatch[1].trim(), 'processing', dlId);
  });

  proc.stderr.on('data', (data) => {
    const chunk = data.toString();
    const match = chunk.match(/\[download\]\s+([\d.]+)%/);
    if (match) db.prepare('UPDATE yt_downloads SET progress = ?, status = ? WHERE id = ?').run(Math.round(parseFloat(match[1])), 'downloading', dlId);
    // Accumulate everything except plain [download] progress lines for diagnostics.
    for (const line of chunk.split('\n')) {
      if (!line.trim() || /^\[download\]\s+\d/.test(line)) continue;
      stderrTail = (stderrTail + line + '\n').slice(-1000);
    }
  });

  proc.on('close', (code) => {
    activeDownloads.delete(dlId);
    if (code === 0) {
      const dl = db.prepare('SELECT * FROM yt_downloads WHERE id = ?').get(dlId);
      const filePath = dl?.file_path;
      let fileSize = 0, durationMs = 0, title = fillerName || 'YouTube Filler';

      if (filePath && require('fs').existsSync(filePath)) {
        fileSize = require('fs').statSync(filePath).size;
        try {
          // spawnSync with array args — filePath is a single literal arg (cannot break out of quotes)
          const r = spawnSync('ffprobe', [
            '-v', 'quiet', '-show_entries', 'format=duration', '-of', 'csv=p=0', filePath
          ], { timeout: 10000 });
          if (r.status === 0) {
            const dur = (r.stdout || '').toString().trim();
            durationMs = Math.round(parseFloat(dur) * 1000) || 0;
          }
        } catch(e) {}
        if (!fillerName) title = path.basename(filePath, path.extname(filePath));
      }

      const fillerResult = db.prepare('INSERT INTO fillers (name, type, duration_ms, local_path, enabled, verified, genre, content_type) VALUES (?,?,?,?,1,1,?,?)')
        .run(title, 'youtube', durationMs, filePath, meta?.genre || null, meta?.content_type || null);
      const fillerId = fillerResult.lastInsertRowid;

      if (channelIds && Array.isArray(channelIds)) {
        const ins = db.prepare('INSERT OR IGNORE INTO channel_fillers (channel_id, filler_id) VALUES (?,?)');
        for (const cid of channelIds) ins.run(cid, fillerId);
      }

      db.prepare('UPDATE yt_downloads SET status=?, progress=100, file_size_bytes=?, duration_ms=?, title=?, filler_id=?, completed_at=datetime(?) WHERE id=?')
        .run('done', fileSize, durationMs, title, fillerId, new Date().toISOString(), dlId);
      console.log(`[YT-DL] Download complete: ${title} (${(fileSize/1048576).toFixed(1)} MB, ${Math.round(durationMs/1000)}s)`);
    } else {
      const reason = stderrTail.trim() || `yt-dlp exited with code ${code}`;
      db.prepare('UPDATE yt_downloads SET status=?, error_msg=? WHERE id=?').run('error', reason.slice(0, 800), dlId);
      console.warn(`[YT-DL] Download ${dlId} failed (code=${code}): ${reason.split('\n').pop()}`);
    }
  });

  db.prepare('UPDATE yt_downloads SET status = ? WHERE id = ?').run('downloading', dlId);
  return dlId;
}

// Download single URL
app.post('/api/livetv/fillers/yt-download', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { url, quality, channelIds, title } = req.body;
  if (!url) return res.status(400).json({ error: 'url required' });
  const dlId = startYtDownload(url, quality, channelIds, title);
  res.json({ success: true, id: dlId });
});

// Download batch of trailers (from scan results)
app.post('/api/livetv/fillers/yt-download-batch', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { items, quality, channelIds } = req.body;
  if (!items || !Array.isArray(items) || items.length === 0) return res.status(400).json({ error: 'items array required' });
  const ids = [];
  for (const item of items) {
    const fillerName = `${item.programTitle} - Trailer`;
    const dlId = startYtDownload(item.ytUrl, quality, channelIds, fillerName);
    ids.push(dlId);
  }
  res.json({ success: true, count: ids.length, ids });
});

// Auto-fetch fillers from YouTube for a channel based on its genre + content type. Uses
// yt-dlp's `ytsearchN:<query>` to grab the top N candidates, filters out anything over 5 min
// (we want short trailers/teasers, not full episodes), and enqueues a download for each.
// Body: { channel_id, count?, quality?, query? } — query overrides the auto-generated string.
app.post('/api/livetv/fillers/auto-fetch', async (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { channel_id, count = 10, quality = '480p', query: customQuery } = req.body || {};
  if (!channel_id) return res.status(400).json({ error: 'channel_id required' });
  const channel = db.prepare('SELECT * FROM channels WHERE id = ?').get(channel_id);
  if (!channel) return res.status(404).json({ error: 'channel not found' });

  // Derive genre + content_type from the channel's source_value JSON.
  let genre = null, contentType = null;
  try {
    const sv = JSON.parse(channel.source_value || '{}');
    genre = sv.genre || null;
    contentType = sv.content_type || null;
  } catch(e) {}

  const noun = contentType === 'episode' ? 'tv show' : (contentType === 'movie' ? 'movie' : '');
  const query = customQuery || `${genre || channel.name} ${noun} trailer`.trim();
  const n = Math.max(1, Math.min(50, parseInt(count) || 10));

  try {
    // yt-dlp --dump-json gives one JSON line per result; --flat-playlist keeps it light (no per-video extraction).
    const search = spawnSync('yt-dlp',
      ['--dump-json', '--flat-playlist', '--no-warnings', `ytsearch${n * 2}:${query}`],
      { timeout: 60000, maxBuffer: 8 * 1024 * 1024 });
    if (search.status !== 0) {
      return res.status(500).json({ error: 'yt-dlp search failed', detail: (search.stderr || '').toString().slice(0, 400) });
    }
    const candidates = (search.stdout || '').toString().split('\n').filter(Boolean).map(l => {
      try { return JSON.parse(l); } catch(e) { return null; }
    }).filter(Boolean);

    // Drop anything obviously too long (>5 min) — flat-playlist gives duration in seconds.
    const usable = candidates.filter(c => !c.duration || c.duration <= 300).slice(0, n);
    const enqueued = [];
    for (const c of usable) {
      const url = c.webpage_url || (c.id ? `https://www.youtube.com/watch?v=${c.id}` : null);
      if (!url) continue;
      const name = `${genre || channel.name} - ${c.title || 'Trailer'}`.slice(0, 200);
      const dlId = startYtDownload(url, quality, [channel_id], name, { genre, content_type: contentType });
      enqueued.push({ id: dlId, url, title: c.title, duration: c.duration });
    }
    res.json({ success: true, query, totalFound: candidates.length, enqueued });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/livetv/fillers/yt-downloads/:id', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const dl = db.prepare('SELECT * FROM yt_downloads WHERE id = ?').get(req.params.id);
  if (!dl) return res.status(404).json({ error: 'Download not found' });

  // Kill active download
  const proc = activeDownloads.get(dl.id);
  if (proc) { proc.kill('SIGTERM'); activeDownloads.delete(dl.id); }

  // Delete file
  if (dl.file_path && require('fs').existsSync(dl.file_path)) {
    try { require('fs').unlinkSync(dl.file_path); } catch(e) {}
  }

  // Delete associated filler record
  if (dl.filler_id) {
    db.prepare('DELETE FROM fillers WHERE id = ?').run(dl.filler_id);
  }

  db.prepare('DELETE FROM yt_downloads WHERE id = ?').run(dl.id);
  res.json({ success: true });
});

// --- Per-Channel Filler Assignment ---
app.get('/api/livetv/channels/:id/fillers', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const fillerIds = db.prepare('SELECT filler_id FROM channel_fillers WHERE channel_id = ?').all(req.params.id).map(r => r.filler_id);
  const fillers = fillerIds.length > 0
    ? db.prepare(`SELECT * FROM fillers WHERE id IN (${fillerIds.map(()=>'?').join(',')}) ORDER BY name`).all(...fillerIds)
    : [];
  res.json({ fillerIds, fillers });
});

app.put('/api/livetv/channels/:id/fillers', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { fillerIds } = req.body; // array of filler IDs
  if (!Array.isArray(fillerIds)) return res.status(400).json({ error: 'fillerIds array required' });

  const channelId = parseInt(req.params.id);
  const ch = db.prepare('SELECT * FROM channels WHERE id = ?').get(channelId);
  if (!ch) return res.status(404).json({ error: 'Channel not found' });

  db.transaction(() => {
    db.prepare('DELETE FROM channel_fillers WHERE channel_id = ?').run(channelId);
    const ins = db.prepare('INSERT OR IGNORE INTO channel_fillers (channel_id, filler_id) VALUES (?,?)');
    for (const fid of fillerIds) {
      ins.run(channelId, fid);
    }
  })();

  invalidatePlaylistCache(channelId);
  res.json({ success: true, count: fillerIds.length });
});

// --- Schedule Rules ---
app.get('/api/livetv/channels/:id/rules', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  res.json(db.prepare('SELECT * FROM schedule_rules WHERE channel_id = ?').all(req.params.id));
});

app.post('/api/livetv/channels/:id/rules', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { name, rule_type, start_month, end_month, start_hour, end_hour, days_of_week, genre_boost, boost_pct } = req.body;
  if (!name || !rule_type) return res.status(400).json({ error: 'name and rule_type required' });
  const dowStr = Array.isArray(days_of_week) ? days_of_week.join(',') : (days_of_week || null);

  const result = db.prepare(`
    INSERT INTO schedule_rules (channel_id, name, rule_type, start_month, end_month, start_hour, end_hour, days_of_week, genre_boost, boost_pct)
    VALUES (?,?,?,?,?,?,?,?,?,?)
  `).run(req.params.id, name, rule_type, start_month != null ? start_month : null, end_month != null ? end_month : null, start_hour != null ? start_hour : null, end_hour != null ? end_hour : null, dowStr, genre_boost || null, boost_pct != null ? boost_pct : 20);
  res.json({ success: true, id: result.lastInsertRowid });
});

app.put('/api/livetv/rules/:id', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { name, rule_type, start_month, end_month, start_hour, end_hour, days_of_week, genre_boost, boost_pct, enabled } = req.body;
  const dowStr = Array.isArray(days_of_week) ? days_of_week.join(',') : days_of_week;
  db.prepare(`
    UPDATE schedule_rules SET name=COALESCE(?,name), rule_type=COALESCE(?,rule_type),
      start_month=?, end_month=?, start_hour=?, end_hour=?, days_of_week=?,
      genre_boost=?, boost_pct=COALESCE(?,boost_pct), enabled=COALESCE(?,enabled)
    WHERE id=?
  `).run(name, rule_type, start_month, end_month, start_hour, end_hour, dowStr, genre_boost, boost_pct, enabled, req.params.id);
  res.json({ success: true });
});

app.delete('/api/livetv/rules/:id', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  db.prepare('DELETE FROM schedule_rules WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// --- Off-Air Settings ---
app.get('/api/livetv/channels/:id/offair-settings', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const ch = db.prepare('SELECT offair_mode, nofiller_message FROM channels WHERE id = ?').get(req.params.id);
  if (!ch) return res.status(404).json({ error: 'Channel not found' });
  res.json(ch);
});

app.put('/api/livetv/channels/:id/offair-settings', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { offair_mode, nofiller_message } = req.body;
  db.prepare('UPDATE channels SET offair_mode = COALESCE(?, offair_mode), nofiller_message = COALESCE(?, nofiller_message) WHERE id = ?')
    .run(offair_mode || null, nofiller_message !== undefined ? nofiller_message : null, req.params.id);
  res.json({ success: true });
});

app.get('/api/livetv/offair-defaults', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const mode = db.prepare("SELECT value FROM livetv_settings WHERE key = 'default_offair_mode'").get();
  const msg = db.prepare("SELECT value FROM livetv_settings WHERE key = 'default_nofiller_message'").get();
  res.json({ offair_mode: mode?.value || 'schedule', nofiller_message: msg?.value || 'Coming up next: {title} at {time}' });
});

app.put('/api/livetv/offair-defaults', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { offair_mode, nofiller_message } = req.body;
  if (offair_mode) db.prepare("INSERT OR REPLACE INTO livetv_settings (key, value) VALUES ('default_offair_mode', ?)").run(offair_mode);
  if (nofiller_message !== undefined) db.prepare("INSERT OR REPLACE INTO livetv_settings (key, value) VALUES ('default_nofiller_message', ?)").run(nofiller_message);
  res.json({ success: true });
});

// --- LiveTV scheduler settings ---
app.get('/api/livetv/scheduler-settings', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const rerun = db.prepare("SELECT value FROM livetv_settings WHERE key='rerun_window_days'").get();
  const auto = db.prepare("SELECT value FROM livetv_settings WHERE key='auto_rebuild_enabled'").get();
  res.json({
    rerun_window_days: parseInt(rerun?.value || '7', 10) || 0,
    auto_rebuild_enabled: (auto?.value || '1') === '1'
  });
});

app.put('/api/livetv/scheduler-settings', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { rerun_window_days, auto_rebuild_enabled } = req.body || {};
  if (rerun_window_days !== undefined) {
    const n = parseInt(rerun_window_days, 10);
    if (!Number.isFinite(n) || n < 0 || n > 60) {
      return res.status(400).json({ error: 'rerun_window_days must be 0–60' });
    }
    db.prepare("INSERT OR REPLACE INTO livetv_settings (key, value) VALUES ('rerun_window_days', ?)").run(String(n));
  }
  if (auto_rebuild_enabled !== undefined) {
    const v = (auto_rebuild_enabled === true || auto_rebuild_enabled === '1' || auto_rebuild_enabled === 1) ? '1' : '0';
    db.prepare("INSERT OR REPLACE INTO livetv_settings (key, value) VALUES ('auto_rebuild_enabled', ?)").run(v);
  }
  res.json({ success: true });
});

// Manual rebuild-all (e.g. when user changes rerun window and wants to apply immediately).
app.post('/api/livetv/rebuild-all', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const channels = db.prepare('SELECT id, name FROM channels WHERE enabled = 1').all();
  let succeeded = 0, failed = 0;
  for (const ch of channels) {
    try { buildChannelPlaylist(ch.id); succeeded++; } catch(e) { failed++; console.warn(`[LiveTV] rebuild ch ${ch.id}:`, e.message); }
  }
  _gcPlaylog();
  res.json({ success: true, channels: channels.length, succeeded, failed });
});

// --- LiveTV subtitle settings ---
app.get('/api/livetv/subtitle-settings', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  res.json(readSubtitleSettings());
});

app.put('/api/livetv/subtitle-settings', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { language, mode } = req.body || {};
  // Validate language: empty or 2/3-letter ISO code
  if (language !== undefined) {
    const lang = String(language).trim().toLowerCase();
    if (lang !== '' && !/^[a-z]{2,3}$/.test(lang)) {
      return res.status(400).json({ error: 'language must be a 2- or 3-letter ISO code, or empty to disable' });
    }
    db.prepare("INSERT OR REPLACE INTO livetv_settings (key, value) VALUES ('subtitle_language', ?)").run(lang);
  }
  if (mode !== undefined) {
    const m = String(mode).toLowerCase();
    if (!['off', 'burn'].includes(m)) {
      return res.status(400).json({ error: "mode must be 'off' or 'burn'" });
    }
    db.prepare("INSERT OR REPLACE INTO livetv_settings (key, value) VALUES ('subtitle_mode', ?)").run(m);
  }
  // Bust the per-rkey probe cache so the next stream re-detects with the new settings
  _subtitleProbeCache.clear();
  res.json({ success: true, settings: readSubtitleSettings() });
});

// --- Channel Logos ---
app.get('/api/livetv/logos/:channelId', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).send();
  const logo = db.prepare('SELECT mime_type, data FROM channel_logos WHERE channel_id = ?').get(req.params.channelId);
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  if (logo) {
    res.set('Content-Type', logo.mime_type);
    res.send(logo.data);
  } else {
    // Generate a simple SVG placeholder. Coerce channel number to a small integer string before
    // injection — avoids any chance of XSS-via-SVG even if upstream validation drifts.
    const ch = db.prepare('SELECT name, number FROM channels WHERE id = ?').get(req.params.channelId);
    let label = '?';
    if (ch) {
      const n = parseInt(ch.number, 10);
      if (Number.isFinite(n) && n >= 0 && n <= 9999) label = String(n);
    }
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200" viewBox="0 0 200 200">
      <rect width="200" height="200" rx="20" fill="#1e3a5f"/>
      <text x="100" y="90" text-anchor="middle" font-family="sans-serif" font-size="48" font-weight="bold" fill="#60a5fa">CH</text>
      <text x="100" y="150" text-anchor="middle" font-family="sans-serif" font-size="56" font-weight="bold" fill="#fff">${label}</text>
    </svg>`;
    res.set('Content-Type', 'image/svg+xml');
    res.send(svg);
  }
});

app.post('/api/livetv/logos/:channelId', express.raw({ type: ['image/*'], limit: '2mb' }), (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const mimeType = req.get('Content-Type') || 'image/png';
  db.prepare('INSERT OR REPLACE INTO channel_logos (channel_id, mime_type, data) VALUES (?,?,?)').run(req.params.channelId, mimeType, req.body);
  res.json({ success: true });
});

// Base64 logo upload (easier for frontend)
app.post('/api/livetv/logos/:channelId/upload', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { dataUrl } = req.body;
  if (!dataUrl) {
    console.log('[LiveTV] Logo upload: no dataUrl in body, body keys:', Object.keys(req.body || {}));
    return res.status(400).json({ error: 'dataUrl required' });
  }
  const match = dataUrl.match(/^data:(image\/[\w+.-]+);base64,(.+)$/);
  if (!match) {
    console.log('[LiveTV] Logo upload: regex mismatch, dataUrl starts with:', dataUrl.substring(0, 50));
    return res.status(400).json({ error: 'Invalid data URL format' });
  }
  const mimeType = match[1];
  const buffer = Buffer.from(match[2], 'base64');
  try {
    db.prepare('INSERT OR REPLACE INTO channel_logos (channel_id, mime_type, data) VALUES (?,?,?)').run(req.params.channelId, mimeType, buffer);
    console.log(`[LiveTV] Logo uploaded for channel ${req.params.channelId}: ${mimeType}, ${buffer.length} bytes`);
    res.json({ success: true });
  } catch(e) {
    console.error('[LiveTV] Logo save error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Delete logo
app.delete('/api/livetv/logos/:channelId', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  db.prepare('DELETE FROM channel_logos WHERE channel_id = ?').run(req.params.channelId);
  res.json({ success: true });
});

// Logo overlay settings
app.get('/api/livetv/logo-settings', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  try {
    const settings = db.prepare("SELECT value FROM livetv_settings WHERE key = 'logo_overlay'").get();
    res.json(settings ? JSON.parse(settings.value) : { enabled: true, position: 'top-right', opacity: 0.7, size: 80 });
  } catch(e) {
    res.json({ enabled: true, position: 'top-right', opacity: 0.7, size: 80 });
  }
});

app.put('/api/livetv/logo-settings', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const { enabled, position, opacity, size } = req.body;
  const settings = JSON.stringify({ enabled: enabled !== false, position: position || 'top-right', opacity: opacity ?? 0.7, size: size || 80 });
  db.prepare("INSERT OR REPLACE INTO livetv_settings (key, value) VALUES ('logo_overlay', ?)").run(settings);
  res.json({ success: true });
});

// DEBUG: Raw Jellyseerr request structure
app.get('/api/jellyseerr/debug', async (req, res) => {
  try {
    const response = await axios.get(`${config.jellyseerr.url}/api/v1/request`, {
      params: { take: 2, skip: 0, sort: 'added' },
      headers: { 'X-Api-Key': config.jellyseerr.apiKey },
      timeout: 5000
    });
    // Return raw structure so we can inspect it
    res.json({
      total: response.data.pageInfo?.results,
      sample: response.data.results?.slice(0, 2).map(r => ({
        id: r.id,
        status: r.status,
        type: r.type,
        mediaId: r.media?.id,
        tmdbId: r.media?.tmdbId,
        requestedBy: r.requestedBy?.username,
        allKeys: Object.keys(r),
        mediaKeys: Object.keys(r.media || {})
      }))
    });
  } catch (error) {
    res.json({ error: error.message });
  }
});

// ============================================
// TOOLS - Real Implementations
// ============================================

// Analytics Export
app.get('/api/tools/analytics-export', async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 30;
    if (!config.tautulli.apiKey) {
      return res.status(400).json({ error: 'Tautulli not configured' });
    }

    const histRes = await axios.get(`${config.tautulli.url}/api/v2`, {
      params: {
        apikey: config.tautulli.apiKey,
        cmd: 'get_history',
        length: 5000,
        after: Math.floor(Date.now() / 1000) - (days * 86400)
      },
      timeout: 30000
    });

    const history = histRes.data?.response?.data?.data || [];
    const totalPlays = history.length;
    const totalDuration = history.reduce((s, h) => s + (h.duration || 0), 0);

    // Plays by user
    const playsByUser = {};
    history.forEach(h => {
      const user = h.friendly_name || h.user || 'Unknown';
      if (!playsByUser[user]) playsByUser[user] = { plays: 0, duration: 0 };
      playsByUser[user].plays++;
      playsByUser[user].duration += h.duration || 0;
    });

    // Plays by library
    const playsByLibrary = {};
    history.forEach(h => {
      const lib = h.library_name || 'Unknown';
      if (!playsByLibrary[lib]) playsByLibrary[lib] = 0;
      playsByLibrary[lib]++;
    });

    // Top content
    const contentCounts = {};
    history.forEach(h => {
      const title = h.full_title || h.title || 'Unknown';
      if (!contentCounts[title]) contentCounts[title] = { title, plays: 0, media_type: h.media_type };
      contentCounts[title].plays++;
    });
    const topContent = Object.values(contentCounts).sort((a, b) => b.plays - a.plays).slice(0, 20);

    // Plays by day of week
    const playsByDayOfWeek = [0, 0, 0, 0, 0, 0, 0]; // Sun-Sat
    history.forEach(h => {
      if (h.date) {
        const d = new Date(h.date * 1000);
        playsByDayOfWeek[d.getDay()]++;
      }
    });

    // Plays by hour
    const playsByHour = new Array(24).fill(0);
    history.forEach(h => {
      if (h.date) {
        const d = new Date(h.date * 1000);
        playsByHour[d.getHours()]++;
      }
    });

    res.json({
      period: `Last ${days} days`,
      totalPlays,
      totalDuration,
      totalDurationFormatted: formatDuration(totalDuration),
      playsByUser: Object.entries(playsByUser)
        .sort((a, b) => b[1].plays - a[1].plays)
        .map(([user, data]) => ({ user, ...data, durationFormatted: formatDuration(data.duration) })),
      playsByLibrary: Object.entries(playsByLibrary)
        .sort((a, b) => b[1] - a[1])
        .map(([library, plays]) => ({ library, plays })),
      topContent,
      playsByDayOfWeek: ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
        .map((day, i) => ({ day, plays: playsByDayOfWeek[i] })),
      playsByHour: playsByHour.map((plays, hour) => ({ hour: `${hour}:00`, plays }))
    });
  } catch (error) {
    console.error('Analytics export error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Duplicate Finder
app.get('/api/tools/duplicates', async (req, res) => {
  try {
    const libraryKey = req.query.libraryKey;
    if (!libraryKey) return res.status(400).json({ error: 'libraryKey required' });

    const allRes = await axios.get(`${config.plex.url}/library/sections/${libraryKey}/all`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { 'Accept': 'application/json' },
      timeout: 30000
    });

    const items = allRes.data.MediaContainer.Metadata || [];

    // Group by normalized title
    const groups = {};
    for (const item of items) {
      const normalized = (item.title || '').toLowerCase().replace(/[^a-z0-9]/g, '');
      if (!normalized) continue;
      if (!groups[normalized]) groups[normalized] = [];
      groups[normalized].push({
        ratingKey: item.ratingKey,
        title: item.title,
        year: item.year || null,
        size: item.Media?.[0]?.Part?.[0]?.size || 0,
        duration: item.duration || 0,
        resolution: item.Media?.[0]?.videoResolution || 'unknown',
        videoCodec: item.Media?.[0]?.videoCodec || 'unknown',
        filePath: item.Media?.[0]?.Part?.[0]?.file || 'unknown'
      });
    }

    // Filter to only groups with duplicates
    const duplicates = Object.entries(groups)
      .filter(([, items]) => items.length > 1)
      .map(([normalizedTitle, items]) => ({
        normalizedTitle,
        count: items.length,
        items,
        totalSize: items.reduce((s, i) => s + i.size, 0)
      }))
      .sort((a, b) => b.totalSize - a.totalSize);

    res.json({
      libraryKey,
      duplicateGroups: duplicates.length,
      totalDuplicateItems: duplicates.reduce((s, g) => s + g.count, 0),
      potentialSavings: duplicates.reduce((s, g) => {
        // Savings = total size minus largest item in each group
        const largest = Math.max(...g.items.map(i => i.size));
        return s + g.totalSize - largest;
      }, 0),
      groups: duplicates
    });
  } catch (error) {
    console.error('Duplicate finder error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Library Health Check
app.get('/api/tools/health-check', async (req, res) => {
  try {
    const libraryKey = req.query.libraryKey;
    if (!libraryKey) return res.status(400).json({ error: 'libraryKey required' });

    const allRes = await axios.get(`${config.plex.url}/library/sections/${libraryKey}/all`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { 'Accept': 'application/json' },
      timeout: 30000
    });

    const items = allRes.data.MediaContainer.Metadata || [];
    const issues = {
      noThumbnail: [],
      shortDuration: [],
      missingYear: [],
      unmatched: [],
      noFile: []
    };

    for (const item of items) {
      const entry = {
        ratingKey: item.ratingKey,
        title: item.title,
        year: item.year || null,
        type: item.type
      };

      if (!item.thumb) {
        issues.noThumbnail.push(entry);
      }

      // Movies shorter than 40min or episodes shorter than 5min are suspicious
      const minDuration = item.type === 'movie' ? 2400000 : 300000;
      if (item.duration && item.duration < minDuration && item.duration > 0) {
        issues.shortDuration.push({
          ...entry,
          duration: item.duration,
          durationFormatted: formatDuration(Math.floor(item.duration / 1000))
        });
      }

      if (!item.year) {
        issues.missingYear.push(entry);
      }

      // Check if unmatched (no guid or guid starts with local://)
      if (!item.guid || item.guid.startsWith('local://')) {
        issues.unmatched.push(entry);
      }

      // Check for missing file path
      if (!item.Media?.[0]?.Part?.[0]?.file) {
        issues.noFile.push(entry);
      }
    }

    const totalIssues = Object.values(issues).reduce((s, arr) => s + arr.length, 0);

    res.json({
      libraryKey,
      totalItems: items.length,
      totalIssues,
      healthScore: items.length > 0 ? Math.max(0, Math.round(100 - (totalIssues / items.length * 100))) : 100,
      issues: {
        noThumbnail: { count: issues.noThumbnail.length, items: issues.noThumbnail.slice(0, 50) },
        shortDuration: { count: issues.shortDuration.length, items: issues.shortDuration.slice(0, 50) },
        missingYear: { count: issues.missingYear.length, items: issues.missingYear.slice(0, 50) },
        unmatched: { count: issues.unmatched.length, items: issues.unmatched.slice(0, 50) },
        noFile: { count: issues.noFile.length, items: issues.noFile.slice(0, 50) }
      }
    });
  } catch (error) {
    console.error('Health check error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Copy Watch History between users
app.post('/api/tools/copy-watch-history', async (req, res) => {
  try {
    const { fromUser, toUser, libraryKey } = req.body;
    if (!fromUser || !toUser || !libraryKey) {
      return res.status(400).json({ success: false, message: 'fromUser, toUser, and libraryKey are required' });
    }
    if (!config.tautulli.apiKey) {
      return res.status(400).json({ success: false, message: 'Tautulli not configured' });
    }

    // Get watch history for source user from Tautulli
    const histRes = await axios.get(`${config.tautulli.url}/api/v2`, {
      params: {
        apikey: config.tautulli.apiKey,
        cmd: 'get_history',
        user_id: fromUser,
        section_id: libraryKey,
        length: 10000
      },
      timeout: 30000
    });

    const history = histRes.data?.response?.data?.data || [];
    if (history.length === 0) {
      return res.json({ success: true, copied: 0, skipped: 0, message: 'No watch history found for source user in this library' });
    }

    // Get unique rating keys that the source user has watched
    const watchedKeys = [...new Set(history.map(h => h.rating_key).filter(Boolean))];

    // Get the target user's Plex token (for shared users) or use admin token
    // For admin-owned server, we use the admin token with the user context
    let copied = 0;
    let skipped = 0;

    for (const ratingKey of watchedKeys) {
      try {
        // Use Plex scrobble endpoint to mark as watched
        await axios.get(`${config.plex.url}/:/scrobble`, {
          params: {
            'X-Plex-Token': config.plex.token,
            key: ratingKey,
            identifier: 'com.plexapp.plugins.library'
          },
          timeout: 5000
        });
        copied++;
      } catch (e) {
        skipped++;
      }
    }

    res.json({ success: true, copied, skipped, total: watchedKeys.length });
  } catch (error) {
    console.error('Copy watch history error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Watch History Cleaner - stub with explanation
app.post('/api/tools/clean-history', (req, res) => {
  res.json({
    success: false,
    message: 'Watch History Cleaner requires direct write access to Tautulli database. To use this feature, you would need to call Tautulli API cmd=delete_history with row_ids. This is disabled by default to prevent accidental data loss.'
  });
});

// Date Added Editor - stub with explanation
app.post('/api/tools/edit-date-added', (req, res) => {
  res.json({
    success: false,
    message: 'Date Added Editor requires Plex API PUT access to /library/metadata/{ratingKey} with addedAt parameter. This is disabled by default as it modifies library metadata directly. Enable it in settings if you understand the risks.'
  });
});

// Server discovery for clients that want automatic LAN/tailscale failover. The TV app caches
// `tailscaleUrl` after a successful LAN connect, then uses it as a fallback on later launches
// when the LAN URL stops responding (e.g. user is off the home network).
//
// Env precedence (must describe THIS Command Center container, not the Plex server):
//   PCC_LAN_URL          — full URL for LAN reach, e.g. http://192.168.1.12:3001
//   PCC_TAILSCALE_URL    — full URL for tailscale reach, e.g. http://100.70.252.122:3001
//   LIVETV_BASE_URL      — already used by tuner endpoints; falls back as tailscaleUrl
// LOCAL_IP / TAILSCALE_IP are intentionally NOT used here — in some setups those describe
// the Plex server (a different machine) and would mislead clients to download from there.
app.get('/api/server-info', (req, res) => {
  res.json({
    lanUrl: process.env.PCC_LAN_URL || null,
    tailscaleUrl: process.env.PCC_TAILSCALE_URL || process.env.LIVETV_BASE_URL || null,
    hostname: require('os').hostname()
  });
});

app.get('/api/health', (req, res) => {
  const liveTvInfo = {};
  if (LIVETV_ENABLED && db) {
    liveTvInfo.channels = db.prepare('SELECT COUNT(*) as cnt FROM channels WHERE enabled = 1').get().cnt;
    liveTvInfo.programs = db.prepare('SELECT COUNT(*) as cnt FROM programs').get().cnt;
  }
  res.json({
    status: 'ok', version: '3.0.0',
    timestamp: new Date().toISOString(),
    services: {
      plex: !!config.plex.token,
      tautulli: !!config.tautulli.apiKey,
      jellyseerr: !!config.jellyseerr.apiKey,
      zabbix: !!config.zabbix.url,
      livetv: LIVETV_ENABLED
    },
    livetv: LIVETV_ENABLED ? liveTvInfo : undefined
  });
});

// Desktop app download
app.get('/download/PlexLiveTV-win64.zip', (req, res) => {
  const zipPath = path.join(__dirname, 'PlexLiveTV-win64.zip');
  if (fs.existsSync(zipPath)) {
    res.download(zipPath, 'PlexLiveTV-win64.zip');
  } else {
    res.status(404).send('File not found');
  }
});

app.get('/download/project', (req, res) => {
  const f = path.join(__dirname, 'public', 'plex-command-center-v2.tar.gz');
  if (require('fs').existsSync(f)) {
    res.set('Content-Disposition', 'attachment; filename="plex-command-center-v2.tar.gz"');
    res.sendFile(f);
  } else res.status(404).send('Not found');
});

app.get('/download/desktop-renderer', (req, res) => {
  const f = path.join(__dirname, 'public', 'desktop-renderer.html');
  if (require('fs').existsSync(f)) {
    res.set('Content-Disposition', 'attachment; filename="index.html"');
    res.sendFile(f);
  } else res.status(404).send('Not found');
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: err.message });
});

// ============================================
// PLEX REVERSE-PROXY GATEWAY
// ============================================
//
// When PCC_GATEWAY_ENABLED=1, PCC listens on PCC_GATEWAY_PORT and reverse-proxies every
// request to the real Plex Media Server (PCC_GATEWAY_TARGET, defaulting to PLEX_URL).
// Before forwarding, the source IP is checked against the existing regional geofence:
//   - LAN/private IPs pass.
//   - IPs in regional_whitelist pass.
//   - Country in regional_settings.allowed_countries passes.
//   - Everything else gets a 403 deny page (HTML for browser, plaintext for API/upgrade).
//
// Safety: if regional_settings.enabled is 0, the gateway acts as a pure pass-through proxy.
// This way enabling the gateway via env never locks you out unintentionally — geofence
// enforcement is opt-in through the existing UI.
//
// Setup steps for the user (documented in release notes):
//   1. Point router public port forward at PCC's host (not PMS) on PCC_GATEWAY_PORT.
//   2. In Plex: Settings → Network → add PCC's LAN IP to "LAN networks" so PCC's proxied
//      requests aren't rate-limited; disable "Enable Relay" so clients can't bypass us.
//   3. (Optional) Custom server access URL → http://<public_ip>:<port> so Plex tells
//      clients to use the public endpoint (which is PCC).
const GATEWAY_ENABLED = process.env.PCC_GATEWAY_ENABLED === '1';
const GATEWAY_PORT = parseInt(process.env.PCC_GATEWAY_PORT) || 32400;
const GATEWAY_TARGET = process.env.PCC_GATEWAY_TARGET || config.plex.url || '';

async function checkGatewayAccess(ip) {
  const cleanIp = (ip || '').replace(/^::ffff:/, '');
  const geo = await lookupGeo(cleanIp);
  const settings = readRegionalSettings();
  // Geofence disabled → pure proxy.
  if (!settings.enabled) return { allowed: true, geo, reason: 'geofence_disabled' };
  if (isIpRegionallyWhitelisted(cleanIp)) return { allowed: true, geo, reason: 'whitelisted' };
  if (settings.allowed_countries.includes(geo.country)) return { allowed: true, geo, reason: 'allowed_country' };
  return { allowed: false, geo, reason: 'geofence' };
}

// In-process cache to log only one "allow" per (ip, day) — keeps volume sane.
const _gatewayAllowSeen = new Map();
function _gatewayAllowKey(ip) { return ip + '|' + new Date().toISOString().slice(0, 10); }
function logGatewayEvent(ip, decision, action, urlPath) {
  try {
    if (decision.allowed) {
      const key = _gatewayAllowKey(ip);
      if (_gatewayAllowSeen.has(key)) return;
      _gatewayAllowSeen.set(key, true);
      // Trim old entries periodically.
      if (_gatewayAllowSeen.size > 5000) {
        const today = new Date().toISOString().slice(0, 10);
        for (const k of _gatewayAllowSeen.keys()) if (!k.endsWith(today)) _gatewayAllowSeen.delete(k);
      }
    }
    pccDb.prepare('INSERT INTO gateway_log (ip_address, country, city, allowed, action, url_path) VALUES (?,?,?,?,?,?)')
      .run(ip, decision.geo?.country || null, decision.geo?.city || null, decision.allowed ? 1 : 0, action, (urlPath || '').slice(0, 200));
  } catch(e) { /* log failure shouldn't break the proxy */ }
}

function denyPageHtml(ip, country) {
  // Plain-template literal; the only interpolated values are ip (already trimmed by socket layer)
  // and country (from our own ip-api cache, server-controlled). Both are safe to embed.
  const esc = s => String(s || '').replace(/[<>&"']/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'}[c]));
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Access Denied</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: -apple-system, system-ui, sans-serif; background:#0a0e27; color:#e2e8f0; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; padding:1rem; }
  .card { background:rgba(15,23,42,.85); border:1px solid rgba(100,116,139,.3); border-radius:14px; padding:2.5rem; max-width:520px; box-shadow:0 20px 60px rgba(0,0,0,.5); }
  h1 { color:#ef4444; margin:0 0 .75rem 0; font-size:1.5rem; }
  p { color:#94a3b8; line-height:1.5; }
  .meta { font-family: ui-monospace, monospace; font-size:.8rem; color:#64748b; margin-top:1.5rem; padding-top:1rem; border-top:1px solid rgba(100,116,139,.2); }
  .meta div { margin:.15rem 0; }
</style></head>
<body><div class="card">
  <h1>Access Not Allowed</h1>
  <p>This server is not accessible from your current location.</p>
  <p>If you believe this is an error, please contact the server administrator.</p>
  <div class="meta">
    <div>IP: ${esc(ip)}</div>
    <div>Country: ${esc(country || 'Unknown')}</div>
    <div>Time: ${new Date().toISOString()}</div>
  </div>
</div></body></html>`;
}

if (GATEWAY_ENABLED && GATEWAY_TARGET) {
  const targetUrl = new URL(GATEWAY_TARGET);
  const tHost = targetUrl.hostname;
  const tPort = Number(targetUrl.port) || (targetUrl.protocol === 'https:' ? 443 : 80);
  const isHttps = targetUrl.protocol === 'https:';
  const httpMod = isHttps ? require('https') : http;

  const gateway = http.createServer(async (req, res) => {
    const ip = (req.socket.remoteAddress || '').replace(/^::ffff:/, '');
    let decision;
    try { decision = await checkGatewayAccess(ip); }
    catch (e) { decision = { allowed: false, geo: { country: 'Unknown' }, reason: 'geo_lookup_failed' }; }

    if (!decision.allowed) {
      logGatewayEvent(ip, decision, 'deny', req.url);
      res.writeHead(403, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'X-Geofence-Blocked': decision.geo.country || 'unknown'
      });
      return res.end(denyPageHtml(ip, decision.geo.country));
    }

    const proxyReq = httpMod.request({
      hostname: tHost, port: tPort, path: req.url, method: req.method,
      headers: { ...req.headers, host: `${tHost}:${tPort}`, 'x-forwarded-for': ip, 'x-real-ip': ip },
      rejectUnauthorized: false  // PMS uses its own *.plex.direct self-signed cert
    }, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    });
    proxyReq.on('error', (err) => {
      console.warn(`[Gateway] upstream error for ${ip}: ${err.message}`);
      if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain' });
      if (!res.writableEnded) res.end('Upstream Plex server unreachable');
    });
    req.pipe(proxyReq);
    logGatewayEvent(ip, decision, 'allow', req.url);
  });

  // WebSocket / generic Upgrade pass-through (Plex uses /:/eventsource and friends).
  gateway.on('upgrade', async (req, clientSocket, head) => {
    const ip = (clientSocket.remoteAddress || '').replace(/^::ffff:/, '');
    let decision;
    try { decision = await checkGatewayAccess(ip); }
    catch (e) { decision = { allowed: false, geo: { country: 'Unknown' }, reason: 'geo_lookup_failed' }; }

    if (!decision.allowed) {
      logGatewayEvent(ip, decision, 'deny-ws', req.url);
      clientSocket.write('HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nAccess denied from your location.');
      return clientSocket.destroy();
    }
    const upstream = net.connect(tPort, tHost, () => {
      const headers = { ...req.headers, host: `${tHost}:${tPort}`, 'x-forwarded-for': ip };
      const reqLine = `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`;
      const headerLines = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\r\n');
      upstream.write(reqLine + headerLines + '\r\n\r\n');
      if (head && head.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
    logGatewayEvent(ip, decision, 'allow-ws', req.url);
  });

  gateway.listen(GATEWAY_PORT, () => {
    console.log(`[Gateway] Plex reverse proxy listening on :${GATEWAY_PORT} → ${GATEWAY_TARGET}`);
  });
} else if (GATEWAY_ENABLED && !GATEWAY_TARGET) {
  console.warn('[Gateway] PCC_GATEWAY_ENABLED=1 but no PCC_GATEWAY_TARGET / PLEX_URL configured. Gateway not started.');
}

// gateway_log API for the UI
app.get('/api/security/gateway-log', (req, res) => {
  const limit = Math.min(500, parseInt(req.query.limit) || 100);
  const onlyDenied = req.query.denied === '1';
  const sql = onlyDenied
    ? 'SELECT * FROM gateway_log WHERE allowed = 0 ORDER BY created_at DESC LIMIT ?'
    : 'SELECT * FROM gateway_log ORDER BY created_at DESC LIMIT ?';
  res.json(pccDb.prepare(sql).all(limit));
});
app.get('/api/security/gateway-stats', (req, res) => {
  res.json({
    enabled: GATEWAY_ENABLED,
    port: GATEWAY_PORT,
    target: GATEWAY_TARGET,
    totals: pccDb.prepare("SELECT SUM(CASE WHEN allowed=1 THEN 1 ELSE 0 END) AS allowed, SUM(CASE WHEN allowed=0 THEN 1 ELSE 0 END) AS denied FROM gateway_log WHERE created_at > datetime('now','-7 days')").get()
  });
});

app.listen(PORT, () => {
  console.log(`\n╔══════════════════════════════════════════════════╗`);
  console.log(`║  🎬 Plex Command Center v3.0.0                  ║`);
  console.log(`║  Port: ${PORT}                                       ║`);
  console.log(`║  Plex:       ${config.plex.token ? '✅' : '❌'}                               ║`);
  console.log(`║  Tautulli:   ${config.tautulli.apiKey ? '✅' : '❌'}                               ║`);
  console.log(`║  Jellyseerr: ${config.jellyseerr.apiKey ? '✅' : '❌'}                               ║`);
  console.log(`║  Zabbix:     ${config.zabbix.url ? '✅' : '⚠️  Not configured'}              ║`);
  console.log(`║  LiveTV:     ${LIVETV_ENABLED ? '✅' : '❌'}                               ║`);
  console.log(`╚══════════════════════════════════════════════════╝\n`);
});