// Plex Command Center v2.5.2 - Complete Fixed Backend
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const si = require('systeminformation');
const path = require('path');
const { spawn } = require('child_process');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Global request logger for debugging Plex connectivity
app.use((req, res, next) => {
  console.log(`[REQ] ${req.method} ${req.path} from ${req.ip}`);
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

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

async function getZabbixToken() {
  if (zabbixAuthToken && Date.now() < zabbixAuthExpiry) return zabbixAuthToken;
  if (!config.zabbix.url || !config.zabbix.user || !config.zabbix.password) return null;

  try {
    const res = await axios.post(`${config.zabbix.url}/api_jsonrpc.php`, {
      jsonrpc: '2.0', method: 'user.login',
      params: { username: config.zabbix.user, password: config.zabbix.password },
      id: 1
    }, { timeout: 5000 });

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
  res.json({
    source: 'unavailable',
    available: false,
    cpu: 0, memory: 0,
    network: { rx: 0, tx: 0 },
    message: 'Configure Zabbix to see Plex server metrics. Set ZABBIX_URL, ZABBIX_USER, ZABBIX_PASSWORD, ZABBIX_HOST_ID in docker-compose.yml'
  });
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

        for (const profile of watchedProfiles.slice(0, 8)) {
          const targetLibs = profile.type === 'movie' ? movieLibs : showLibs;

          // 1) "Because you watched X" - by director (movies only, if director exists)
          if (profile.directors.length > 0 && profile.type === 'movie') {
            const director = profile.directors[0];
            for (const lib of targetLibs) {
              try {
                const dirRes = await axios.get(`${config.plex.url}/library/sections/${lib.key}/all`, {
                  params: { 'X-Plex-Token': config.plex.token, director, 'X-Plex-Container-Size': 0, 'X-Plex-Container-Start': 0 },
                  headers: { Accept: 'application/json' }, timeout: 5000
                });
                const count = dirRes.data.MediaContainer.totalSize || dirRes.data.MediaContainer.size || 0;
                const sugKey = `dir:${director}:${lib.key}`;
                if (count > 2 && !suggestionTitles.has(sugKey)) {
                  suggestionTitles.add(sugKey);
                  suggestions.push({
                    title: `More from ${director}`,
                    type: 'personal',
                    subtype: 'director',
                    sourceTitle: profile.fullTitle,
                    filters: { director },
                    reason: `Because you watched "${profile.fullTitle}" — ${count} more by ${director}`,
                    libraryKey: lib.key,
                    libraryTitle: lib.title,
                    estimatedItems: count,
                    createType: 'director',
                    createValue: director
                  });
                }
              } catch(e) {}
            }
          }

          // 2) "Because you watched X" - by lead actor
          if (profile.actors.length > 0) {
            const actor = profile.actors[0];
            for (const lib of targetLibs) {
              try {
                const actRes = await axios.get(`${config.plex.url}/library/sections/${lib.key}/all`, {
                  params: { 'X-Plex-Token': config.plex.token, actor, 'X-Plex-Container-Size': 0, 'X-Plex-Container-Start': 0 },
                  headers: { Accept: 'application/json' }, timeout: 5000
                });
                const count = actRes.data.MediaContainer.totalSize || actRes.data.MediaContainer.size || 0;
                const sugKey = `act:${actor}:${lib.key}`;
                if (count > 2 && !suggestionTitles.has(sugKey)) {
                  suggestionTitles.add(sugKey);
                  suggestions.push({
                    title: `More with ${actor}`,
                    type: 'personal',
                    subtype: 'actor',
                    sourceTitle: profile.fullTitle,
                    filters: { actor },
                    reason: `Because you watched "${profile.fullTitle}" — ${count} more starring ${actor}`,
                    libraryKey: lib.key,
                    libraryTitle: lib.title,
                    estimatedItems: count,
                    createType: 'actor',
                    createValue: actor
                  });
                }
              } catch(e) {}
            }
          }

          // 3) "Because you watched X" - by genre combo (use primary+secondary genre)
          if (profile.genres.length >= 2) {
            const [g1, g2] = profile.genres;
            for (const lib of targetLibs) {
              try {
                const genreRes = await axios.get(`${config.plex.url}/library/sections/${lib.key}/all`, {
                  params: { 'X-Plex-Token': config.plex.token, genre: g1, unwatched: 1, 'X-Plex-Container-Size': 0, 'X-Plex-Container-Start': 0 },
                  headers: { Accept: 'application/json' }, timeout: 5000
                });
                const count = genreRes.data.MediaContainer.totalSize || genreRes.data.MediaContainer.size || 0;
                const sugKey = `genre:${g1}+${g2}:${lib.key}`;
                if (count > 3 && !suggestionTitles.has(sugKey)) {
                  suggestionTitles.add(sugKey);
                  suggestions.push({
                    title: `${g1} & ${g2} Mix`,
                    type: 'personal',
                    subtype: 'genre',
                    sourceTitle: profile.fullTitle,
                    filters: { genre: g1, unwatched: true },
                    reason: `Because you watched "${profile.fullTitle}" (${g1}/${g2}) — ${count} unwatched similar titles`,
                    libraryKey: lib.key,
                    libraryTitle: lib.title,
                    estimatedItems: count,
                    createType: 'genre',
                    createValue: g1
                  });
                }
              } catch(e) {}
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
              filters: { genre }, reason: sug.reason,
              libraryKey: lib.key, libraryTitle: lib.title, estimatedItems: count,
              createType: 'seasonal', createValue: genre,
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

      // Find matching items
      let filterParams = {};
      if (createType === 'genre' || createType === 'seasonal') filterParams.genre = createValue;
      else if (createType === 'actor') filterParams.actor = createValue;
      else if (createType === 'director') filterParams.director = createValue;
      else if (createType === 'studio') filterParams.studio = createValue;

      const itemsRes = await axios.get(`${config.plex.url}/library/sections/${libraryKey}/all`, {
        params: { 'X-Plex-Token': config.plex.token, ...filterParams },
        headers: { 'Accept': 'application/json' }, timeout: 10000
      });
      const items = (itemsRes.data.MediaContainer.Metadata || []).slice(0, 150);
      if (items.length === 0) continue;

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
  } catch(e) { /* columns already exist */ }

  // Migrate: add excluded_programs column to channels
  try {
    const chCols = db.pragma('table_info(channels)').map(c => c.name);
    if (!chCols.includes('excluded_programs')) {
      db.exec("ALTER TABLE channels ADD COLUMN excluded_programs TEXT DEFAULT '[]'");
    }
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
}

// --- Virtual Clock Engine ---
const playlistCache = new Map();

function getPlaylistData(channelId) {
  if (playlistCache.has(channelId)) return playlistCache.get(channelId);
  const rows = db.prepare(`
    SELECT cp.position, cp.duration_ms, cp.program_id, cp.filler_id,
      p.title as prog_title, p.type as prog_type, p.show_title, p.thumb as prog_thumb,
      p.plex_rating_key as prog_rkey, p.plex_key as prog_pkey, p.genre as prog_genre,
      p.year as prog_year, p.season_num, p.episode_num, p.content_rating,
      f.name as filler_name, f.type as filler_type, f.plex_rating_key as filler_rkey, f.plex_key as filler_pkey
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

function getCurrentProgram(channelId, now) {
  now = now || Date.now();
  const data = getPlaylistData(channelId);
  if (!data || data.cycleDuration === 0) return null;

  const elapsed = now - LIVETV_EPOCH;
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

function getBaseUrl(req) {
  if (LIVETV_BASE_URL) return LIVETV_BASE_URL;
  return `${req.protocol}://${req.get('host')}`;
}

function slugify(text) {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

// --- Library Scanner ---
app.post('/api/livetv/scan', async (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  try {
    const libRes = await axios.get(`${config.plex.url}/library/sections`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { Accept: 'application/json' }, timeout: 10000
    });
    const libraries = libRes.data.MediaContainer.Directory || [];
    let added = 0, updated = 0;

    const upsert = db.prepare(`
      INSERT INTO programs (plex_rating_key, title, type, show_title, season_num, episode_num,
        duration_ms, genre, year, thumb, art, content_rating, library_key, file_path, plex_key, updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, datetime('now'))
      ON CONFLICT(plex_rating_key) DO UPDATE SET
        title=excluded.title, duration_ms=excluded.duration_ms, genre=excluded.genre,
        year=excluded.year, thumb=excluded.thumb, art=excluded.art, content_rating=excluded.content_rating,
        file_path=excluded.file_path, updated_at=datetime('now')
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
            `/library/metadata/${item.ratingKey}`
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
                `/library/metadata/${ep.ratingKey}`
              );
              if (existing) updated++; else added++;
            }
          } catch (e) {
            console.error(`Failed to scan show ${show.title}:`, e.message);
          }
        }
      }
    }

    const total = db.prepare('SELECT COUNT(*) as cnt FROM programs').get().cnt;
    console.log(`LiveTV scan complete: ${added} added, ${updated} updated, ${total} total`);
    res.json({ success: true, added, updated, total });
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
  const { name, number, category, source_type, source_value, library_key, enabled, shuffle, logo_url } = req.body;
  const ch = db.prepare('SELECT * FROM channels WHERE id = ?').get(req.params.id);
  if (!ch) return res.status(404).json({ error: 'Channel not found' });

  db.prepare(`
    UPDATE channels SET name=?, number=?, slug=?, category=?, source_type=?, source_value=?,
      library_key=?, enabled=?, shuffle=?, logo_url=?, updated_at=datetime('now')
    WHERE id=?
  `).run(
    name || ch.name, number || ch.number, slugify(name || ch.name),
    category || ch.category, source_type || ch.source_type, source_value || ch.source_value,
    library_key !== undefined ? library_key : ch.library_key,
    enabled !== undefined ? (enabled ? 1 : 0) : ch.enabled,
    shuffle !== undefined ? (shuffle ? 1 : 0) : ch.shuffle,
    logo_url !== undefined ? logo_url : ch.logo_url,
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

  res.json({
    shows: Object.values(shows).sort((a, b) => a.name.localeCompare(b.name)),
    movies: movies.sort((a, b) => a.title.localeCompare(b.title)),
    totalPrograms: programs.length,
    excludedCount: excluded.length,
    filters: ch.source_value && ch.source_value.startsWith('{') ? JSON.parse(ch.source_value) : { genre: ch.source_value }
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

  // Shuffle if configured
  if (channel.shuffle) {
    // Deterministic shuffle using channel id as seed
    const seed = channelId * 2654435761;
    for (let i = programs.length - 1; i > 0; i--) {
      const j = Math.abs((seed * (i + 1) * 2246822519) % (i + 1));
      [programs[i], programs[j]] = [programs[j], programs[i]];
    }
  } else {
    // For TV episodes: sort by show, season, episode
    programs.sort((a, b) => {
      if (a.type === 'episode' && b.type === 'episode') {
        const showCmp = (a.show_title || '').localeCompare(b.show_title || '');
        if (showCmp !== 0) return showCmp;
        if ((a.season_num || 0) !== (b.season_num || 0)) return (a.season_num || 0) - (b.season_num || 0);
        return (a.episode_num || 0) - (b.episode_num || 0);
      }
      return a.title.localeCompare(b.title);
    });
  }

  // Get available fillers - prefer genre-matched trailers for this channel
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
  const fillers = typeMatched.length >= 3 ? typeMatched : matchedFillers.length >= 3 ? matchedFillers : allFillers;

  // Build playlist with fillers interleaved
  const insert = db.prepare('INSERT INTO channel_programming (channel_id, position, program_id, filler_id, duration_ms) VALUES (?,?,?,?,?)');
  const buildTx = db.transaction(() => {
    let pos = 0;
    let fillerIdx = 0;
    for (let i = 0; i < programs.length; i++) {
      // Insert filler before every N-th program
      if (fillers.length > 0 && i > 0 && i % LIVETV_FILLER_INTERVAL === 0) {
        const filler = fillers[fillerIdx % fillers.length];
        fillerIdx++;
        insert.run(channelId, pos, null, filler.id, filler.duration_ms);
        pos++;
      }
      insert.run(channelId, pos, programs[i].id, null, programs[i].duration_ms);
      pos++;
    }
  });
  buildTx();

  invalidatePlaylistCache(channelId);
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
      const seed = channelId * 2654435761;
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
    const onAir = isChannelOnAir(ch.id);
    const current = getCurrentProgram(ch.id);
    if (!current) return { channel: ch, current: null, next: null, onAir };
    const data = getPlaylistData(ch.id);
    const nextItem = data.playlist[current.nextIndex];
    return {
      channel: { id: ch.id, number: ch.number, name: ch.name, slug: ch.slug, logo_url: ch.logo_url || `${baseUrl}/api/livetv/logos/${ch.id}`, category: ch.category },
      onAir,
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

  const current = getCurrentProgram(channelId);
  if (!current) return res.status(503).json({ error: 'No programming available' });

  const ratingKey = current.item.prog_rkey || current.item.filler_rkey;
  if (!ratingKey) return res.status(503).json({ error: 'No playable content' });

  const offsetSec = Math.floor(current.offsetMs / 1000);
  const title = current.item.prog_title || current.item.filler_name || 'Unknown';

  // Look up media info from Plex to determine best playback method
  let streamUrl, streamType = 'direct', sessionId = null;
  try {
    const metaRes = await axios.get(`${config.plex.url}/library/metadata/${ratingKey}`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { Accept: 'application/json' }
    });
    const media = metaRes.data?.MediaContainer?.Metadata?.[0]?.Media?.[0];
    const part = media?.Part?.[0];
    const videoCodec = media?.videoCodec || '';
    const container = media?.container || '';
    const partKey = part?.key || '';

    // Check client type from query param
    const isDesktopApp = req.query.client === 'desktop';

    // Desktop app (Electron/Chromium) can direct-play H264 and HEVC in MP4/MKV
    // Browser can only direct-play H264 in MP4/M4V/MOV
    const canDirectPlay = isDesktopApp
      ? ['h264', 'hevc', 'h265'].includes(videoCodec) && ['mp4', 'm4v', 'mov', 'mkv'].includes(container)
      : videoCodec === 'h264' && ['mp4', 'm4v', 'mov'].includes(container);

    if (canDirectPlay && partKey) {
      // Direct play - fastest, no transcoding at all
      streamUrl = `${config.plex.url}${partKey}?X-Plex-Token=${config.plex.token}`;
      streamType = 'direct';
      console.log(`LiveTV Watch: Direct play for ${title} (${videoCodec}/${container}) client=${isDesktopApp?'desktop':'browser'}`);
    } else {
      // Need transcoding - use Plex universal transcode
      sessionId = `PCC-Watch-${Date.now()}`;
      streamUrl = `${config.plex.url}/video/:/transcode/universal/start?` + new URLSearchParams({
        path: `/library/metadata/${ratingKey}`,
        mediaIndex: '0',
        partIndex: '0',
        protocol: 'http',
        fastSeek: '1',
        directPlay: '1',
        directStream: '1',
        directStreamAudio: '1',
        videoQuality: '100',
        maxVideoBitrate: '20000',
        subtitleSize: '100',
        audioBoost: '100',
        location: 'lan',
        offset: String(offsetSec),
        hasMDE: '1',
        session: sessionId,
        'X-Plex-Platform': isDesktopApp ? 'Desktop' : 'Chrome',
        'X-Plex-Client-Identifier': sessionId,
        'X-Plex-Token': config.plex.token
      }).toString();
      streamType = 'transcode';
      console.log(`LiveTV Watch: Transcode for ${title} (${videoCodec}/${container}) client=${isDesktopApp?'desktop':'browser'}`);
    }
  } catch(e) {
    // Fallback to progressive transcode if metadata lookup fails
    sessionId = `PCC-Watch-${Date.now()}`;
    streamUrl = `${config.plex.url}/video/:/transcode/universal/start?` + new URLSearchParams({
      path: `/library/metadata/${ratingKey}`,
      mediaIndex: '0',
      partIndex: '0',
      protocol: 'http',
      fastSeek: '1',
      directPlay: '0',
      directStream: '1',
      directStreamAudio: '1',
      videoQuality: '100',
      maxVideoBitrate: '200000',
      location: 'lan',
      offset: String(offsetSec),
      session: sessionId,
      'X-Plex-Platform': 'Chrome',
      'X-Plex-Client-Identifier': sessionId,
      'X-Plex-Token': config.plex.token
    }).toString();
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
    watchId
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
        const progAtStart = getCurrentProgram(ch.id, range.start);
        if (progAtStart) {
          let idx = progAtStart.positionIndex;
          let currentTime = range.start - progAtStart.offsetMs;
          while (currentTime < range.end) {
            const item = data.playlist[idx];
            const startAt = Math.max(currentTime, range.start);
            const stopAt = Math.min(currentTime + item.duration_ms, range.end);
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
            }
            currentTime += item.duration_ms;
            idx = (idx + 1) % data.playlist.length;
          }
        }
        lastEnd = range.end;
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
  res.json(entries);
});

// --- HDHomeRun Emulation (matching ErsatzTV/Tunarr implementation) ---
const HDHR_DEVICE_ID = '12345678';

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
    TunerCount: 2
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
  const channels = db.prepare('SELECT * FROM channels WHERE enabled = 1 ORDER BY number').all();
  const baseUrl = getBaseUrl(req);
  const lineup = channels
    .filter(ch => isChannelOnAir(ch.id))
    .map(ch => ({
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
        xml += `  <programme start="${xmlDate(startAt)}" stop="${xmlDate(stopAt)}" channel="ch-${ch.number}">\n`;
        xml += `    <title>${escapeXml(showName)}</title>\n`;
        if (epTitle) xml += `    <sub-title>${escapeXml(epTitle)}</sub-title>\n`;
        if (item.prog_thumb) {
          const thumbUrl = `${config.plex.url}${item.prog_thumb}?X-Plex-Token=${config.plex.token}`;
          xml += `    <icon src="${escapeXml(thumbUrl)}"/>\n`;
        }
        if (item.prog_genre) xml += `    <category>${escapeXml(item.prog_genre.split(',')[0])}</category>\n`;
        if (item.prog_year) xml += `    <date>${item.prog_year}</date>\n`;
        if (item.season_num && item.episode_num) {
          xml += `    <episode-num system="onscreen">S${String(item.season_num).padStart(2,'0')}E${String(item.episode_num).padStart(2,'0')}</episode-num>\n`;
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
  const onAir = isChannelOnAir(ch.id);
  res.json({ channelId: ch.id, channelName: ch.name, onAir, timeRules });
});

// --- Stream via ffmpeg MPEG-TS (continuous - chains programs automatically) ---
// Handle both /api/livetv/stream/2 and /api/livetv/stream/2.ts
app.get('/api/livetv/stream/:channelId', async (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  const channelId = parseInt(req.params.channelId.replace(/\.ts$/, ''));
  const ch = db.prepare('SELECT * FROM channels WHERE id = ?').get(channelId);
  if (!ch) return res.status(404).json({ error: 'Channel not found' });

  if (!isChannelOnAir(channelId)) {
    return res.status(503).json({ error: 'Channel is currently off air' });
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

  // Stream programs continuously until client disconnects or channel goes off air
  const streamNextProgram = async () => {
    if (clientDisconnected || res.writableEnded) return;

    if (!isChannelOnAir(channelId)) {
      console.log(`[LiveTV] Channel ${ch.number} went off air, ending stream`);
      if (!res.writableEnded) res.end();
      return;
    }

    const prog = getCurrentProgram(channelId);
    if (!prog) {
      console.log(`[LiveTV] No more programming for ch=${ch.number}, ending stream`);
      if (!res.writableEnded) res.end();
      return;
    }

    const progRkey = prog.item.prog_rkey || prog.item.filler_rkey;
    if (!progRkey) {
      console.log(`[LiveTV] No playable content for ch=${ch.number}, ending stream`);
      if (!res.writableEnded) res.end();
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
      if (!partKey) throw new Error('No media part found');

      const fileUrl = `${config.plex.url}${partKey}?X-Plex-Token=${config.plex.token}`;
      const videoCodec = metadata?.Media?.[0]?.videoCodec || 'unknown';
      const audioCodec = metadata?.Media?.[0]?.audioCodec || 'unknown';

      const segStart = Date.now();
      let segBytes = 0;
      const title = prog.item.prog_title || prog.item.filler_name || 'Unknown';
      console.log(`[LiveTV] Stream ch=${ch.number} "${title}" rk=${progRkey} offset=${offsetSec}s video=${videoCodec} audio=${audioCodec}`);

      const needsTranscode = ['hevc', 'h265', 'vp9', 'av1'].includes(videoCodec);
      const videoArgs = needsTranscode
        ? ['-c:v', 'libx264', '-preset', 'ultrafast', '-tune', 'zerolatency',
           '-crf', '23', '-profile:v', 'main', '-level', '4.0', '-pix_fmt', 'yuv420p',
           '-b:v', '4M', '-maxrate', '5M', '-bufsize', '8M',
           '-g', '48', '-keyint_min', '48', '-sc_threshold', '0']
        : ['-c:v', 'copy'];
      const audioArgs = ['-c:a', 'aac', '-b:a', '192k', '-ac', '2'];

      console.log(`[LiveTV] Video: ${needsTranscode ? 'transcode' : 'copy'} (${videoCodec}), Audio: transcode to aac`);

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
      streamNextProgram();
    } catch (error) {
      console.error('[LiveTV] Stream segment error:', error.message);
      // Don't end the stream on a single segment error - skip to next program
      const title = prog?.item?.prog_title || prog?.item?.filler_name || 'Unknown';
      console.log(`[LiveTV] Skipping failed segment "${title}", advancing to next program`);
      // Wait the remaining duration virtually so the clock advances past this broken item
      const skipMs = Math.min(prog?.remainingMs || 5000, 5000);
      await new Promise(r => setTimeout(r, skipMs));
      if (!clientDisconnected && !res.writableEnded) {
        streamNextProgram();
      } else {
        if (!res.writableEnded) res.end();
      }
    }
  };

  streamNextProgram();
});

// --- Filler CRUD ---
app.get('/api/livetv/fillers', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).json({ error: 'LiveTV not enabled' });
  res.json(db.prepare('SELECT * FROM fillers ORDER BY name').all());
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
      INSERT OR IGNORE INTO fillers (name, type, plex_rating_key, duration_ms, plex_key, genre, parent_title, library_key, content_type)
      VALUES (?,?,?,?,?,?,?,?,?)
    `);
    // Ensure unique constraint on plex_rating_key for OR IGNORE
    try { db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_fillers_rkey ON fillers(plex_rating_key)'); } catch(e) {}

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
                const name = `${ex.title || item.title}`;
                const result = insertFiller.run(name, 'trailer', rkey, ex.duration, `/library/metadata/${rkey}`, genre, item.title, lib.key, contentType);
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
    console.log(`LiveTV: Trailer scan complete - scanned ${scanned} items, added ${added} trailers`);
    res.json({ success: true, added, scanned });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
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

// --- Channel Logos ---
app.get('/api/livetv/logos/:channelId', (req, res) => {
  if (!LIVETV_ENABLED) return res.status(404).send();
  const logo = db.prepare('SELECT mime_type, data FROM channel_logos WHERE channel_id = ?').get(req.params.channelId);
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  if (logo) {
    res.set('Content-Type', logo.mime_type);
    res.send(logo.data);
  } else {
    // Generate a simple SVG placeholder
    const ch = db.prepare('SELECT name, number FROM channels WHERE id = ?').get(req.params.channelId);
    const label = ch ? ch.number : '?';
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

app.get('/api/health', (req, res) => {
  const liveTvInfo = {};
  if (LIVETV_ENABLED && db) {
    liveTvInfo.channels = db.prepare('SELECT COUNT(*) as cnt FROM channels WHERE enabled = 1').get().cnt;
    liveTvInfo.programs = db.prepare('SELECT COUNT(*) as cnt FROM programs').get().cnt;
  }
  res.json({
    status: 'ok', version: '2.5.2',
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

app.listen(PORT, () => {
  console.log(`\n╔══════════════════════════════════════════════════╗`);
  console.log(`║  🎬 Plex Command Center v2.5.2                  ║`);
  console.log(`║  Port: ${PORT}                                       ║`);
  console.log(`║  Plex:       ${config.plex.token ? '✅' : '❌'}                               ║`);
  console.log(`║  Tautulli:   ${config.tautulli.apiKey ? '✅' : '❌'}                               ║`);
  console.log(`║  Jellyseerr: ${config.jellyseerr.apiKey ? '✅' : '❌'}                               ║`);
  console.log(`║  Zabbix:     ${config.zabbix.url ? '✅' : '⚠️  Not configured'}              ║`);
  console.log(`║  LiveTV:     ${LIVETV_ENABLED ? '✅' : '❌'}                               ║`);
  console.log(`╚══════════════════════════════════════════════════╝\n`);
});