// Plex Command Center v2.5.2 - Complete Fixed Backend
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const si = require('systeminformation');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());
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
        rx: Math.round(rxTotal / 1024 / 8), // bits to KB/s
        tx: Math.round(txTotal / 1024 / 8)
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
      memory: Math.round((mem.used / mem.total) * 1000) / 10,
      network: { rx: Math.round((net[0]?.rx_sec || 0) / 1024), tx: Math.round((net[0]?.tx_sec || 0) / 1024) }
    });
    if (dockerHistory.length > 720) dockerHistory.shift();
  } catch (e) {}
}, 5000);

app.get('/api/docker/resources', async (req, res) => {
  try {
    const [cpu, mem, disks, net] = await Promise.all([si.currentLoad(), si.mem(), si.fsSize(), si.networkStats()]);
    
    // Get actual directory sizes using du command
    const { execSync } = require('child_process');
    const directories = ['/app', '/app/logs', '/app/data', '/app/public', '/tmp'];
    const dirSizes = [];
    
    for (const dir of directories) {
      try {
        const output = execSync(`du -sb ${dir} 2>/dev/null | cut -f1`).toString().trim();
        const bytes = parseInt(output);
        if (bytes > 0) {
          dirSizes.push({
            name: dir,
            mount: dir,
            label: dir.replace('/app/', ''),
            total: Math.round(bytes / 1048576), // MB
            used: Math.round(bytes / 1048576),
            percentage: 0, // Will calculate based on parent
            sizeFormatted: bytes > 1073741824 
              ? `${(bytes / 1073741824).toFixed(2)} GB`
              : `${(bytes / 1048576).toFixed(1)} MB`
          });
        }
      } catch (e) {
        // Directory doesn't exist or can't read
      }
    }
    
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
      memory: Math.round((mem.used / mem.total) * 1000) / 10,
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

    // Extract IPs from PLEX_URL
    const plexUrlObj = new URL(config.plex.url);
    const localIP = plexUrlObj.hostname;

    res.json({
      online: true,
      friendlyName: mc.friendlyName || 'Plex Media Server',
      version: mc.version,
      platform: mc.platform,
      platformVersion: mc.platformVersion,
      localIP: localIP,
      tailscaleIP: process.env.TAILSCALE_IP || localIP,
      libraryCount: libraries.length,
      libraries: libraries.map(l => ({ key: l.key, title: l.title, type: l.type, count: l.count })),
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
      sessionId: s.sessionKey,
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
    await axios.delete(`${config.plex.url}/status/sessions/terminate`, {
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

// Collections with posters
app.get('/api/plex/collections', async (req, res) => {
  try {
    const libRes = await axios.get(`${config.plex.url}/library/sections`, {
      params: { 'X-Plex-Token': config.plex.token },
      headers: { 'Accept': 'application/json' },
      timeout: 5000
    });

    const allCollections = [];
    for (const lib of libRes.data.MediaContainer.Directory || []) {
      try {
        const colRes = await axios.get(`${config.plex.url}/library/sections/${lib.key}/collections`, {
          params: { 'X-Plex-Token': config.plex.token },
          headers: { 'Accept': 'application/json' },
          timeout: 5000
        });
        (colRes.data.MediaContainer.Metadata || []).forEach(col => {
          allCollections.push({
            key: col.ratingKey, title: col.title,
            thumb: col.thumb ? `${config.plex.url}${col.thumb}?X-Plex-Token=${config.plex.token}` : null,
            art: col.art ? `${config.plex.url}${col.art}?X-Plex-Token=${config.plex.token}` : null,
            itemCount: col.childCount || 0,
            library: lib.title, libraryKey: lib.key, summary: col.summary || ''
          });
        });
      } catch (e) {}
    }
    res.json(allCollections);
  } catch (error) {
    res.json([]);
  }
});

// Create collection by genre/year/actor
app.post('/api/plex/collections/create', async (req, res) => {
  try {
    const { libraryKey, title, type, value } = req.body;

    if (!libraryKey || !title) {
      return res.status(400).json({ success: false, error: 'libraryKey and title required' });
    }

    // Step 1: Find matching items in the library
    let filterParams = {};
    if (type === 'genre') filterParams.genre = value;
    else if (type === 'year') {
      const decade = parseInt(value);
      filterParams['year>>'] = decade;
      filterParams['year<<'] = decade + 9;
    }

    const itemsRes = await axios.get(`${config.plex.url}/library/sections/${libraryKey}/all`, {
      params: { 'X-Plex-Token': config.plex.token, ...filterParams },
      headers: { 'Accept': 'application/json' },
      timeout: 10000
    });

    const items = itemsRes.data.MediaContainer.Metadata || [];

    if (items.length === 0) {
      return res.json({ success: false, error: `No items found for ${type}: ${value}` });
    }

    // Step 2: Create the collection via Plex API
    const createRes = await axios.post(
      `${config.plex.url}/library/collections`,
      null,
      {
        params: {
          'X-Plex-Token': config.plex.token,
          type: 1, // 1 = movie, 2 = show
          title: title,
          smart: 0,
          sectionId: libraryKey,
          uri: items.slice(0, 50).map(i => `server://localhost/com.plexapp.plugins.library/library/metadata/${i.ratingKey}`).join(',')
        },
        headers: { 'Accept': 'application/json' },
        timeout: 10000
      }
    );

    res.json({
      success: true,
      message: `Collection "${title}" created with ${items.length} items`,
      itemCount: items.length
    });
  } catch (error) {
    console.error('Collection create error:', error.message);
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
      size: item.Media?.[0]?.size || 0,
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
        order_column: 'total_plays',
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
    res.json(response.data.response.data || {});
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

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok', version: '2.5.2',
    timestamp: new Date().toISOString(),
    services: {
      plex: !!config.plex.token,
      tautulli: !!config.tautulli.apiKey,
      jellyseerr: !!config.jellyseerr.apiKey,
      zabbix: !!config.zabbix.url
    }
  });
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
  console.log(`╚══════════════════════════════════════════════════╝\n`);
});