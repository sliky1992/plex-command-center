// PCC TCP Front
// Pure TCP pass-through proxy on TCP_PORT. Checks the client IP against PCC's
// existing regional geofence (read from pcc.db) before forwarding raw bytes
// to the Plex Media Server (which terminates TLS with its own *.plex.direct
// cert). Lets us geofence without ever decrypting TLS, sidestepping the need
// to extract Plex's PKCS#12 password.
//
// Required: better-sqlite3 (bundled with PCC's node_modules).
// Optional env:
//   TCP_PORT      - listen port (default: 32401)
//   PMS_HOST      - Plex host (default: 127.0.0.1)
//   PMS_PORT      - Plex port (default: 32400)
//   PCC_DB_PATH   - pcc.db (default: C:\ProgramData\PlexCommandCenter\pcc.db)

const net   = require('net');
const http  = require('http');
const fs    = require('fs');

let Database;
try { Database = require('better-sqlite3'); }
catch (e) {
  console.error('[tcp-front] better-sqlite3 missing. From PCC dir:  npm install better-sqlite3 --no-save');
  process.exit(1);
}

const TCP_PORT = parseInt(process.env.TCP_PORT, 10) || 32401;
const PMS_HOST = process.env.PMS_HOST || '127.0.0.1';
const PMS_PORT = parseInt(process.env.PMS_PORT, 10) || 32400;
const DB_PATH  = process.env.PCC_DB_PATH || 'C:\\ProgramData\\PlexCommandCenter\\pcc.db';

if (!fs.existsSync(DB_PATH)) {
  console.error('[tcp-front] pcc.db not found at:', DB_PATH);
  console.error('  Set PCC_DB_PATH if it lives elsewhere.');
  process.exit(1);
}
const db = new Database(DB_PATH);

// --- Geofence config (refreshed every 60s) ---------------------------------
let cfg = { enabled: false, allowedCountries: new Set(), whitelist: new Set() };
function refreshCfg() {
  try {
    const rows = db.prepare("SELECT key, value FROM regional_settings").all();
    const s = Object.fromEntries(rows.map(r => [r.key, r.value]));
    cfg.enabled = s.enabled === '1';
    // allowed_countries is JSON-encoded in current PCC, was comma-separated in older builds.
    let countries = [];
    const raw = s.allowed_countries || '';
    try {
      const parsed = JSON.parse(raw);
      countries = Array.isArray(parsed)
        ? parsed.map(String)
        : String(parsed).split(',');
    } catch (_) {
      countries = raw.split(',');
    }
    cfg.allowedCountries = new Set(countries.map(x => x.trim()).filter(Boolean));
    const wl = db.prepare("SELECT ip_address FROM regional_whitelist").all();
    cfg.whitelist = new Set(wl.map(r => r.ip_address));
  } catch (e) { console.error('[tcp-front] cfg refresh failed:', e.message); }
}
refreshCfg();
setInterval(refreshCfg, 60_000);

// --- Geo lookup (ip-api.com, 24h cache) ------------------------------------
const geoCache = new Map();
const GEO_TTL_MS = 24 * 60 * 60 * 1000;
function isPrivate(ip) {
  return /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fc00:|fd00:|fe80:)/i.test(ip);
}
// ip-api.com free tier is HTTP-only (HTTPS = 403). 45 req/min limit.
function lookupCountry(ip) {
  return new Promise((resolve) => {
    const c = geoCache.get(ip);
    if (c && Date.now() - c.ts < GEO_TTL_MS) return resolve(c.country);
    const url = `http://ip-api.com/json/${ip}?fields=status,country,countryCode,message`;
    const req = http.get(url, { timeout: 4000 }, (res) => {
      let buf = '';
      res.on('data', d => buf += d);
      res.on('end', () => {
        let country = 'Unknown';
        try {
          const j = JSON.parse(buf);
          if (j.status === 'success') {
            country = j.country || j.countryCode || 'Unknown';
          } else {
            console.warn(`[tcp-front] geo lookup ${ip}: ${j.message || 'unknown error'} (status ${res.statusCode})`);
          }
        } catch (e) {
          console.warn(`[tcp-front] geo lookup ${ip}: parse failed (status ${res.statusCode}): ${buf.slice(0,80)}`);
        }
        // Cache failures for 5 minutes so we don't hammer the API on retry storms.
        const ttl = country === 'Unknown' ? 5 * 60 * 1000 : GEO_TTL_MS;
        geoCache.set(ip, { country, ts: Date.now() - (GEO_TTL_MS - ttl) });
        resolve(country);
      });
    });
    req.on('timeout', () => { req.destroy(); console.warn(`[tcp-front] geo lookup ${ip}: timeout`); resolve('Unknown'); });
    req.on('error', (e) => { console.warn(`[tcp-front] geo lookup ${ip}: ${e.message}`); resolve('Unknown'); });
  });
}

// --- Log into PCC's gateway_log so the UI shows TCP events -----------------
const logStmt = db.prepare(
  'INSERT INTO gateway_log (ip_address, country, city, allowed, action, url_path) VALUES (?,?,?,?,?,?)'
);
const _allowSeen = new Map();   // dedupe allow logs to one per (ip, day)
function logEvent(ip, country, allowed, action) {
  try {
    if (allowed) {
      const key = ip + '|' + new Date().toISOString().slice(0, 10);
      if (_allowSeen.has(key)) return;
      _allowSeen.set(key, true);
      if (_allowSeen.size > 5000) {
        const today = new Date().toISOString().slice(0, 10);
        for (const k of _allowSeen.keys()) if (!k.endsWith(today)) _allowSeen.delete(k);
      }
    }
    logStmt.run(ip, country || null, null, allowed ? 1 : 0, action, '[TCP]');
  } catch (_) { /* never let logging break the proxy */ }
}

// --- Decision --------------------------------------------------------------
async function decide(ip) {
  if (!cfg.enabled) return { allow: true, country: 'GeoOff', reason: 'geofence_disabled' };
  if (isPrivate(ip)) return { allow: true, country: 'Local', reason: 'private_ip' };
  if (cfg.whitelist.has(ip)) return { allow: true, country: 'Whitelist', reason: 'whitelisted' };
  const country = await lookupCountry(ip);
  if (cfg.allowedCountries.has(country)) return { allow: true, country, reason: 'allowed_country' };
  return { allow: false, country, reason: 'geofence' };
}

// --- TCP server ------------------------------------------------------------
const server = net.createServer((client) => {
  const ip = (client.remoteAddress || '').replace(/^::ffff:/, '');
  decide(ip).then((d) => {
    if (!d.allow) {
      logEvent(ip, d.country, false, 'deny');
      console.log(`[tcp-front] deny  ${ip}  (${d.country})`);
      client.destroy();
      return;
    }
    logEvent(ip, d.country, true, 'allow');
    console.log(`[tcp-front] allow ${ip}  (${d.country})`);
    const upstream = net.createConnection(PMS_PORT, PMS_HOST, () => {
      client.pipe(upstream).pipe(client);
    });
    upstream.on('error', (e) => { console.error('[tcp-front] upstream error:', e.message); client.destroy(); });
    client.on('error',   () => upstream.destroy());
  });
});

server.on('error', (err) => {
  console.error('[tcp-front] server error:', err.message);
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${TCP_PORT} is already bound. Stop the PCC HTTP gateway first (Security tab in PCC).`);
    process.exit(1);
  }
});

server.listen(TCP_PORT, () => {
  console.log(`[tcp-front] TCP on :${TCP_PORT} -> ${PMS_HOST}:${PMS_PORT}`);
  console.log(`[tcp-front] DB: ${DB_PATH}`);
  console.log(`[tcp-front] geofence enabled=${cfg.enabled}  allowed=[${[...cfg.allowedCountries].join(',')}]  whitelist=${cfg.whitelist.size}`);
});
