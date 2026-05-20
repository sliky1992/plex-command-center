// Installs Plex Command Center as a Windows Service via node-windows.
// Run from an *elevated* PowerShell / cmd:
//
//   npm run service:install
//
// On success: the service is registered, started, and set to auto-start at boot.
// node-windows wraps the node binary in a small native helper (winsw) so the service
// survives node version upgrades and restarts automatically on crash.

const path = require('path');
const fs = require('fs');

if (process.platform !== 'win32') {
  console.error('This script is Windows-only. On Linux/macOS just run "npm start".');
  process.exit(1);
}

let Service;
try { ({ Service } = require('node-windows')); }
catch (e) {
  console.error('node-windows is not installed. Run: npm install node-windows --production');
  process.exit(1);
}

const APP_DIR = path.resolve(__dirname, '..');
const SCRIPT = path.join(APP_DIR, 'backend-server-v2.5.2-final.js');
const DEFAULT_DATA_DIR = path.join(process.env.PROGRAMDATA || 'C:\\ProgramData', 'PlexCommandCenter');
const DEFAULT_BIN_DIR  = path.join(APP_DIR, 'bin');

if (!fs.existsSync(SCRIPT)) {
  console.error(`Backend script not found at ${SCRIPT}.`);
  process.exit(1);
}

const svc = new Service({
  name: 'PlexCommandCenter',
  description: 'Plex monitoring + Virtual Live TV web app',
  script: SCRIPT,
  workingDirectory: APP_DIR,
  // Auto-restart on crash; back off so we don't churn if Plex is unreachable on boot.
  wait: 2,
  grow: .5,
  maxRetries: 60,
  env: [
    { name: 'NODE_ENV', value: 'production' },
    { name: 'PCC_DATA_DIR', value: process.env.PCC_DATA_DIR || DEFAULT_DATA_DIR },
    { name: 'PCC_BIN_DIR',  value: process.env.PCC_BIN_DIR  || DEFAULT_BIN_DIR  },
    { name: 'PORT',         value: process.env.PORT         || '3001' }
  ]
});

svc.on('install', () => {
  console.log(`[install] Service "${svc.name}" installed.`);
  console.log(`[install] Data dir : ${process.env.PCC_DATA_DIR || DEFAULT_DATA_DIR}`);
  console.log(`[install] Bin dir  : ${process.env.PCC_BIN_DIR  || DEFAULT_BIN_DIR }`);
  console.log('[install] Starting…');
  svc.start();
});
svc.on('alreadyinstalled', () => {
  console.log(`[install] Service "${svc.name}" is already installed.`);
  console.log('[install] Run "npm run service:uninstall" first if you want to re-create it.');
});
svc.on('start',   () => console.log(`[install] Service started. Open http://localhost:${process.env.PORT || 3001}`));
svc.on('error',   (e) => console.error('[install] Service error:', e));
svc.on('invalidinstallation', () => console.error('[install] Invalid installation — try removing the Service Wrapper files in node_modules/node-windows/lib/winsw and re-running.'));

svc.install();
