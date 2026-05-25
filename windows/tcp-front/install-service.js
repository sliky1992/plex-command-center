// Installs PCC-TCP-Front as a Windows service. Run elevated:
//   "C:\Program Files\PlexCommandCenter\node\node.exe" install-service.js

const path = require('path');
let Service;
try { Service = require('node-windows').Service; }
catch (e) {
  console.error('node-windows missing. From PCC dir:  npm install node-windows --no-save');
  process.exit(1);
}

const env = [];
for (const k of ['TCP_PORT', 'PMS_HOST', 'PMS_PORT', 'PCC_DB_PATH']) {
  if (process.env[k]) env.push({ name: k, value: process.env[k] });
}

const svc = new Service({
  name: 'PCC-TCP-Front',
  description: 'TCP pass-through gateway with IP geofence for Plex Media Server',
  script: path.join(__dirname, 'index.js'),
  env,
});

svc.on('install', () => { console.log('Installed. Starting...'); svc.start(); });
svc.on('alreadyinstalled', () => console.log('Already installed.'));
svc.on('start', () => console.log('Started. Service: PCC-TCP-Front'));
svc.on('error', (err) => console.error('Service error:', err));
svc.install();
