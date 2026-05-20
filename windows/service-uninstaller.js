// Removes the PlexCommandCenter Windows Service. Run from an elevated shell:
//   npm run service:uninstall
// Note: this does NOT delete the data directory (%ProgramData%\PlexCommandCenter).

const path = require('path');

if (process.platform !== 'win32') {
  console.error('This script is Windows-only.');
  process.exit(1);
}

let Service;
try { ({ Service } = require('node-windows')); }
catch (e) {
  console.error('node-windows is not installed.');
  process.exit(1);
}

const APP_DIR = path.resolve(__dirname, '..');
const SCRIPT = path.join(APP_DIR, 'backend-server-v2.5.2-final.js');

const svc = new Service({
  name: 'PlexCommandCenter',
  script: SCRIPT
});

svc.on('uninstall', () => {
  console.log(`[uninstall] Service "${svc.name}" removed.`);
  console.log('[uninstall] Data dir was not touched — delete manually if you also want to wipe DBs and fillers.');
});
svc.on('alreadyuninstalled', () => console.log(`[uninstall] Service "${svc.name}" was not installed.`));
svc.on('error', (e) => console.error('[uninstall] Error:', e));

svc.uninstall();
