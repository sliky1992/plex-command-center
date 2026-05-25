// Uninstalls PCC-TCP-Front Windows service. Run elevated.
const path = require('path');
const Service = require('node-windows').Service;
const svc = new Service({ name: 'PCC-TCP-Front', script: path.join(__dirname, 'index.js') });
svc.on('uninstall', () => console.log('Uninstalled.'));
svc.on('alreadyuninstalled', () => console.log('Was not installed.'));
svc.on('error', (err) => console.error('Error:', err));
svc.uninstall();
