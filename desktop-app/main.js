const { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage, dialog } = require('electron');
const path = require('path');
const https = require('https');
const http = require('http');

let mainWindow = null;
let tray = null;
let serverUrl = '';

// Store settings in userData
const settingsPath = path.join(app.getPath('userData'), 'settings.json');
const fs = require('fs');

function loadSettings() {
  try {
    return JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
  } catch (e) {
    return { serverUrl: '', volume: 80, lastChannel: null, alwaysOnTop: false };
  }
}

function saveSettings(settings) {
  try {
    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
  } catch (e) {}
}

function createWindow() {
  const settings = loadSettings();

  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 800,
    minHeight: 500,
    title: 'Plex LiveTV',
    backgroundColor: '#0a0e27',
    frame: false,
    titleBarStyle: 'hidden',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    },
    alwaysOnTop: settings.alwaysOnTop || false,
    icon: path.join(__dirname, 'icon.png')
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // System tray
  try {
    const iconPath = path.join(__dirname, 'icon.png');
    const trayIcon = nativeImage.createFromPath(iconPath).resize({ width: 16, height: 16 });
    tray = new Tray(trayIcon);
    tray.setToolTip('Plex LiveTV');
    tray.on('click', () => {
      if (mainWindow) {
        mainWindow.isVisible() ? mainWindow.hide() : mainWindow.show();
      }
    });
    const contextMenu = Menu.buildFromTemplate([
      { label: 'Show', click: () => mainWindow && mainWindow.show() },
      { label: 'Always on Top', type: 'checkbox', checked: settings.alwaysOnTop, click: (item) => {
        const s = loadSettings();
        s.alwaysOnTop = item.checked;
        saveSettings(s);
        if (mainWindow) mainWindow.setAlwaysOnTop(item.checked);
      }},
      { type: 'separator' },
      { label: 'Quit', click: () => app.quit() }
    ]);
    tray.setContextMenu(contextMenu);
  } catch (e) {
    console.log('Tray icon skipped:', e.message);
  }
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

// IPC handlers
ipcMain.handle('get-settings', () => loadSettings());
ipcMain.handle('save-settings', (event, settings) => {
  saveSettings(settings);
  if (mainWindow && settings.alwaysOnTop !== undefined) {
    mainWindow.setAlwaysOnTop(settings.alwaysOnTop);
  }
  return true;
});

ipcMain.handle('window-minimize', () => mainWindow && mainWindow.minimize());
ipcMain.handle('window-maximize', () => {
  if (mainWindow) {
    mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize();
  }
});
ipcMain.handle('window-close', () => mainWindow && mainWindow.close());
ipcMain.handle('window-toggle-fullscreen', () => {
  if (mainWindow) mainWindow.setFullScreen(!mainWindow.isFullScreen());
});
ipcMain.handle('window-is-maximized', () => mainWindow && mainWindow.isMaximized());
ipcMain.handle('window-is-fullscreen', () => mainWindow && mainWindow.isFullScreen());

// Notify renderer of fullscreen state changes
app.on('browser-window-created', (_, win) => {
  win.on('enter-full-screen', () => win.webContents.send('fullscreen-changed', true));
  win.on('leave-full-screen', () => win.webContents.send('fullscreen-changed', false));
});
