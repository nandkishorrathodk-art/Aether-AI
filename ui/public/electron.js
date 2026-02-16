const { app, BrowserWindow, ipcMain, Tray, Menu, globalShortcut } = require('electron');
const path = require('path');
const Store = require('electron-store');
const isDev = process.env.NODE_ENV === 'development';

const store = new Store();
let mainWindow;
let tray;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 420,              // Voice-optimized width
    height: 600,             // Voice-optimized height
    minWidth: 380,           // Minimum width
    minHeight: 550,          // Minimum height
    frame: false,            // Frameless for custom drag bar
    transparent: true,       // Transparent for rounded corners
    alwaysOnTop: true,       // Float above other windows
    resizable: true,         // Can resize
    movable: true,           // Can drag
    hasShadow: true,         // Shadow effect
    show: false,             // Don't show until ready
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      enableRemoteModule: false,
      preload: path.join(__dirname, 'preload.js')
    },
    icon: path.join(__dirname, 'assets', 'icon.png'),
    backgroundColor: '#00000000', // Fully transparent
    titleBarStyle: 'hidden',
    autoHideMenuBar: true
  });

  const startURL = isDev
    ? 'http://localhost:3000'
    : `file://${path.join(__dirname, 'build/index.html')}`;

  mainWindow.loadURL(startURL);

  // Show window when ready
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    mainWindow.focus();
  });

  // DevTools only in dev mode
  if (isDev) {
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  mainWindow.on('minimize', (event) => {
    if (process.platform === 'win32') {
      event.preventDefault();
      mainWindow.hide();
    }
  });

  // Handle window control IPC messages
  ipcMain.on('minimize-window', () => {
    if (mainWindow) mainWindow.minimize();
  });

  ipcMain.on('close-window', () => {
    if (mainWindow) mainWindow.close();
  });

  ipcMain.on('maximize-window', () => {
    if (mainWindow) {
      if (mainWindow.isMaximized()) {
        mainWindow.unmaximize();
      } else {
        mainWindow.maximize();
      }
    }
  });

  createTray();
}

function createTray() {
  const iconPath = path.join(__dirname, 'assets', 'tray-icon.png');
  tray = new Tray(iconPath);

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Show Aether',
      click: () => {
        mainWindow.show();
      }
    },
    {
      label: 'Hide Aether',
      click: () => {
        mainWindow.hide();
      }
    },
    { type: 'separator' },
    {
      label: 'Voice Input',
      type: 'checkbox',
      checked: true,
      click: (menuItem) => {
        mainWindow.webContents.send('toggle-voice-input', menuItem.checked);
      }
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => {
        app.quit();
      }
    }
  ]);

  tray.setToolTip('Aether AI');
  tray.setContextMenu(contextMenu);

  tray.on('click', () => {
    mainWindow.isVisible() ? mainWindow.hide() : mainWindow.show();
  });
}

app.on('ready', () => {
  createWindow();
  
  globalShortcut.register('CommandOrControl+Space', () => {
    if (mainWindow) {
      mainWindow.webContents.send('activate-voice-input');
    }
  });

  const autoLaunch = store.get('autoLaunch', false);
  if (autoLaunch) {
    app.setLoginItemSettings({
      openAtLogin: true,
      path: process.execPath
    });
  }
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  }
});

app.on('will-quit', () => {
  globalShortcut.unregisterAll();
});

ipcMain.on('minimize-to-tray', () => {
  mainWindow.hide();
});

ipcMain.on('show-window', () => {
  mainWindow.show();
});

ipcMain.handle('get-store-value', (event, key, defaultValue) => {
  return store.get(key, defaultValue);
});

ipcMain.handle('set-store-value', (event, key, value) => {
  store.set(key, value);
  return true;
});

ipcMain.handle('set-auto-launch', (event, enabled) => {
  app.setLoginItemSettings({
    openAtLogin: enabled,
    path: process.execPath
  });
  store.set('autoLaunch', enabled);
  return true;
});

ipcMain.handle('show-notification', (event, title, body) => {
  if (mainWindow) {
    mainWindow.webContents.send('show-notification', { title, body });
  }
  return true;
});
