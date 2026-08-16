import { app, BrowserWindow, shell, ipcMain, dialog } from 'electron'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import os from 'node:os'
import { showNotification } from './notify'
import { type NotifyOption, type Config } from '../../type'
import { init } from './init'
import { getRealImageData } from './image'
import { getConfig, writeConfig } from './config'
import { checkTheme } from './theme'
import { registerVaultIpc, lockVault, shutdownBackend } from './vault'


// const require = createRequire(import.meta.url)
const __dirname = path.dirname(fileURLToPath(import.meta.url))

// The built directory structure
//
// ├─┬ dist-electron
// │ ├─┬ main
// │ │ └── index.js    > Electron-Main
// │ └─┬ preload
// │   └── index.mjs   > Preload-Scripts
// ├─┬ dist
// │ └── index.html    > Electron-Renderer
//
process.env.APP_ROOT = path.join(__dirname, '../..')

export const MAIN_DIST = path.join(process.env.APP_ROOT, 'dist-electron')
export const RENDERER_DIST = path.join(process.env.APP_ROOT, 'dist')
export const VITE_DEV_SERVER_URL = process.env.VITE_DEV_SERVER_URL

process.env.VITE_PUBLIC = VITE_DEV_SERVER_URL
  ? path.join(process.env.APP_ROOT, 'public')
  : RENDERER_DIST

// Disable GPU Acceleration for Windows 7
if (os.release().startsWith('6.1')) app.disableHardwareAcceleration();

// Set application name for Windows 10+ notifications
if (process.platform === 'win32') app.setAppUserModelId(app.getName());

if (!app.requestSingleInstanceLock()) {
  app.quit();
  process.exit(0);
}

export let win: BrowserWindow | null = null;
const preload = path.join(__dirname, '../preload/index.mjs');
const indexHtml = path.join(RENDERER_DIST, 'index.html');

async function createWindow() {
  win = new BrowserWindow({
    title: 'Shinkuro 保险柜',
    icon: path.join(process.env.VITE_PUBLIC, 'icon.ico'),
    autoHideMenuBar: true,
    width: 900,
    height: 650,
    minWidth: 900,
    minHeight: 650,
    webPreferences: {
      preload,
      devTools: false,
      // Warning: Enable nodeIntegration and disable contextIsolation is not secure in production
      // nodeIntegration: true,

      // Consider using contextBridge.exposeInMainWorld
      // Read more on https://www.electronjs.org/docs/latest/tutorial/context-isolation
      // contextIsolation: false,
    },
  })

  if (VITE_DEV_SERVER_URL) {
    win.loadURL(VITE_DEV_SERVER_URL)
    // Open devTool if the app is not packaged
    // win.webContents.openDevTools()
  } else {
    win.loadFile(indexHtml);
  }

  win.webContents.on('did-finish-load', () => {
    win?.webContents.send('main-process-message', new Date().toLocaleString());
    win?.webContents.send('main-process-message', app.getName())
  })

  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https:') || url.startsWith('http:')) shell.openExternal(url)
    return { action: 'deny' }
  })

  win.on('close', () => {
    lockVault(); // 关闭窗口即锁定保险柜并清除敏感信息
  });
}

function quitApp() {
  shutdownBackend();
  if (win) {
    win.destroy();
  }
  app.quit();
}

app.whenReady().then(()=>{
  registerVaultIpc();
  createWindow();
})

app.on('before-quit', () => {
  shutdownBackend();
})

app.on('window-all-closed', () => {
  win = null
  if (process.platform !== 'darwin') app.quit()
})

ipcMain.on("init", () => {
  init()
})

ipcMain.on("show-notification", (_, option: NotifyOption) => {
  showNotification(option);
})

ipcMain.handle('dialog-selectFile', async (_event, options) => {
  const result = await dialog.showOpenDialog({
    properties: ['openFile'],
    filters: options?.filters || [],
    defaultPath: options?.defaultPath || undefined,
  });
  if (!result.canceled && result.filePaths.length > 0) {
    return result.filePaths[0];
  }
  return null;
});

app.on('activate', () => {
  const allWindows = BrowserWindow.getAllWindows()
  if (allWindows.length) {
    allWindows[0].focus()
  } else {
    createWindow()
  }
})

ipcMain.handle('load-local-image', async (_event, filePath) => {
  return getRealImageData(filePath)
});

ipcMain.handle('get-version', _ => {
  return app.getVersion()
})

ipcMain.handle('get-app-name', _ => {
  return app.getName()
})

ipcMain.handle('open-win', (_, arg) => {
  const childWindow = new BrowserWindow({
    webPreferences: {
      preload,
      nodeIntegration: true,
      contextIsolation: false,
    },
  })

  if (VITE_DEV_SERVER_URL) {
    childWindow.loadURL(`${VITE_DEV_SERVER_URL}#${arg}`)
  } else {
    childWindow.loadFile(indexHtml, { hash: arg })
  }
})

ipcMain.handle('get-config', _ => {
  return getConfig()
})

ipcMain.on('edit-config', (_e, data: Config) => {
  if (data && typeof data === 'object' && data.theme) {
    writeConfig(data);
    checkTheme();
  }
})

ipcMain.on("quit", _ => {
  quitApp();
})