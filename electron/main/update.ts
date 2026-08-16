import { getConfig } from "./config";
import { type Config } from '../../type'
import { win } from ".";
import { app } from 'electron';
import pkg from 'electron-updater';
const { autoUpdater } = pkg;

var isUpdateChecked: boolean = false;

function initAutoUpdate() {
  if (!app.isPackaged) {
    return;
  }

  autoUpdater.setFeedURL({
    provider: 'github',
    owner: 'bishop9910',
    repo: 'Shinkuro'
  });

  autoUpdater.checkForUpdatesAndNotify();

  autoUpdater.on('error', (err: Error) => {
    win?.webContents.send('update-error', err.message);
  });

  autoUpdater.on('download-progress', (progressObj) => {
    win?.webContents.send('update-download-progress', progressObj);
  });

  autoUpdater.on('update-downloaded', (_info) => {
    win?.webContents.send('update-downloaded')
  });

  autoUpdater.on('update-available', (_info) => {
    win?.webContents.send("update-available")
  })

  autoUpdater.on('update-not-available', (_info)=>{
    win?.webContents.send("update-not-available")
  })
}

export function checkUpdate(): void{
  if(isUpdateChecked){
    return;
  }
  const data = getConfig();
  if (data !== undefined){
    const config: Config = data;
    if(config.autoUpdate){
      win?.webContents.send('update-checking');
      initAutoUpdate();
    }
  }
  isUpdateChecked = true;
}

export function installUpdate(): void{
  autoUpdater.quitAndInstall()
}