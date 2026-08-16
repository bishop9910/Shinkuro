export async function InstallUpdate() {
  window.ipcRenderer.send('install-update');
}