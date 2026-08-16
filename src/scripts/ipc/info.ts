export async function GetVersion() {
  return window.ipcRenderer.invoke("get-version");
}

export async function GetAppName() {
  return window.ipcRenderer.invoke("get-app-name");
}