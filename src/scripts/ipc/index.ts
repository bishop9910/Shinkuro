import { GetAppName, GetVersion } from "./info";

var isInited: boolean = false;

export async function Init(){
  if(isInited){
    return
  }
  window.ipcRenderer.on('main-process-message', (_event, ...args) => {
    console.log('[Receive Main-process message]:', ...args)
  });
  window.ipcRenderer.send("init");
  const version = await GetVersion();
  const name = await GetAppName();

  console.log(`${name} 已启动，版本号${version}`)

  isInited = true;
}