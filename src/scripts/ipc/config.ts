import { type Config } from '../../../type'

function getConfig(){
  return window.ipcRenderer.invoke("get-config");
}

export function EditConfig(formData: Config): void{
  window.ipcRenderer.send("edit-config", formData);
}

export async function GetConfig(): Promise<Config> {
  const data = await getConfig()
  if(data === undefined){
    window.ipcRenderer.send("show-notification", {
      title: "Error",
      body: `获取设置文件失败`
    });
    window.ipcRenderer.send("quit")
  }
  return data
}

// 安全读取配置：不存在时返回 undefined，不会退出应用
export async function GetConfigSafe(): Promise<Config | undefined> {
  return window.ipcRenderer.invoke("get-config");
}
