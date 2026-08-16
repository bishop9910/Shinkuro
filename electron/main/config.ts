import { Exist, ReadJSON, WriteJSON, Mkdir, RootDistPath } from './io'
import { type Config } from '../../type'

const ConfigDistPath: string = RootDistPath;
const ConfigFilePath: string = RootDistPath + "/config.json";

const OriginConfig: Config = {
  theme: "light",
};

export function checkConfig(): void{
  if(!isConfigDistExist()){
    Mkdir(ConfigDistPath);
  }

  if(!isConfigFileExist()){
    ConfigInit();
  }
  console.log("Config File Ready");
}

export function getConfig(): Config | undefined{
  try{
    return ReadJSON(ConfigFilePath) as Config;
  }catch(e){
    return undefined;
  }
}

export function writeConfig(data: Config): void{
  WriteJSON(ConfigFilePath, data);
}

function ConfigInit(): void{
  WriteJSON(ConfigFilePath, OriginConfig);
}

function isConfigDistExist(): boolean{
  return Exist(ConfigDistPath);
}

function isConfigFileExist(): boolean{
  return Exist(ConfigFilePath);
}