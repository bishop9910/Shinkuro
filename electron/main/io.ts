import { app } from "electron";
import fs from "node:fs";
import os from 'node:os';

export const RootDistPath: string = os.homedir() + "\\" + app.getName();

export function Exist(path: string): boolean{
  return fs.existsSync(path)
}

export function ReadJSON(path: string): object{
  return JSON.parse(fs.readFileSync(path).toString());
}

export function WriteJSON(path: string, object: object): void{
  fs.writeFileSync(path, JSON.stringify(object));
}

export function Mkdir(path: string): void{
  fs.mkdirSync(path);
}