import { checkConfig } from "./config";
import { checkTheme } from "./theme";

export function init(): void{
  //主进程初始化做的事
  checkConfig();
  checkTheme();
}
