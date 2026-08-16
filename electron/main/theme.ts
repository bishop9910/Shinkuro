import { nativeTheme } from "electron";
import { getConfig } from "./config";

export function applyTheme(theme: "light" | "dark"): void {
  nativeTheme.themeSource = theme;
}

export function checkTheme(): void {
  const data = getConfig();
  if (data !== undefined) {
    applyTheme(data.theme === "dark" ? "dark" : "light");
  }
}
