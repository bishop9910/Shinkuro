export type Config = {
  theme: "light" | "dark";
}

export type NotifyOption = {
  title?: string;
  body: string;
}

export type VaultEntry = {
  name: string;
  size: number;
  mtime: number;
}

export type VaultList = {
  path: string;
  count: number;
  files: VaultEntry[];
}

export type OpenState = {
  open: boolean;
}

export type AddFilesResult = {
  added: VaultEntry[];
  errors: string[];
}

export type OpenFileResult = {
  path: string;
  name: string;
  size: number;
  opened: boolean;
  openError: string | null;
}
