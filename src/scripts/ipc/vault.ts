import type { AddFilesResult, OpenFileResult, OpenState, VaultList } from '../../../type'

export class VaultError extends Error {
  code: string
  constructor(code: string, message: string) {
    super(message)
    this.code = code
  }
}

type RpcResult<T> = { ok: true; result: T }
type RpcFailure = { ok: false; error: { code: string; message: string } }

async function call<T>(channel: string, ...args: unknown[]): Promise<T> {
  const res = (await window.ipcRenderer.invoke(channel, ...args)) as RpcResult<T> | RpcFailure | null
  if (!res || (res as RpcFailure).ok === false) {
    const err = (res as RpcFailure)?.error
    throw new VaultError(err?.code ?? 'INTERNAL', err?.message ?? '未知错误')
  }
  return (res as RpcResult<T>).result
}

export function isOpen(): Promise<OpenState> {
  return call('vault:isOpen')
}

export function pickSave(): Promise<string | null> {
  return call('vault:pickSave')
}

export function pickOpen(): Promise<string | null> {
  return call('vault:pickOpen')
}

export function createVault(path: string, password: string): Promise<{ open: boolean; path: string }> {
  return call('vault:create', { path, password })
}

export function openVault(path: string, password: string): Promise<{ open: boolean; path: string }> {
  return call('vault:open', { path, password })
}

export function lockVault(): Promise<OpenState> {
  return call('vault:lock')
}

export function listFiles(): Promise<VaultList> {
  return call('vault:list')
}

export function addFiles(): Promise<AddFilesResult> {
  return call('vault:addFile')
}

export function openFile(name: string): Promise<OpenFileResult> {
  return call('vault:openFile', name)
}

export function deleteFile(name: string): Promise<{ ok: boolean }> {
  return call('vault:delete', name)
}

export function extractTo(
  name: string
): Promise<{ canceled: boolean; path?: string; name?: string; size?: number }> {
  return call('vault:extractTo', name)
}

export function changePassword(oldPassword: string, newPassword: string): Promise<{ ok: boolean }> {
  return call('vault:changePassword', { oldPassword, newPassword })
}
