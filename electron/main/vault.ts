// Bridges Electron main <-> the C++ vault backend over newline-delimited JSON-RPC.
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import path from 'node:path'
import fs from 'node:fs'
import { app, dialog, ipcMain, shell } from 'electron'

export type VaultEntry = { name: string; size: number; mtime: number }
export type VaultList = { path: string; count: number; files: VaultEntry[] }
export type OpenState = { open: boolean }

export class VaultBackendError extends Error {
  code: string
  constructor(code: string, message: string) {
    super(message)
    this.code = code
  }
}

type Pending = { resolve: (v: unknown) => void; reject: (e: Error) => void }

let proc: ChildProcessWithoutNullStreams | null = null
let nextId = 1
const pending = new Map<number, Pending>()
let stdoutBuf = ''
let stderrBuf = ''
let shuttingDown = false

function backendBinary(): string {
  const exe = process.platform === 'win32' ? 'vault_backend.exe' : 'vault_backend'
  if (process.env.VAULT_BACKEND_PATH) return process.env.VAULT_BACKEND_PATH
  const root = process.env.APP_ROOT ?? process.cwd()
  const candidates = [
    path.join(root, 'cpp_backend', 'build', exe),
    ...(app.isPackaged ? [path.join(process.resourcesPath, 'vault_backend', exe)] : []),
  ]
  return candidates.find((p) => fs.existsSync(p)) ?? candidates[0]
}

function failAll(err: Error) {
  for (const p of pending.values()) p.reject(err)
  pending.clear()
}

function ensureBackend(): ChildProcessWithoutNullStreams {
  if (shuttingDown) throw new Error('保险柜后端正在关闭')
  if (proc && proc.exitCode === null) return proc
  const bin = backendBinary()
  if (!fs.existsSync(bin)) {
    throw new Error(`未找到保险柜后端程序：${bin}\n请先在 cpp_backend 目录运行 build.bat 编译。`)
  }
  proc = spawn(bin, [], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true })
  stdoutBuf = ''
  stderrBuf = ''
  proc.stdout.setEncoding('utf8')
  proc.stdout.on('data', (chunk: string) => {
    stdoutBuf += chunk
    let idx: number
    while ((idx = stdoutBuf.indexOf('\n')) >= 0) {
      const line = stdoutBuf.slice(0, idx).trim()
      stdoutBuf = stdoutBuf.slice(idx + 1)
      if (!line) continue
      try {
        const msg = JSON.parse(line)
        const p = pending.get(msg.id)
        if (p) {
          pending.delete(msg.id)
          if (msg.ok) p.resolve(msg.result)
          else
            p.reject(
              new VaultBackendError(msg.error?.code ?? 'INTERNAL', msg.error?.message ?? '后端错误')
            )
        }
      } catch {
        /* ignore malformed line */
      }
    }
  })
  proc.stderr.setEncoding('utf8')
  proc.stderr.on('data', (c: string) => {
    stderrBuf += c
  })
  // Swallow EPIPE: if the backend exits before we finish writing (e.g. during quit),
  // the write error must not crash the main process.
  proc.stdin.on('error', () => {
    /* ignore */
  })
  proc.on('error', (e) => {
    failAll(new Error(`无法启动保险柜后端：${e.message}`))
    proc = null
  })
  proc.on('exit', (code) => {
    proc = null
    if (code !== 0) {
      failAll(
        new Error(`保险柜后端异常退出（code=${code}）${stderrBuf.trim() ? '：' + stderrBuf.trim() : ''}`)
      )
    }
  })
  return proc
}

function request<T = unknown>(method: string, params: Record<string, unknown> = {}): Promise<T> {
  const p = ensureBackend()
  const id = nextId++
  return new Promise<T>((resolve, reject) => {
    pending.set(id, { resolve: resolve as (v: unknown) => void, reject })
    p.stdin.write(JSON.stringify({ id, method, params }) + '\n', (err) => {
      if (err) {
        pending.delete(id)
        reject(err)
      }
    })
  })
}

function ok<T>(result: T) {
  return { ok: true, result }
}
function fail(e: unknown) {
  if (e instanceof VaultBackendError) return { ok: false, error: { code: e.code, message: e.message } }
  return { ok: false, error: { code: 'INTERNAL', message: e instanceof Error ? e.message : String(e) } }
}

export function registerVaultIpc() {
  ipcMain.handle('vault:isOpen', async () => {
    try {
      return ok(await request<OpenState>('is_open'))
    } catch (e) {
      return fail(e)
    }
  })

  ipcMain.handle('vault:pickSave', async () => {
    try {
      const r = await dialog.showSaveDialog({
        title: '新建保险柜',
        defaultPath: '我的保险柜.vault',
        filters: [{ name: '保险柜文件', extensions: ['vault'] }],
      })
      return ok(r.canceled || !r.filePath ? null : r.filePath)
    } catch (e) {
      return fail(e)
    }
  })

  ipcMain.handle('vault:pickOpen', async () => {
    try {
      const r = await dialog.showOpenDialog({
        title: '打开保险柜',
        properties: ['openFile'],
        filters: [{ name: '保险柜文件', extensions: ['vault'] }],
      })
      return ok(r.canceled || !r.filePaths.length ? null : r.filePaths[0])
    } catch (e) {
      return fail(e)
    }
  })

  ipcMain.handle('vault:create', async (_e, arg: { path: string; password: string }) => {
    try {
      return ok(await request('create', arg))
    } catch (e) {
      return fail(e)
    }
  })

  ipcMain.handle('vault:open', async (_e, arg: { path: string; password: string }) => {
    try {
      return ok(await request('open', arg))
    } catch (e) {
      return fail(e)
    }
  })

  ipcMain.handle('vault:lock', async () => {
    try {
      return ok(await request('lock'))
    } catch (e) {
      return fail(e)
    }
  })

  ipcMain.handle('vault:list', async () => {
    try {
      return ok(await request<VaultList>('list'))
    } catch (e) {
      return fail(e)
    }
  })

  ipcMain.handle('vault:addFile', async () => {
    const r = await dialog.showOpenDialog({
      title: '选择要加入保险柜的文件',
      properties: ['openFile', 'multiSelections'],
    })
    if (r.canceled || !r.filePaths.length) return ok({ added: [] as VaultEntry[], errors: [] as string[] })
    const added: VaultEntry[] = []
    const errors: string[] = []
    for (const src of r.filePaths) {
      try {
        added.push(await request<VaultEntry>('add', { src }))
      } catch (e) {
        errors.push(`${path.basename(src)}：${e instanceof Error ? e.message : String(e)}`)
      }
    }
    return ok({ added, errors })
  })

  ipcMain.handle('vault:openFile', async (_e, name: string) => {
    try {
      const r = await request<{ path: string; name: string; size: number }>('extract', { name })
      const openError = await shell.openPath(r.path)
      return ok({ ...r, opened: openError === '', openError: openError || null })
    } catch (e) {
      return fail(e)
    }
  })

  ipcMain.handle('vault:delete', async (_e, name: string) => {
    try {
      return ok(await request('delete', { name }))
    } catch (e) {
      return fail(e)
    }
  })
}

// Wipe keys + temp files while the app is still alive (called on lock & window close).
export async function lockVault() {
  if (proc && proc.exitCode === null) {
    try {
      await request('lock')
    } catch {
      /* best effort */
    }
  }
}

// Final teardown on quit: ask the backend to lock/wipe, then kill it.
// Idempotent: quitApp() and the before-quit hook may both call this.
export function shutdownBackend() {
  if (shuttingDown) return
  shuttingDown = true
  if (proc && proc.exitCode === null) {
    const p = proc
    try {
      p.stdin.write(JSON.stringify({ id: nextId++, method: 'shutdown', params: {} }) + '\n')
    } catch {
      /* ignore */
    }
    const t = setTimeout(() => {
      try {
        p.kill()
      } catch {
        /* ignore */
      }
    }, 800)
    if (typeof t.unref === 'function') t.unref()
  }
}
