import { app, BrowserWindow, clipboard, ipcMain } from 'electron'
import crypto from 'node:crypto'
import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const isDev = !app.isPackaged
const require = createRequire(import.meta.url)

const DEFAULT_CLIPBOARD_CLEAR_SECONDS = 30

type VaultStatus = {
  path: string
  label: string
  itemCount: number
  kdfMemoryKib: number
  kdfIterations: number
  kdfParallelism: number
}

type ItemSummary = {
  id: string
  itemType: string
  title: string
  subtitle: string | null
  url: string | null
  favorite: boolean
  hasTotp: boolean
  updatedAt: number
  tags: string[]
}

type LoginDetail = {
  id: string
  title: string
  urls: string[]
  username: string | null
  hasPassword: boolean
  hasTotp: boolean
  notes: string | null
  favorite: boolean
  createdAt: number
  updatedAt: number
  tags: string[]
}

type TotpCode = {
  code: string
  period: number
  remaining: number
}

type VaultSession = {
  status: () => VaultStatus
  listItems: (query?: string | null) => ItemSummary[]
  lock: () => void
  getLogin: (id: string) => LoginDetail
  getLoginPassword: (id: string) => string
  getLoginTotp: (id: string) => TotpCode
}

type AddonApi = {
  coreBanner: () => string
  vaultCreate: (path: string, masterPassword: string, vaultLabel?: string | null) => void
  vaultStatus: (path: string) => VaultStatus
  vaultCheck: (path: string, masterPassword: string) => VaultStatus
  vaultUnlock: (path: string, masterPassword: string) => VaultSession
}

const addon = loadAddon()
registerIpcHandlers(addon)

const createWindow = () => {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  })

  if (isDev) {
    win.loadURL(process.env.VITE_DEV_SERVER_URL ?? 'http://localhost:5173')
    return
  }

  win.loadFile(path.join(__dirname, '../dist/index.html'))
}

app.whenReady().then(() => {
  createWindow()
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow()
    }
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
  }
})

function registerIpcHandlers(api: AddonApi) {
  let session: VaultSession | null = null
  let clipboardClear: { token: Buffer; digest: string; timeoutId: NodeJS.Timeout } | null = null

  ipcMain.handle('core.banner', () => api.coreBanner())
  ipcMain.handle('vault.create', (_event, payload: { path: string; masterPassword: string; label?: string }) => {
    const safePath = validateText(payload.path, 'path', 4096)
    const safePassword = validateText(payload.masterPassword, 'masterPassword', 1024)
    const safeLabel = payload.label ? validateText(payload.label, 'label', 64) : undefined
    api.vaultCreate(safePath, safePassword, safeLabel)
    return true
  })
  ipcMain.handle('vault.status', (_event, payload: { path: string }) => {
    const safePath = validateText(payload.path, 'path', 4096)
    return api.vaultStatus(safePath)
  })
  ipcMain.handle('vault.check', (_event, payload: { path: string; masterPassword: string }) => {
    const safePath = validateText(payload.path, 'path', 4096)
    const safePassword = validateText(payload.masterPassword, 'masterPassword', 1024)
    return api.vaultCheck(safePath, safePassword)
  })
  ipcMain.handle('vault.unlock', (_event, payload: { path: string; masterPassword: string }) => {
    const safePath = validateText(payload.path, 'path', 4096)
    const safePassword = validateText(payload.masterPassword, 'masterPassword', 1024)
    session = api.vaultUnlock(safePath, safePassword)
    return session.status()
  })
  ipcMain.handle('vault.lock', () => {
    if (session) {
      session.lock()
      session = null
    }
    return true
  })
  ipcMain.handle('item.list', (_event, payload: { query?: string | null }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const query = payload?.query ? validateOptionalText(payload.query, 'query', 256) : null
    return session.listItems(query)
  })

  ipcMain.handle('item.login.get', (_event, payload: { id: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    return session.getLogin(safeId)
  })

  ipcMain.handle('item.login.copy-username', (_event, payload: { id: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    const detail = session.getLogin(safeId)
    if (!detail.username) {
      throw new Error('login item has no username')
    }
    clipboardSetWithAutoClear(detail.username, DEFAULT_CLIPBOARD_CLEAR_SECONDS)
    return true
  })

  ipcMain.handle('item.login.copy-password', (_event, payload: { id: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    const password = session.getLoginPassword(safeId)
    clipboardSetWithAutoClear(password, DEFAULT_CLIPBOARD_CLEAR_SECONDS)
    return true
  })

  ipcMain.handle('item.login.totp.get', (_event, payload: { id: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    return session.getLoginTotp(safeId)
  })

  ipcMain.handle('item.login.copy-totp', (_event, payload: { id: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    const code = session.getLoginTotp(safeId)
    clipboardSetWithAutoClear(code.code, DEFAULT_CLIPBOARD_CLEAR_SECONDS)
    return true
  })

  function clipboardSetWithAutoClear(value: string, timeoutSeconds: number) {
    const token = crypto.randomBytes(32)
    clipboard.writeText(value)

    const digest = sha256Base64(token, value)
    if (clipboardClear) {
      clearTimeout(clipboardClear.timeoutId)
    }
    const timeoutId = setTimeout(() => {
      try {
        const current = clipboard.readText()
        const currentDigest = sha256Base64(token, current)
        if (currentDigest === digest) {
          clipboard.writeText('')
        }
      } catch {
        // Best-effort: never crash the app while clearing.
      } finally {
        clipboardClear = null
      }
    }, timeoutSeconds * 1000)
    clipboardClear = { token, digest, timeoutId }
  }
}

function validateText(value: string, field: string, maxLen: number): string {
  if (typeof value !== 'string') {
    throw new Error(`${field} must be a string`)
  }
  const trimmed = value.trim()
  if (trimmed.length === 0) {
    throw new Error(`${field} cannot be empty`)
  }
  if (trimmed.length > maxLen) {
    throw new Error(`${field} is too long`)
  }
  return trimmed
}

function validateOptionalText(value: string, field: string, maxLen: number): string {
  if (typeof value !== 'string') {
    throw new Error(`${field} must be a string`)
  }
  const trimmed = value.trim()
  if (trimmed.length > maxLen) {
    throw new Error(`${field} is too long`)
  }
  return trimmed
}

function sha256Base64(token: Buffer, value: string): string {
  return crypto.createHash('sha256').update(token).update(value).digest('base64')
}

function loadAddon(): AddonApi {
  const addonPath = path.resolve(__dirname, '../native/npw-addon.node')
  try {
    return require(addonPath) as AddonApi
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new Error(`Failed to load native addon at ${addonPath}: ${message}`)
  }
}
