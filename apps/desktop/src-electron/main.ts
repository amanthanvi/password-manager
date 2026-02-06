import { app, BrowserWindow, ipcMain } from 'electron'
import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const isDev = !app.isPackaged
const require = createRequire(import.meta.url)

type VaultStatus = {
  path: string
  label: string
  itemCount: number
  kdfMemoryKib: number
  kdfIterations: number
  kdfParallelism: number
}

type AddonApi = {
  coreBanner: () => string
  vaultCreate: (path: string, masterPassword: string, vaultLabel?: string | null) => void
  vaultStatus: (path: string) => VaultStatus
  vaultCheck: (path: string, masterPassword: string) => VaultStatus
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

function loadAddon(): AddonApi {
  const addonPath = path.resolve(__dirname, '../native/npw-addon.node')
  try {
    return require(addonPath) as AddonApi
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new Error(`Failed to load native addon at ${addonPath}: ${message}`)
  }
}
