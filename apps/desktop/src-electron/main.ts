import { app, BrowserWindow, clipboard, dialog, ipcMain, powerMonitor, shell } from 'electron'
import crypto from 'node:crypto'
import fs from 'node:fs/promises'
import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const isDev = !app.isPackaged
const require = createRequire(import.meta.url)

const DEFAULT_CLIPBOARD_CLEAR_SECONDS = 30
const MAX_RECENT_VAULTS = 10
const DEFAULT_AUTO_LOCK_MS = 5 * 60 * 1000

const PROD_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-src 'none'"
].join('; ')

type VaultStatus = {
  path: string
  label: string
  itemCount: number
  kdfMemoryKib: number
  kdfIterations: number
  kdfParallelism: number
}

type SecurityConfig = {
  clipboardTimeoutSeconds: number
  autoLockMinutes: number
  lockOnSuspend: boolean
  revealRequiresConfirm: boolean
}

type GeneratorConfig = {
  defaultMode: string
  charsetLength: number
  charsetUppercase: boolean
  charsetLowercase: boolean
  charsetDigits: boolean
  charsetSymbols: boolean
  charsetAvoidAmbiguous: boolean
  dicewareWords: number
  dicewareSeparator: string
}

type LoggingConfig = {
  level: string
}

type BackupConfig = {
  maxRetained: number
}

type AppConfig = {
  configPath: string
  defaultVault: string | null
  security: SecurityConfig
  generator: GeneratorConfig
  logging: LoggingConfig
  backup: BackupConfig
}

type RecentVault = {
  path: string
  label: string
  lastOpenedAt: number
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

type NoteDetail = {
  id: string
  title: string
  body: string
  favorite: boolean
  createdAt: number
  updatedAt: number
  tags: string[]
}

type PasskeyRefDetail = {
  id: string
  title: string
  rpId: string
  rpName: string | null
  userDisplayName: string | null
  credentialIdHex: string
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

type BackupCandidate = {
  path: string
  timestamp: number
  itemCount: number
  label: string
}

type VaultRecoveryResult = {
  corruptPath: string | null
}

type AddLoginInput = {
  title: string
  url?: string | null
  username?: string | null
  password?: string | null
  notes?: string | null
}

type VaultSession = {
  status: () => VaultStatus
  listItems: (query?: string | null) => ItemSummary[]
  lock: () => void
  getLogin: (id: string) => LoginDetail
  getLoginPassword: (id: string) => string
  loginGenerateAndReplacePassword: (id: string) => string
  getLoginTotp: (id: string) => TotpCode
  getLoginTotpQrSvg: (id: string) => string
  getNote: (id: string) => NoteDetail
  getPasskeyRef: (id: string) => PasskeyRefDetail
  addNote: (title: string, body: string) => string
  addLogin: (input: AddLoginInput) => string
  deleteItem: (id: string) => boolean
}

type AddonApi = {
  coreBanner: () => string
  configLoad: () => AppConfig
  configSet: (key: string, value: string) => AppConfig
  vaultCreate: (path: string, masterPassword: string, vaultLabel?: string | null) => void
  vaultStatus: (path: string) => VaultStatus
  vaultCheck: (path: string, masterPassword: string) => VaultStatus
  vaultUnlock: (path: string, masterPassword: string) => VaultSession
  vaultListBackups: (path: string) => BackupCandidate[]
  vaultRecoverFromBackup: (vaultPath: string, backupPath: string) => VaultRecoveryResult
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

  if (!isDev) {
    applyProductionSecurityPolicy(win)
  }

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

function applyProductionSecurityPolicy(win: BrowserWindow) {
  const session = win.webContents.session

  session.webRequest.onBeforeRequest((details, callback) => {
    const url = new URL(details.url)
    if (url.protocol === 'http:' || url.protocol === 'https:' || url.protocol === 'ws:' || url.protocol === 'wss:') {
      callback({ cancel: true })
      return
    }
    callback({ cancel: false })
  })

  session.webRequest.onHeadersReceived((details, callback) => {
    const responseHeaders = details.responseHeaders ?? {}
    responseHeaders['Content-Security-Policy'] = [PROD_CSP]
    callback({ responseHeaders })
  })
}

function registerIpcHandlers(api: AddonApi) {
  let session: VaultSession | null = null
  let clipboardClear: { token: Buffer; digest: string; timeoutId: NodeJS.Timeout } | null = null
  const recentsPath = path.join(app.getPath('userData'), 'recent-vaults.json')
  let autoLockTimer: NodeJS.Timeout | null = null
  let configCache: AppConfig | null = null

  try {
    configCache = api.configLoad()
  } catch {
    // Best-effort: desktop defaults still work without config access.
  }

  ipcMain.handle('core.banner', () => api.coreBanner())
  ipcMain.handle('config.load', () => {
    configCache = api.configLoad()
    return configCache
  })
  ipcMain.handle('config.set', (_event, payload: { key: string; value: string }) => {
    const safeKey = validateText(payload.key, 'key', 128)
    const safeValue = validateText(payload.value, 'value', 4096)
    configCache = api.configSet(safeKey, safeValue)
    resetAutoLockTimer()
    return configCache
  })
  ipcMain.handle('app.activity', () => {
    resetAutoLockTimer()
    return true
  })

  void app.whenReady().then(() => {
    powerMonitor.on('suspend', () => {
      if (configCache?.security.lockOnSuspend ?? true) {
        lockSession('suspend')
      }
    })
    powerMonitor.on('lock-screen', () => {
      if (configCache?.security.lockOnSuspend ?? true) {
        lockSession('lock-screen')
      }
    })
  })

  ipcMain.handle('vault.recents.list', async () => loadRecents())
  ipcMain.handle('vault.recents.remove', async (_event, payload: { path: string }) => {
    const safePath = validateText(payload.path, 'path', 4096)
    await removeRecentVault(safePath)
    return true
  })

  ipcMain.handle('vault.dialog.open', async () => {
    const result = await dialog.showOpenDialog({
      properties: ['openFile'],
      filters: [{ name: 'npw Vault', extensions: ['npw'] }]
    })
    if (result.canceled || result.filePaths.length === 0) {
      return null
    }
    return result.filePaths[0]
  })

  ipcMain.handle('vault.dialog.create', async () => {
    const result = await dialog.showSaveDialog({
      defaultPath: 'vault.npw',
      filters: [{ name: 'npw Vault', extensions: ['npw'] }]
    })
    if (result.canceled || !result.filePath) {
      return null
    }
    return ensureNpwExtension(result.filePath)
  })

  ipcMain.handle('vault.create', (_event, payload: { path: string; masterPassword: string; label?: string }) => {
    const safePath = validateText(payload.path, 'path', 4096)
    const safePassword = validateText(payload.masterPassword, 'masterPassword', 1024)
    const safeLabel = payload.label ? validateText(payload.label, 'label', 64) : undefined
    api.vaultCreate(safePath, safePassword, safeLabel)
    try {
      const status = api.vaultStatus(safePath)
      void upsertRecentVault(status.path, status.label)
    } catch {
      // Best-effort: recents are not security-critical.
    }
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
  ipcMain.handle('vault.backups.list', (_event, payload: { path: string }) => {
    const safePath = validateText(payload.path, 'path', 4096)
    return api.vaultListBackups(safePath)
  })
  ipcMain.handle('vault.backups.recover', (_event, payload: { path: string; backupPath: string }) => {
    if (session) {
      throw new Error('vault must be locked before recovery')
    }
    const safePath = validateText(payload.path, 'path', 4096)
    const safeBackupPath = validateText(payload.backupPath, 'backupPath', 4096)
    return api.vaultRecoverFromBackup(safePath, safeBackupPath)
  })
  ipcMain.handle('vault.unlock', (_event, payload: { path: string; masterPassword: string }) => {
    const safePath = validateText(payload.path, 'path', 4096)
    const safePassword = validateText(payload.masterPassword, 'masterPassword', 1024)
    session = api.vaultUnlock(safePath, safePassword)
    const status = session.status()
    void upsertRecentVault(status.path, status.label)
    resetAutoLockTimer()
    return status
  })
  ipcMain.handle('vault.lock', () => {
    lockSession('manual')
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

  ipcMain.handle('item.note.get', (_event, payload: { id: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    return session.getNote(safeId)
  })

  ipcMain.handle('item.passkey.get', (_event, payload: { id: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    return session.getPasskeyRef(safeId)
  })

  ipcMain.handle('item.passkey.open-site', async (_event, payload: { id: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    const detail = session.getPasskeyRef(safeId)
    const origin = rpIdToOrigin(detail.rpId)
    await shell.openExternal(origin)
    return true
  })

  ipcMain.handle('passkey.open-manager', async () => {
    const target = osPasskeyManagerUrl()
    if (!target) {
      throw new Error('passkey manager is not available on this platform')
    }
    await shell.openExternal(target)
    return true
  })

  ipcMain.handle('item.note.add', (_event, payload: { title: string; body: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeTitle = validateText(payload.title, 'title', 256)
    if (typeof payload.body !== 'string') {
      throw new Error('body must be a string')
    }
    if (payload.body.length > 1_000_000) {
      throw new Error('body is too long')
    }
    return session.addNote(safeTitle, payload.body)
  })

  ipcMain.handle('item.login.add', (_event, payload: AddLoginInput) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeTitle = validateText(payload.title, 'title', 256)
    const safeUrl = payload.url ? validateOptionalText(payload.url, 'url', 2048) : undefined
    const safeUsername = payload.username ? validateOptionalText(payload.username, 'username', 256) : undefined

    const password = payload.password
    if (password != null && typeof password !== 'string') {
      throw new Error('password must be a string')
    }
    if (typeof password === 'string' && password.length > 10_000) {
      throw new Error('password is too long')
    }

    const notes = payload.notes
    if (notes != null && typeof notes !== 'string') {
      throw new Error('notes must be a string')
    }
    if (typeof notes === 'string' && notes.length > 100_000) {
      throw new Error('notes is too long')
    }

    return session.addLogin({
      title: safeTitle,
      url: safeUrl && safeUrl.length > 0 ? safeUrl : undefined,
      username: safeUsername && safeUsername.length > 0 ? safeUsername : undefined,
      password: typeof password === 'string' && password.length > 0 ? password : undefined,
      notes: typeof notes === 'string' && notes.length > 0 ? notes : undefined
    })
  })

  ipcMain.handle('item.delete', (_event, payload: { id: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    return session.deleteItem(safeId)
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
    clipboardSetWithAutoClear(detail.username)
    return true
  })

  ipcMain.handle('item.login.copy-password', (_event, payload: { id: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    const password = session.getLoginPassword(safeId)
    clipboardSetWithAutoClear(password)
    return true
  })

  ipcMain.handle('item.login.reveal-password', (_event, payload: { id: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    return session.getLoginPassword(safeId)
  })

  ipcMain.handle('item.login.generate-replace-password', (_event, payload: { id: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    return session.loginGenerateAndReplacePassword(safeId)
  })

  ipcMain.handle('item.login.totp.get', (_event, payload: { id: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    return session.getLoginTotp(safeId)
  })

  ipcMain.handle('item.login.totp.qr-svg', (_event, payload: { id: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    return session.getLoginTotpQrSvg(safeId)
  })

  ipcMain.handle('item.login.copy-totp', (_event, payload: { id: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    const code = session.getLoginTotp(safeId)
    clipboardSetWithAutoClear(code.code)
    return true
  })

  function clipboardSetWithAutoClear(value: string) {
    const timeoutSeconds = configCache?.security.clipboardTimeoutSeconds ?? DEFAULT_CLIPBOARD_CLEAR_SECONDS
    const token = crypto.randomBytes(32)
    clipboard.writeText(value)

    if (timeoutSeconds === 0) {
      if (clipboardClear) {
        clearTimeout(clipboardClear.timeoutId)
        clipboardClear = null
      }
      return
    }

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

  function resetAutoLockTimer() {
    if (!session) {
      return
    }
    const autoLockMinutes = configCache?.security.autoLockMinutes ?? DEFAULT_AUTO_LOCK_MS / 60_000
    if (autoLockMinutes <= 0) {
      return
    }
    if (autoLockTimer) {
      clearTimeout(autoLockTimer)
    }
    autoLockTimer = setTimeout(() => {
      lockSession('idle')
    }, autoLockMinutes * 60_000)
  }

  function lockSession(reason: string) {
    if (autoLockTimer) {
      clearTimeout(autoLockTimer)
      autoLockTimer = null
    }
    if (session) {
      session.lock()
      session = null
    }
    notifyVaultLocked(reason)
  }

  function notifyVaultLocked(reason: string) {
    for (const win of BrowserWindow.getAllWindows()) {
      win.webContents.send('vault.locked', { reason })
    }
  }

  async function loadRecents(): Promise<RecentVault[]> {
    try {
      const raw = await fs.readFile(recentsPath, 'utf8')
      const parsed = JSON.parse(raw) as unknown
      if (!Array.isArray(parsed)) {
        return []
      }
      return parsed
        .filter((entry): entry is RecentVault => {
          if (!entry || typeof entry !== 'object') {
            return false
          }
          const candidate = entry as Partial<RecentVault>
          return typeof candidate.path === 'string' && typeof candidate.label === 'string'
        })
        .slice(0, MAX_RECENT_VAULTS)
    } catch (error) {
      if (isErrnoException(error) && error.code === 'ENOENT') {
        return []
      }
      return []
    }
  }

  async function saveRecents(vaults: RecentVault[]) {
    await fs.mkdir(path.dirname(recentsPath), { recursive: true })
    await fs.writeFile(recentsPath, JSON.stringify(vaults.slice(0, MAX_RECENT_VAULTS), null, 2), 'utf8')
  }

  async function upsertRecentVault(vaultPath: string, label: string) {
    const now = Date.now()
    const current = await loadRecents()
    const next: RecentVault[] = [{ path: vaultPath, label, lastOpenedAt: now }, ...current.filter((entry) => entry.path !== vaultPath)]
    await saveRecents(next)
  }

  async function removeRecentVault(vaultPath: string) {
    const current = await loadRecents()
    await saveRecents(current.filter((entry) => entry.path !== vaultPath))
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

function rpIdToOrigin(rpId: string): string {
  const trimmed = rpId.trim()
  if (trimmed.length === 0) {
    throw new Error('rpId cannot be empty')
  }
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    const parsed = new URL(trimmed)
    return parsed.origin
  }
  const parsed = new URL(`https://${trimmed}`)
  return parsed.origin
}

function osPasskeyManagerUrl(): string | null {
  if (process.platform === 'darwin') {
    return 'x-apple.systempreferences:com.apple.Passwords'
  }
  if (process.platform === 'win32') {
    return 'ms-settings:signinoptions'
  }
  return null
}

function ensureNpwExtension(filePath: string): string {
  return filePath.toLowerCase().endsWith('.npw') ? filePath : `${filePath}.npw`
}

function isErrnoException(error: unknown): error is NodeJS.ErrnoException {
  if (!error || typeof error !== 'object') {
    return false
  }
  return 'code' in error
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
