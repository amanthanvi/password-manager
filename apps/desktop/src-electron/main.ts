import { app, BrowserWindow, clipboard, dialog, ipcMain, powerMonitor, shell } from 'electron'
import crypto from 'node:crypto'
import fs from 'node:fs/promises'
import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const isDev = !app.isPackaged
const isE2E = process.env.NPW_E2E === '1' || process.argv.includes('--npw-e2e')
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
  vaultIdHex?: string | null
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

type UrlEntry = {
  url: string
  matchType: 'exact' | 'domain' | 'subdomain'
}

type LoginDetail = {
  id: string
  title: string
  urls: UrlEntry[]
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

type ImportDuplicate = {
  sourceIndex: number
  itemType: string
  title: string
  username: string | null
  primaryUrl: string | null
  existingId: string
  existingTitle: string
  existingUsername: string | null
  existingPrimaryUrl: string | null
}

type ImportPreview = {
  importType: string
  candidates: number
  duplicates: ImportDuplicate[]
  warnings: string[]
}

type ImportDuplicateDecision = {
  sourceIndex: number
  action: string
}

type ImportResult = {
  imported: number
  skipped: number
  overwritten: number
  warnings: string[]
}

type UrlEntryInput = {
  url: string
  matchType?: string | null
}

type AddLoginInput = {
  title: string
  urls?: UrlEntryInput[] | null
  username?: string | null
  password?: string | null
  notes?: string | null
  tags?: string[] | null
  favorite?: boolean | null
}

type UpdateLoginInput = {
  id: string
  title: string
  urls?: UrlEntryInput[] | null
  username?: string | null
  notes?: string | null
  tags?: string[] | null
  favorite?: boolean | null
}

type AddNoteInput = {
  title: string
  body: string
  tags?: string[] | null
  favorite?: boolean | null
}

type UpdateNoteInput = {
  id: string
  title: string
  body: string
  tags?: string[] | null
  favorite?: boolean | null
}

type AddPasskeyRefInput = {
  title: string
  rpId: string
  rpName?: string | null
  userDisplayName?: string | null
  credentialIdHex: string
  notes?: string | null
  tags?: string[] | null
  favorite?: boolean | null
}

type UpdatePasskeyRefInput = {
  id: string
  title: string
  notes?: string | null
  tags?: string[] | null
  favorite?: boolean | null
}

type VaultSession = {
  status: () => VaultStatus
  vaultIdHex: () => string
  quickUnlockIsEnabled: () => boolean
  quickUnlockEnable: () => boolean
  quickUnlockDisable: () => boolean
  listItems: (query?: string | null) => ItemSummary[]
  lock: () => void
  getLogin: (id: string) => LoginDetail
  getLoginPassword: (id: string) => string
  loginGenerateAndReplacePassword: (id: string) => string
  updateLogin: (input: UpdateLoginInput) => boolean
  getLoginTotp: (id: string) => TotpCode
  getLoginTotpQrSvg: (id: string) => string
  setLoginTotp: (id: string, value: string) => boolean
  getNote: (id: string) => NoteDetail
  getPasskeyRef: (id: string) => PasskeyRefDetail
  updatePasskeyRef: (input: UpdatePasskeyRefInput) => boolean
  addNote: (input: AddNoteInput) => string
  updateNote: (input: UpdateNoteInput) => boolean
  addLogin: (input: AddLoginInput) => string
  addPasskeyRef: (input: AddPasskeyRefInput) => string
  deleteItem: (id: string) => boolean
  importCsvPreview: (inputPath: string) => ImportPreview
  importCsvApply: (inputPath: string, decisions: ImportDuplicateDecision[]) => ImportResult
  importBitwardenJsonPreview: (inputPath: string) => ImportPreview
  importBitwardenJsonApply: (inputPath: string, decisions: ImportDuplicateDecision[]) => ImportResult
  exportCsv: (outputPath: string, includeSecrets: boolean) => number
  exportJson: (outputPath: string, includeSecrets: boolean) => number
  exportEncrypted: (outputPath: string, exportPassword: string, redacted: boolean) => number
}

type AddonApi = {
  coreBanner: () => string
  configLoad: () => AppConfig
  configSet: (key: string, value: string) => AppConfig
  vaultCreate: (path: string, masterPassword: string, vaultLabel?: string | null) => void
  vaultStatus: (path: string) => VaultStatus
  vaultCheck: (path: string, masterPassword: string) => VaultStatus
  vaultUnlock: (path: string, masterPassword: string) => VaultSession
  vaultUnlockQuick: (path: string, vaultIdHex: string) => VaultSession
  quickUnlockHasEntry: (vaultIdHex: string) => boolean
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
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  })

  if (!isDev || isE2E) {
    applyProductionSecurityPolicy(win)
  }

  if (isDev && !isE2E) {
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

  ipcMain.handle('import.dialog.csv', async () => {
    const result = await dialog.showOpenDialog({
      properties: ['openFile'],
      filters: [{ name: 'CSV', extensions: ['csv'] }]
    })
    if (result.canceled || result.filePaths.length === 0) {
      return null
    }
    return result.filePaths[0]
  })

  ipcMain.handle('import.dialog.bitwarden', async () => {
    const result = await dialog.showOpenDialog({
      properties: ['openFile'],
      filters: [{ name: 'Bitwarden JSON', extensions: ['json'] }]
    })
    if (result.canceled || result.filePaths.length === 0) {
      return null
    }
    return result.filePaths[0]
  })

  ipcMain.handle('export.dialog.csv', async () => {
    const result = await dialog.showSaveDialog({
      defaultPath: 'npw-export.csv',
      filters: [{ name: 'CSV', extensions: ['csv'] }]
    })
    if (result.canceled || !result.filePath) {
      return null
    }
    return result.filePath
  })

  ipcMain.handle('export.dialog.json', async () => {
    const result = await dialog.showSaveDialog({
      defaultPath: 'npw-export.json',
      filters: [{ name: 'JSON', extensions: ['json'] }]
    })
    if (result.canceled || !result.filePath) {
      return null
    }
    return result.filePath
  })

  ipcMain.handle('export.dialog.encrypted', async () => {
    const result = await dialog.showSaveDialog({
      defaultPath: 'npw-export.npw',
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
    const vaultIdHex = session.vaultIdHex()
    void upsertRecentVault(status.path, status.label, vaultIdHex)
    resetAutoLockTimer()
    return status
  })
  ipcMain.handle('vault.unlock.quick', async (_event, payload: { path: string }) => {
    const safePath = validateText(payload.path, 'path', 4096)
    const recents = await loadRecents()
    const recent = recents.find((entry) => entry.path === safePath)
    const vaultIdHex = typeof recent?.vaultIdHex === 'string' ? recent.vaultIdHex : null
    if (!vaultIdHex) {
      throw new Error(
        'Quick Unlock is not configured for this vault yet. Unlock with the master password once, then enable Quick Unlock.'
      )
    }
    session = api.vaultUnlockQuick(safePath, vaultIdHex)
    const status = session.status()
    void upsertRecentVault(status.path, status.label, vaultIdHex)
    resetAutoLockTimer()
    return status
  })
  ipcMain.handle('quick_unlock.status_for_path', async (_event, payload: { path: string }) => {
    const safePath = validateText(payload.path, 'path', 4096)
    const recents = await loadRecents()
    const recent = recents.find((entry) => entry.path === safePath)
    const vaultIdHex = typeof recent?.vaultIdHex === 'string' ? recent.vaultIdHex : null
    if (!vaultIdHex) {
      return { available: true, configured: false, enabled: false, error: null }
    }
    try {
      const enabled = api.quickUnlockHasEntry(vaultIdHex)
      return { available: true, configured: true, enabled, error: null }
    } catch (error) {
      return {
        available: false,
        configured: true,
        enabled: false,
        error: error instanceof Error ? error.message : String(error)
      }
    }
  })
  ipcMain.handle('quick_unlock.status_current', () => {
    if (!session) {
      throw new Error('vault is locked')
    }
    try {
      const enabled = session.quickUnlockIsEnabled()
      return { available: true, configured: true, enabled, error: null }
    } catch (error) {
      return {
        available: false,
        configured: true,
        enabled: false,
        error: error instanceof Error ? error.message : String(error)
      }
    }
  })
  ipcMain.handle('quick_unlock.enable_current', () => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const vaultIdHex = session.vaultIdHex()
    const enabled = session.quickUnlockEnable()
    const status = session.status()
    void upsertRecentVault(status.path, status.label, vaultIdHex)
    return enabled
  })
  ipcMain.handle('quick_unlock.disable_current', () => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const vaultIdHex = session.vaultIdHex()
    const disabled = session.quickUnlockDisable()
    const status = session.status()
    void upsertRecentVault(status.path, status.label, vaultIdHex)
    return disabled
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

  ipcMain.handle('import.csv.preview', (_event, payload: { inputPath: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeInputPath = validateText(payload.inputPath, 'inputPath', 4096)
    return session.importCsvPreview(safeInputPath)
  })

  ipcMain.handle('import.csv.apply', (_event, payload: { inputPath: string; decisions: ImportDuplicateDecision[] }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeInputPath = validateText(payload.inputPath, 'inputPath', 4096)
    const safeDecisions = validateImportDecisions(payload.decisions, 'decisions')
    return session.importCsvApply(safeInputPath, safeDecisions)
  })

  ipcMain.handle('import.bitwarden.preview', (_event, payload: { inputPath: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeInputPath = validateText(payload.inputPath, 'inputPath', 4096)
    return session.importBitwardenJsonPreview(safeInputPath)
  })

  ipcMain.handle('import.bitwarden.apply', (_event, payload: { inputPath: string; decisions: ImportDuplicateDecision[] }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeInputPath = validateText(payload.inputPath, 'inputPath', 4096)
    const safeDecisions = validateImportDecisions(payload.decisions, 'decisions')
    return session.importBitwardenJsonApply(safeInputPath, safeDecisions)
  })

  ipcMain.handle('export.csv', (_event, payload: { outputPath: string; includeSecrets: boolean; acknowledged?: boolean }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeOutputPath = validateText(payload.outputPath, 'outputPath', 4096)
    if (typeof payload.includeSecrets !== 'boolean') {
      throw new Error('includeSecrets must be a boolean')
    }
    if (payload.includeSecrets && payload.acknowledged !== true) {
      throw new Error('plaintext export requires acknowledgement')
    }
    return session.exportCsv(safeOutputPath, payload.includeSecrets)
  })

  ipcMain.handle('export.json', (_event, payload: { outputPath: string; includeSecrets: boolean; acknowledged?: boolean }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeOutputPath = validateText(payload.outputPath, 'outputPath', 4096)
    if (typeof payload.includeSecrets !== 'boolean') {
      throw new Error('includeSecrets must be a boolean')
    }
    if (payload.includeSecrets && payload.acknowledged !== true) {
      throw new Error('plaintext export requires acknowledgement')
    }
    return session.exportJson(safeOutputPath, payload.includeSecrets)
  })

  ipcMain.handle(
    'export.encrypted',
    (_event, payload: { outputPath: string; exportPassword: string; masterPassword: string; redacted: boolean }) => {
      if (!session) {
        throw new Error('vault is locked')
      }
      const safeOutputPath = validateText(payload.outputPath, 'outputPath', 4096)
      const exportPassword = validateText(payload.exportPassword, 'exportPassword', 1024)
      const masterPassword = validateText(payload.masterPassword, 'masterPassword', 1024)
      if (exportPassword === masterPassword) {
        throw new Error('export password must differ from the vault master password')
      }
      if (typeof payload.redacted !== 'boolean') {
        throw new Error('redacted must be a boolean')
      }

      // Best-effort enforcement: validate the user entered the correct master password before comparing.
      api.vaultCheck(session.status().path, masterPassword)

      return session.exportEncrypted(safeOutputPath, exportPassword, payload.redacted)
    }
  )

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

  ipcMain.handle('item.passkey.update', (_event, payload: UpdatePasskeyRefInput) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    const safeTitle = validateText(payload.title, 'title', 256)
    const notes = payload.notes
    if (notes != null && typeof notes !== 'string') {
      throw new Error('notes must be a string')
    }
    if (typeof notes === 'string' && notes.length > 100_000) {
      throw new Error('notes is too long')
    }
    const tags = payload.tags != null ? validateTags(payload.tags, 'tags') : undefined
    const favorite = payload.favorite != null ? validateOptionalBool(payload.favorite, 'favorite') : undefined

    return session.updatePasskeyRef({
      id: safeId,
      title: safeTitle,
      notes: typeof notes === 'string' && notes.length > 0 ? notes : undefined,
      tags,
      favorite
    })
  })

  ipcMain.handle('item.passkey.add', (_event, payload: AddPasskeyRefInput) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeTitle = validateText(payload.title, 'title', 256)
    const safeRpId = validateText(payload.rpId, 'rpId', 256)
    const safeCredentialIdHex = validateText(payload.credentialIdHex, 'credentialIdHex', 4096)
    if (!/^[0-9a-fA-F]+$/.test(safeCredentialIdHex)) {
      throw new Error('credentialIdHex must be hex')
    }
    if (safeCredentialIdHex.length % 2 !== 0) {
      throw new Error('credentialIdHex must have even length')
    }
    const safeRpName = payload.rpName != null ? validateOptionalText(payload.rpName, 'rpName', 256) : undefined
    const safeUser =
      payload.userDisplayName != null ? validateOptionalText(payload.userDisplayName, 'userDisplayName', 256) : undefined
    const notes = payload.notes
    if (notes != null && typeof notes !== 'string') {
      throw new Error('notes must be a string')
    }
    if (typeof notes === 'string' && notes.length > 100_000) {
      throw new Error('notes is too long')
    }
    const tags = payload.tags != null ? validateTags(payload.tags, 'tags') : undefined
    const favorite = payload.favorite != null ? validateOptionalBool(payload.favorite, 'favorite') : undefined

    return session.addPasskeyRef({
      title: safeTitle,
      rpId: safeRpId,
      rpName: safeRpName && safeRpName.length > 0 ? safeRpName : undefined,
      userDisplayName: safeUser && safeUser.length > 0 ? safeUser : undefined,
      credentialIdHex: safeCredentialIdHex,
      notes: typeof notes === 'string' && notes.length > 0 ? notes : undefined,
      tags,
      favorite
    })
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

  ipcMain.handle('item.note.add', (_event, payload: AddNoteInput) => {
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
    const tags = payload.tags != null ? validateTags(payload.tags, 'tags') : undefined
    const favorite = payload.favorite != null ? validateOptionalBool(payload.favorite, 'favorite') : undefined
    return session.addNote({
      title: safeTitle,
      body: payload.body,
      tags,
      favorite
    })
  })

  ipcMain.handle('item.note.update', (_event, payload: UpdateNoteInput) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    const safeTitle = validateText(payload.title, 'title', 256)
    if (typeof payload.body !== 'string') {
      throw new Error('body must be a string')
    }
    if (payload.body.length > 1_000_000) {
      throw new Error('body is too long')
    }
    const tags = payload.tags != null ? validateTags(payload.tags, 'tags') : undefined
    const favorite = payload.favorite != null ? validateOptionalBool(payload.favorite, 'favorite') : undefined
    return session.updateNote({
      id: safeId,
      title: safeTitle,
      body: payload.body,
      tags,
      favorite
    })
  })

  ipcMain.handle('item.login.add', (_event, payload: AddLoginInput) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeTitle = validateText(payload.title, 'title', 256)
    const safeUsername = payload.username ? validateOptionalText(payload.username, 'username', 256) : undefined
    const urls = payload.urls != null ? validateUrlEntries(payload.urls, 'urls') : undefined
    const tags = payload.tags != null ? validateTags(payload.tags, 'tags') : undefined
    const favorite = payload.favorite != null ? validateOptionalBool(payload.favorite, 'favorite') : undefined

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
      urls,
      username: safeUsername && safeUsername.length > 0 ? safeUsername : undefined,
      password: typeof password === 'string' && password.length > 0 ? password : undefined,
      notes: typeof notes === 'string' && notes.length > 0 ? notes : undefined,
      tags,
      favorite
    })
  })

  ipcMain.handle('item.login.update', (_event, payload: UpdateLoginInput) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    const safeTitle = validateText(payload.title, 'title', 256)
    const safeUsername = payload.username ? validateOptionalText(payload.username, 'username', 256) : undefined
    const urls = payload.urls != null ? validateUrlEntries(payload.urls, 'urls') : undefined
    const tags = payload.tags != null ? validateTags(payload.tags, 'tags') : undefined
    const favorite = payload.favorite != null ? validateOptionalBool(payload.favorite, 'favorite') : undefined

    const notes = payload.notes
    if (notes != null && typeof notes !== 'string') {
      throw new Error('notes must be a string')
    }
    if (typeof notes === 'string' && notes.length > 100_000) {
      throw new Error('notes is too long')
    }

    return session.updateLogin({
      id: safeId,
      title: safeTitle,
      urls,
      username: safeUsername && safeUsername.length > 0 ? safeUsername : undefined,
      notes: typeof notes === 'string' && notes.length > 0 ? notes : undefined,
      tags,
      favorite
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

  ipcMain.handle('item.login.totp.set', (_event, payload: { id: string; value: string }) => {
    if (!session) {
      throw new Error('vault is locked')
    }
    const safeId = validateText(payload.id, 'id', 128)
    const safeValue = validateText(payload.value, 'value', 4096)
    return session.setLoginTotp(safeId, safeValue)
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
          const vaultIdHex = candidate.vaultIdHex
          if (vaultIdHex != null && typeof vaultIdHex !== 'string') {
            return false
          }
          if (typeof vaultIdHex === 'string' && !/^[0-9a-fA-F]{32}$/.test(vaultIdHex)) {
            return false
          }
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

  async function upsertRecentVault(vaultPath: string, label: string, vaultIdHex?: string) {
    const now = Date.now()
    const current = await loadRecents()
    const existing = current.find((entry) => entry.path === vaultPath)
    const nextVaultIdHex = vaultIdHex ?? existing?.vaultIdHex ?? null
    const next: RecentVault[] = [
      { path: vaultPath, label, lastOpenedAt: now, vaultIdHex: nextVaultIdHex },
      ...current.filter((entry) => entry.path !== vaultPath)
    ]
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

function validateOptionalBool(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') {
    throw new Error(`${field} must be a boolean`)
  }
  return value
}

function validateTags(value: unknown, field: string): string[] {
  if (!Array.isArray(value)) {
    throw new Error(`${field} must be an array`)
  }
  const tags: string[] = []
  for (const entry of value) {
    if (typeof entry !== 'string') {
      throw new Error(`${field} entries must be strings`)
    }
    const trimmed = entry.trim()
    if (trimmed.length === 0) {
      continue
    }
    if (trimmed.length > 64) {
      throw new Error(`${field} entry is too long`)
    }
    tags.push(trimmed)
  }
  return tags
}

function validateUrlEntries(value: unknown, field: string): UrlEntryInput[] {
  if (!Array.isArray(value)) {
    throw new Error(`${field} must be an array`)
  }
  const urls: UrlEntryInput[] = []
  for (const [index, entry] of value.entries()) {
    if (!entry || typeof entry !== 'object') {
      throw new Error(`${field}[${index}] must be an object`)
    }
    const candidate = entry as Partial<UrlEntryInput>
    if (typeof candidate.url !== 'string') {
      throw new Error(`${field}[${index}].url must be a string`)
    }
    const urlTrimmed = candidate.url.trim()
    if (urlTrimmed.length === 0) {
      continue
    }
    if (urlTrimmed.length > 2048) {
      throw new Error(`${field}[${index}].url is too long`)
    }
    try {
      new URL(urlTrimmed)
    } catch {
      throw new Error(`${field}[${index}].url must be a valid URL`)
    }

    let matchType: string | undefined = undefined
    if (candidate.matchType != null) {
      if (typeof candidate.matchType !== 'string') {
        throw new Error(`${field}[${index}].matchType must be a string`)
      }
      const trimmed = candidate.matchType.trim().toLowerCase()
      if (trimmed.length === 0) {
        matchType = undefined
      } else if (trimmed === 'exact' || trimmed === 'domain' || trimmed === 'subdomain') {
        matchType = trimmed
      } else {
        throw new Error(`${field}[${index}].matchType must be exact|domain|subdomain`)
      }
    }

    urls.push({ url: urlTrimmed, matchType })
  }
  return urls
}

function validateImportDecisions(value: unknown, field: string): ImportDuplicateDecision[] {
  if (!Array.isArray(value)) {
    throw new Error(`${field} must be an array`)
  }
  const decisions: ImportDuplicateDecision[] = []
  const seen = new Set<number>()
  for (const [index, entry] of value.entries()) {
    if (!entry || typeof entry !== 'object') {
      throw new Error(`${field}[${index}] must be an object`)
    }
    const candidate = entry as Partial<ImportDuplicateDecision>
    const sourceIndex = Number(candidate.sourceIndex)
    if (!Number.isFinite(sourceIndex) || !Number.isInteger(sourceIndex) || sourceIndex < 0) {
      throw new Error(`${field}[${index}].sourceIndex must be a non-negative integer`)
    }
    if (typeof candidate.action !== 'string') {
      throw new Error(`${field}[${index}].action must be a string`)
    }
    const action = candidate.action.trim()
    if (action !== 'skip' && action !== 'overwrite' && action !== 'keep_both') {
      throw new Error(`${field}[${index}].action must be one of: skip, overwrite, keep_both`)
    }
    if (seen.has(sourceIndex)) {
      throw new Error(`${field}[${index}].sourceIndex is duplicated`)
    }
    seen.add(sourceIndex)
    decisions.push({ sourceIndex, action })
  }
  return decisions
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
