import { contextBridge, ipcRenderer } from 'electron'

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

contextBridge.exposeInMainWorld('npw', {
  coreBanner: (): Promise<string> => ipcRenderer.invoke('core.banner'),
  configLoad: (): Promise<AppConfig> => ipcRenderer.invoke('config.load'),
  configSet: (payload: { key: string; value: string }): Promise<AppConfig> => ipcRenderer.invoke('config.set', payload),
  appActivity: (): Promise<boolean> => ipcRenderer.invoke('app.activity'),
  onVaultLocked: (callback: (payload: { reason: string }) => void): (() => void) => {
    const listener = (_event: Electron.IpcRendererEvent, payload: { reason: string }) => {
      callback(payload)
    }
    ipcRenderer.on('vault.locked', listener)
    return () => {
      ipcRenderer.removeListener('vault.locked', listener)
    }
  },
  vaultRecentsList: (): Promise<RecentVault[]> => ipcRenderer.invoke('vault.recents.list'),
  vaultRecentsRemove: (payload: { path: string }): Promise<boolean> => ipcRenderer.invoke('vault.recents.remove', payload),
  vaultDialogOpen: (): Promise<string | null> => ipcRenderer.invoke('vault.dialog.open'),
  vaultDialogCreate: (): Promise<string | null> => ipcRenderer.invoke('vault.dialog.create'),
  importDialogCsv: (): Promise<string | null> => ipcRenderer.invoke('import.dialog.csv'),
  importDialogBitwarden: (): Promise<string | null> => ipcRenderer.invoke('import.dialog.bitwarden'),
  exportDialogCsv: (): Promise<string | null> => ipcRenderer.invoke('export.dialog.csv'),
  exportDialogJson: (): Promise<string | null> => ipcRenderer.invoke('export.dialog.json'),
  exportDialogEncrypted: (): Promise<string | null> => ipcRenderer.invoke('export.dialog.encrypted'),
  vaultCreate: (payload: { path: string; masterPassword: string; label?: string }): Promise<boolean> =>
    ipcRenderer.invoke('vault.create', payload),
  vaultStatus: (payload: { path: string }): Promise<VaultStatus> => ipcRenderer.invoke('vault.status', payload),
  vaultCheck: (payload: { path: string; masterPassword: string }): Promise<VaultStatus> =>
    ipcRenderer.invoke('vault.check', payload),
  vaultBackupsList: (payload: { path: string }): Promise<BackupCandidate[]> => ipcRenderer.invoke('vault.backups.list', payload),
  vaultRecoverFromBackup: (payload: { path: string; backupPath: string }): Promise<VaultRecoveryResult> =>
    ipcRenderer.invoke('vault.backups.recover', payload),
  vaultUnlock: (payload: { path: string; masterPassword: string }): Promise<VaultStatus> =>
    ipcRenderer.invoke('vault.unlock', payload),
  vaultLock: (): Promise<boolean> => ipcRenderer.invoke('vault.lock'),
  importCsvPreview: (payload: { inputPath: string }): Promise<ImportPreview> => ipcRenderer.invoke('import.csv.preview', payload),
  importCsvApply: (payload: { inputPath: string; decisions: ImportDuplicateDecision[] }): Promise<ImportResult> =>
    ipcRenderer.invoke('import.csv.apply', payload),
  importBitwardenPreview: (payload: { inputPath: string }): Promise<ImportPreview> =>
    ipcRenderer.invoke('import.bitwarden.preview', payload),
  importBitwardenApply: (payload: { inputPath: string; decisions: ImportDuplicateDecision[] }): Promise<ImportResult> =>
    ipcRenderer.invoke('import.bitwarden.apply', payload),
  exportCsv: (payload: { outputPath: string; includeSecrets: boolean; acknowledged?: boolean }): Promise<number> =>
    ipcRenderer.invoke('export.csv', payload),
  exportJson: (payload: { outputPath: string; includeSecrets: boolean; acknowledged?: boolean }): Promise<number> =>
    ipcRenderer.invoke('export.json', payload),
  exportEncrypted: (payload: { outputPath: string; exportPassword: string; masterPassword: string; redacted: boolean }): Promise<number> =>
    ipcRenderer.invoke('export.encrypted', payload),
  itemList: (payload: { query?: string | null }): Promise<ItemSummary[]> => ipcRenderer.invoke('item.list', payload),
  loginGet: (payload: { id: string }): Promise<LoginDetail> => ipcRenderer.invoke('item.login.get', payload),
  noteGet: (payload: { id: string }): Promise<NoteDetail> => ipcRenderer.invoke('item.note.get', payload),
  passkeyRefGet: (payload: { id: string }): Promise<PasskeyRefDetail> => ipcRenderer.invoke('item.passkey.get', payload),
  passkeyRefAdd: (payload: AddPasskeyRefInput): Promise<string> => ipcRenderer.invoke('item.passkey.add', payload),
  passkeyRefUpdate: (payload: {
    id: string
    title: string
    notes?: string | null
    tags?: string[] | null
    favorite?: boolean | null
  }): Promise<boolean> =>
    ipcRenderer.invoke('item.passkey.update', payload),
  passkeyOpenSite: (payload: { id: string }): Promise<boolean> => ipcRenderer.invoke('item.passkey.open-site', payload),
  passkeyOpenManager: (): Promise<boolean> => ipcRenderer.invoke('passkey.open-manager'),
  noteAdd: (payload: AddNoteInput): Promise<string> => ipcRenderer.invoke('item.note.add', payload),
  noteUpdate: (payload: UpdateNoteInput): Promise<boolean> => ipcRenderer.invoke('item.note.update', payload),
  loginAdd: (payload: AddLoginInput): Promise<string> => ipcRenderer.invoke('item.login.add', payload),
  loginUpdate: (payload: UpdateLoginInput): Promise<boolean> =>
    ipcRenderer.invoke('item.login.update', payload),
  itemDelete: (payload: { id: string }): Promise<boolean> => ipcRenderer.invoke('item.delete', payload),
  loginCopyUsername: (payload: { id: string }): Promise<boolean> =>
    ipcRenderer.invoke('item.login.copy-username', payload),
  loginCopyPassword: (payload: { id: string }): Promise<boolean> =>
    ipcRenderer.invoke('item.login.copy-password', payload),
  loginRevealPassword: (payload: { id: string }): Promise<string> =>
    ipcRenderer.invoke('item.login.reveal-password', payload),
  loginGenerateReplacePassword: (payload: { id: string }): Promise<string> =>
    ipcRenderer.invoke('item.login.generate-replace-password', payload),
  loginTotpGet: (payload: { id: string }): Promise<TotpCode> => ipcRenderer.invoke('item.login.totp.get', payload),
  loginTotpQrSvg: (payload: { id: string }): Promise<string> => ipcRenderer.invoke('item.login.totp.qr-svg', payload),
  loginTotpSet: (payload: { id: string; value: string }): Promise<boolean> => ipcRenderer.invoke('item.login.totp.set', payload),
  loginCopyTotp: (payload: { id: string }): Promise<boolean> => ipcRenderer.invoke('item.login.copy-totp', payload),
})
