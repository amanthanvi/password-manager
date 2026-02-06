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
  itemList: (payload: { query?: string | null }): Promise<ItemSummary[]> => ipcRenderer.invoke('item.list', payload),
  loginGet: (payload: { id: string }): Promise<LoginDetail> => ipcRenderer.invoke('item.login.get', payload),
  noteGet: (payload: { id: string }): Promise<NoteDetail> => ipcRenderer.invoke('item.note.get', payload),
  passkeyRefGet: (payload: { id: string }): Promise<PasskeyRefDetail> => ipcRenderer.invoke('item.passkey.get', payload),
  passkeyOpenSite: (payload: { id: string }): Promise<boolean> => ipcRenderer.invoke('item.passkey.open-site', payload),
  passkeyOpenManager: (): Promise<boolean> => ipcRenderer.invoke('passkey.open-manager'),
  noteAdd: (payload: { title: string; body: string }): Promise<string> => ipcRenderer.invoke('item.note.add', payload),
  noteUpdate: (payload: { id: string; title: string; body: string }): Promise<boolean> =>
    ipcRenderer.invoke('item.note.update', payload),
  loginAdd: (payload: AddLoginInput): Promise<string> => ipcRenderer.invoke('item.login.add', payload),
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
