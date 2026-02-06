import { contextBridge, ipcRenderer } from 'electron'

type VaultStatus = {
  path: string
  label: string
  itemCount: number
  kdfMemoryKib: number
  kdfIterations: number
  kdfParallelism: number
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

type TotpCode = {
  code: string
  period: number
  remaining: number
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
  vaultRecentsList: (): Promise<RecentVault[]> => ipcRenderer.invoke('vault.recents.list'),
  vaultRecentsRemove: (payload: { path: string }): Promise<boolean> => ipcRenderer.invoke('vault.recents.remove', payload),
  vaultDialogOpen: (): Promise<string | null> => ipcRenderer.invoke('vault.dialog.open'),
  vaultDialogCreate: (): Promise<string | null> => ipcRenderer.invoke('vault.dialog.create'),
  vaultCreate: (payload: { path: string; masterPassword: string; label?: string }): Promise<boolean> =>
    ipcRenderer.invoke('vault.create', payload),
  vaultStatus: (payload: { path: string }): Promise<VaultStatus> => ipcRenderer.invoke('vault.status', payload),
  vaultCheck: (payload: { path: string; masterPassword: string }): Promise<VaultStatus> =>
    ipcRenderer.invoke('vault.check', payload),
  vaultUnlock: (payload: { path: string; masterPassword: string }): Promise<VaultStatus> =>
    ipcRenderer.invoke('vault.unlock', payload),
  vaultLock: (): Promise<boolean> => ipcRenderer.invoke('vault.lock'),
  itemList: (payload: { query?: string | null }): Promise<ItemSummary[]> => ipcRenderer.invoke('item.list', payload),
  loginGet: (payload: { id: string }): Promise<LoginDetail> => ipcRenderer.invoke('item.login.get', payload),
  noteGet: (payload: { id: string }): Promise<NoteDetail> => ipcRenderer.invoke('item.note.get', payload),
  noteAdd: (payload: { title: string; body: string }): Promise<string> => ipcRenderer.invoke('item.note.add', payload),
  loginAdd: (payload: AddLoginInput): Promise<string> => ipcRenderer.invoke('item.login.add', payload),
  loginCopyUsername: (payload: { id: string }): Promise<boolean> =>
    ipcRenderer.invoke('item.login.copy-username', payload),
  loginCopyPassword: (payload: { id: string }): Promise<boolean> =>
    ipcRenderer.invoke('item.login.copy-password', payload),
  loginTotpGet: (payload: { id: string }): Promise<TotpCode> => ipcRenderer.invoke('item.login.totp.get', payload),
  loginCopyTotp: (payload: { id: string }): Promise<boolean> => ipcRenderer.invoke('item.login.copy-totp', payload),
})
