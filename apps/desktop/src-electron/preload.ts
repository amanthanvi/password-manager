import { contextBridge, ipcRenderer } from 'electron'

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

contextBridge.exposeInMainWorld('npw', {
  coreBanner: (): Promise<string> => ipcRenderer.invoke('core.banner'),
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
  loginCopyUsername: (payload: { id: string }): Promise<boolean> =>
    ipcRenderer.invoke('item.login.copy-username', payload),
  loginCopyPassword: (payload: { id: string }): Promise<boolean> =>
    ipcRenderer.invoke('item.login.copy-password', payload),
})
