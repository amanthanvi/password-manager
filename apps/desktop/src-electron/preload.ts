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
})
