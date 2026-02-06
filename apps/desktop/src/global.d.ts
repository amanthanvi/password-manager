declare global {
  interface VaultStatus {
    path: string
    label: string
    itemCount: number
    kdfMemoryKib: number
    kdfIterations: number
    kdfParallelism: number
  }

  interface ItemSummary {
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

  interface Window {
    npw: {
      coreBanner: () => Promise<string>
      vaultCreate: (payload: { path: string; masterPassword: string; label?: string }) => Promise<boolean>
      vaultStatus: (payload: { path: string }) => Promise<VaultStatus>
      vaultCheck: (payload: { path: string; masterPassword: string }) => Promise<VaultStatus>
      vaultUnlock: (payload: { path: string; masterPassword: string }) => Promise<VaultStatus>
      vaultLock: () => Promise<boolean>
      itemList: (payload: { query?: string | null }) => Promise<ItemSummary[]>
    }
  }
}

export {}
