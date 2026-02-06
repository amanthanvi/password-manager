declare global {
  interface VaultStatus {
    path: string
    label: string
    itemCount: number
    kdfMemoryKib: number
    kdfIterations: number
    kdfParallelism: number
  }

  interface RecentVault {
    path: string
    label: string
    lastOpenedAt: number
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

  interface LoginDetail {
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

  interface TotpCode {
    code: string
    period: number
    remaining: number
  }

  interface Window {
    npw: {
      coreBanner: () => Promise<string>
      vaultRecentsList: () => Promise<RecentVault[]>
      vaultRecentsRemove: (payload: { path: string }) => Promise<boolean>
      vaultDialogOpen: () => Promise<string | null>
      vaultDialogCreate: () => Promise<string | null>
      vaultCreate: (payload: { path: string; masterPassword: string; label?: string }) => Promise<boolean>
      vaultStatus: (payload: { path: string }) => Promise<VaultStatus>
      vaultCheck: (payload: { path: string; masterPassword: string }) => Promise<VaultStatus>
      vaultUnlock: (payload: { path: string; masterPassword: string }) => Promise<VaultStatus>
      vaultLock: () => Promise<boolean>
      itemList: (payload: { query?: string | null }) => Promise<ItemSummary[]>
      loginGet: (payload: { id: string }) => Promise<LoginDetail>
      loginCopyUsername: (payload: { id: string }) => Promise<boolean>
      loginCopyPassword: (payload: { id: string }) => Promise<boolean>
      loginTotpGet: (payload: { id: string }) => Promise<TotpCode>
      loginCopyTotp: (payload: { id: string }) => Promise<boolean>
    }
  }
}

export {}
