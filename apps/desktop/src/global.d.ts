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

  interface NoteDetail {
    id: string
    title: string
    body: string
    favorite: boolean
    createdAt: number
    updatedAt: number
    tags: string[]
  }

  interface PasskeyRefDetail {
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

  interface TotpCode {
    code: string
    period: number
    remaining: number
  }

  interface Window {
    npw: {
      coreBanner: () => Promise<string>
      appActivity: () => Promise<boolean>
      onVaultLocked: (callback: (payload: { reason: string }) => void) => () => void
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
      noteGet: (payload: { id: string }) => Promise<NoteDetail>
      passkeyRefGet: (payload: { id: string }) => Promise<PasskeyRefDetail>
      passkeyOpenSite: (payload: { id: string }) => Promise<boolean>
      passkeyOpenManager: () => Promise<boolean>
      noteAdd: (payload: { title: string; body: string }) => Promise<string>
      loginAdd: (payload: {
        title: string
        url?: string | null
        username?: string | null
        password?: string | null
        notes?: string | null
      }) => Promise<string>
      itemDelete: (payload: { id: string }) => Promise<boolean>
      loginCopyUsername: (payload: { id: string }) => Promise<boolean>
      loginCopyPassword: (payload: { id: string }) => Promise<boolean>
      loginTotpGet: (payload: { id: string }) => Promise<TotpCode>
      loginCopyTotp: (payload: { id: string }) => Promise<boolean>
    }
  }
}

export {}
