declare global {
  interface VaultStatus {
    path: string
    label: string
    itemCount: number
    kdfMemoryKib: number
    kdfIterations: number
    kdfParallelism: number
  }

  interface Window {
    npw: {
      coreBanner: () => Promise<string>
      vaultCreate: (payload: { path: string; masterPassword: string; label?: string }) => Promise<boolean>
      vaultStatus: (payload: { path: string }) => Promise<VaultStatus>
      vaultCheck: (payload: { path: string; masterPassword: string }) => Promise<VaultStatus>
    }
  }
}

export {}
