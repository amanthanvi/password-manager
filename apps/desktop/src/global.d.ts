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

  interface AppConfig {
    configPath: string
    defaultVault: string | null
    security: {
      clipboardTimeoutSeconds: number
      autoLockMinutes: number
      lockOnSuspend: boolean
      revealRequiresConfirm: boolean
    }
    generator: {
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
    logging: { level: string }
    backup: { maxRetained: number }
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

  interface UrlEntry {
    url: string
    matchType: 'exact' | 'domain' | 'subdomain'
  }

  interface LoginDetail {
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

  interface ImportDuplicate {
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

  interface ImportPreview {
    importType: string
    candidates: number
    duplicates: ImportDuplicate[]
    warnings: string[]
  }

  interface ImportDuplicateDecision {
    sourceIndex: number
    action: 'skip' | 'overwrite' | 'keep_both'
  }

  interface ImportResult {
    imported: number
    skipped: number
    overwritten: number
    warnings: string[]
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
      importDialogCsv: () => Promise<string | null>
      importDialogBitwarden: () => Promise<string | null>
      exportDialogCsv: () => Promise<string | null>
      exportDialogJson: () => Promise<string | null>
      exportDialogEncrypted: () => Promise<string | null>
      vaultCreate: (payload: { path: string; masterPassword: string; label?: string }) => Promise<boolean>
      vaultStatus: (payload: { path: string }) => Promise<VaultStatus>
      vaultCheck: (payload: { path: string; masterPassword: string }) => Promise<VaultStatus>
      vaultBackupsList: (payload: { path: string }) => Promise<{ path: string; timestamp: number; itemCount: number; label: string }[]>
      vaultRecoverFromBackup: (payload: { path: string; backupPath: string }) => Promise<{ corruptPath: string | null }>
      vaultUnlock: (payload: { path: string; masterPassword: string }) => Promise<VaultStatus>
      vaultLock: () => Promise<boolean>
      configLoad: () => Promise<AppConfig>
      configSet: (payload: { key: string; value: string }) => Promise<AppConfig>
      importCsvPreview: (payload: { inputPath: string }) => Promise<ImportPreview>
      importCsvApply: (payload: { inputPath: string; decisions: ImportDuplicateDecision[] }) => Promise<ImportResult>
      importBitwardenPreview: (payload: { inputPath: string }) => Promise<ImportPreview>
      importBitwardenApply: (payload: { inputPath: string; decisions: ImportDuplicateDecision[] }) => Promise<ImportResult>
      exportCsv: (payload: { outputPath: string; includeSecrets: boolean; acknowledged?: boolean }) => Promise<number>
      exportJson: (payload: { outputPath: string; includeSecrets: boolean; acknowledged?: boolean }) => Promise<number>
      exportEncrypted: (payload: {
        outputPath: string
        exportPassword: string
        masterPassword: string
        redacted: boolean
      }) => Promise<number>
      itemList: (payload: { query?: string | null }) => Promise<ItemSummary[]>
      loginGet: (payload: { id: string }) => Promise<LoginDetail>
      noteGet: (payload: { id: string }) => Promise<NoteDetail>
      passkeyRefGet: (payload: { id: string }) => Promise<PasskeyRefDetail>
      passkeyOpenSite: (payload: { id: string }) => Promise<boolean>
      passkeyOpenManager: () => Promise<boolean>
      passkeyRefAdd: (payload: {
        title: string
        rpId: string
        rpName?: string | null
        userDisplayName?: string | null
        credentialIdHex: string
        notes?: string | null
        tags?: string[] | null
        favorite?: boolean | null
      }) => Promise<string>
      passkeyRefUpdate: (payload: { id: string; title: string; notes?: string | null; tags?: string[] | null; favorite?: boolean | null }) => Promise<boolean>
      noteAdd: (payload: { title: string; body: string; tags?: string[] | null; favorite?: boolean | null }) => Promise<string>
      noteUpdate: (payload: { id: string; title: string; body: string; tags?: string[] | null; favorite?: boolean | null }) => Promise<boolean>
      loginAdd: (payload: {
        title: string
        urls?: { url: string; matchType?: string | null }[] | null
        username?: string | null
        password?: string | null
        notes?: string | null
        tags?: string[] | null
        favorite?: boolean | null
      }) => Promise<string>
      loginUpdate: (payload: {
        id: string
        title: string
        urls?: { url: string; matchType?: string | null }[] | null
        username?: string | null
        notes?: string | null
        tags?: string[] | null
        favorite?: boolean | null
      }) => Promise<boolean>
      itemDelete: (payload: { id: string }) => Promise<boolean>
      loginCopyUsername: (payload: { id: string }) => Promise<boolean>
      loginCopyPassword: (payload: { id: string }) => Promise<boolean>
      loginRevealPassword: (payload: { id: string }) => Promise<string>
      loginGenerateReplacePassword: (payload: { id: string }) => Promise<string>
      loginTotpGet: (payload: { id: string }) => Promise<TotpCode>
      loginTotpQrSvg: (payload: { id: string }) => Promise<string>
      loginTotpSet: (payload: { id: string; value: string }) => Promise<boolean>
      loginCopyTotp: (payload: { id: string }) => Promise<boolean>
    }
  }
}

export {}
