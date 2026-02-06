<script>
  import { onDestroy, onMount } from 'svelte'
  import { APP_TITLE, formatStatus } from './lib/app'
  import jsQR from 'jsqr'

  let vaultPath = '/tmp/npw-desktop.npw'
  let vaultLabel = 'Desktop Vault'
  let masterPassword = ''
  let quickUnlockForPath = { available: true, configured: false, enabled: false, error: null }
  let quickUnlockForCurrent = { available: true, configured: false, enabled: false, error: null }
  let quickUnlockBusy = false
  let query = ''
  let bridgeStatus = 'initializing'
  let bridgeAvailable = false
  let npw = null
  let lastResult = ''
  let status = null
  let items = []
  let selectedItem = null
  let loginDetail = null
  let noteDetail = null
  let passkeyDetail = null
  let passkeyEditTitle = ''
  let passkeyEditNotes = ''
  let passkeyEditTagsRaw = ''
  let passkeyEditFavorite = false
  let passkeyEditBusy = false
  let passkeyEditError = ''
  let totp = null
  let totpInterval = null
  let totpQrUrl = null
  let totpQrVisible = false
  let totpImportVisible = false
  let totpImportValue = ''
  let totpImportError = ''
  let totpImportBusy = false
  let totpImportVideo = null
  let totpImportStream = null
  let totpImportCanvas = null
  let totpImportContext = null
  let totpImportFrameId = null
  let recents = []
  let newNoteTitle = ''
  let newNoteBody = ''
  let newNoteTagsRaw = ''
  let newNoteFavorite = false
  let noteEditTitle = ''
  let noteEditBody = ''
  let noteEditTagsRaw = ''
  let noteEditFavorite = false
  let noteEditBusy = false
  let noteEditError = ''
  let newLoginTitle = ''
  let newLoginUrls = [{ url: '', matchType: 'exact' }]
  let newLoginUsername = ''
  let newLoginPassword = ''
  let newLoginNotes = ''
  let newLoginTagsRaw = ''
  let newLoginFavorite = false
  let loginEditTitle = ''
  let loginEditUrls = [{ url: '', matchType: 'exact' }]
  let loginEditUsername = ''
  let loginEditNotes = ''
  let loginEditTagsRaw = ''
  let loginEditFavorite = false
  let loginEditBusy = false
  let loginEditError = ''
  let newPasskeyTitle = ''
  let newPasskeyRpId = ''
  let newPasskeyRpName = ''
  let newPasskeyUserDisplayName = ''
  let newPasskeyCredentialIdHex = ''
  let newPasskeyNotes = ''
  let newPasskeyTagsRaw = ''
  let newPasskeyFavorite = false
  let newPasskeyBusy = false
  let newPasskeyError = ''
  let detachVaultLocked = null
  let activityListener = null
  let lastActivityPingAt = 0
  let recoveryVisible = false
  let recoveryVaultPath = ''
  let recoveryBackups = []
  let recoverySelectedBackupPath = ''
  let recoveryBusy = false
  let recoveryError = ''
  let appConfig = null
  let settingsClipboardTimeoutSeconds = 30
  let settingsAutoLockMinutes = 5
  let settingsLockOnSuspend = true
  let settingsRevealRequiresConfirm = true
  let settingsLogLevel = 'info'
  let settingsSaving = false
  let settingsError = ''
  let revealedPassword = null
  let revealPasswordTimeoutId = null
  let toastNextId = 0
  let toasts = []
  let filterType = 'all'
  let filterFavoritesOnly = false
  let filterTag = ''
  let importType = null
  let importInputPath = ''
  let importPreview = null
  let importDecisions = {}
  let importBusy = false
  let importError = ''
  let encryptedExportVisible = false
  let encryptedExportOutputPath = ''
  let encryptedExportPassword = ''
  let encryptedExportPasswordConfirm = ''
  let encryptedExportMasterPassword = ''
  let encryptedExportRedacted = false
  let encryptedExportBusy = false
  let encryptedExportError = ''

  $: availableTags = (() => {
    const seen = Object.create(null)
    const tags = []
    for (const item of items) {
      const itemTags = Array.isArray(item.tags) ? item.tags : []
      for (const rawTag of itemTags) {
        if (typeof rawTag !== 'string') {
          continue
        }
        const normalized = rawTag.trim().toLowerCase()
        if (normalized.length === 0) {
          continue
        }
        if (seen[normalized]) {
          continue
        }
        seen[normalized] = true
        tags.push(normalized)
      }
    }
    tags.sort()
    return tags
  })()

  $: itemsView = items.filter((item) => {
    if (filterType !== 'all' && item.itemType !== filterType) {
      return false
    }
    if (filterFavoritesOnly && !item.favorite) {
      return false
    }
    const needle = filterTag.trim().toLowerCase()
    if (needle.length > 0) {
      const tags = Array.isArray(item.tags) ? item.tags : []
      const matchesTag = tags.some((tag) => String(tag).trim().toLowerCase() === needle)
      if (!matchesTag) {
        return false
      }
    }
    return true
  })

  const dismissToast = (id) => {
    toasts = toasts.filter((toast) => toast.id !== id)
  }

  const pushToast = ({
    kind = 'info',
    title,
    detail = null,
    retryLabel = null,
    retry = null,
    timeoutMs = null
  }) => {
    const id = (toastNextId += 1)
    const toast = { id, kind, title, detail, retryLabel, retry }
    toasts = [toast, ...toasts].slice(0, 6)
    if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
      setTimeout(() => dismissToast(id), timeoutMs)
    }
  }

  const collapseWhitespace = (value) => String(value).split(/\s+/).filter(Boolean).join(' ')

  const parseTagsRaw = (raw) => {
    const parts = String(raw)
      .split(';')
      .map((tag) => collapseWhitespace(tag).trim())
      .filter((tag) => tag.length > 0)

    const seen = Object.create(null)
    const tags = []
    for (const tag of parts) {
      const key = tag.toLowerCase()
      if (seen[key]) {
        continue
      }
      seen[key] = true
      tags.push(tag)
    }
    return tags
  }

  const formatTagsRaw = (tags) => (Array.isArray(tags) && tags.length > 0 ? tags.join('; ') : '')

  const normalizeUrlInputs = (entries) =>
    (Array.isArray(entries) ? entries : [])
      .map((entry) => ({
        url: String(entry?.url ?? '').trim(),
        matchType: entry?.matchType === 'domain' || entry?.matchType === 'subdomain' ? entry.matchType : 'exact'
      }))
      .filter((entry) => entry.url.length > 0)

  const ensureUrlEditorRows = (entries) => {
    const normalized = normalizeUrlInputs(entries)
    return normalized.length > 0 ? normalized : [{ url: '', matchType: 'exact' }]
  }

  onMount(async () => {
    npw = typeof window !== 'undefined' ? window['npw'] : null

    bridgeAvailable =
      typeof window !== 'undefined' &&
      npw &&
      typeof npw.coreBanner === 'function' &&
      typeof npw.onVaultLocked === 'function'

    if (!bridgeAvailable) {
      bridgeStatus = formatStatus(
        'Desktop bridge unavailable. This UI must be run inside Electron. Run `pnpm --filter desktop dev`.'
      )
      return
    }

    try {
      const banner = await npw.coreBanner()
      bridgeStatus = formatStatus(banner)
    } catch (error) {
      bridgeStatus = formatStatus(formatError(error))
    }

    try {
      await refreshRecents()
    } catch {
      // Best-effort: recents are not security-critical.
    }

    try {
      await refreshConfig()
    } catch {
      // Best-effort: config UI falls back to defaults.
    }

    detachVaultLocked = npw.onVaultLocked(({ reason }) => {
      status = null
      items = []
      selectedItem = null
      loginDetail = null
      loginEditTitle = ''
      loginEditUrls = [{ url: '', matchType: 'exact' }]
      loginEditUsername = ''
      loginEditNotes = ''
      loginEditTagsRaw = ''
      loginEditFavorite = false
      loginEditBusy = false
      loginEditError = ''
      noteDetail = null
      noteEditTitle = ''
      noteEditBody = ''
      noteEditTagsRaw = ''
      noteEditFavorite = false
      noteEditBusy = false
      noteEditError = ''
      passkeyDetail = null
      passkeyEditTitle = ''
      passkeyEditNotes = ''
      passkeyEditTagsRaw = ''
      passkeyEditFavorite = false
      passkeyEditBusy = false
      passkeyEditError = ''
      totp = null
      totpQrUrl = null
      totpQrVisible = false
      closeTotpImport()
      clearImportState()
      closeEncryptedExport()
      clearTotpInterval()
      masterPassword = ''
      newNoteTitle = ''
      newNoteBody = ''
      newNoteTagsRaw = ''
      newNoteFavorite = false
      newLoginTitle = ''
      newLoginUrls = [{ url: '', matchType: 'exact' }]
      newLoginUsername = ''
      newLoginPassword = ''
      newLoginNotes = ''
      newLoginTagsRaw = ''
      newLoginFavorite = false
      newPasskeyTitle = ''
      newPasskeyRpId = ''
      newPasskeyRpName = ''
      newPasskeyUserDisplayName = ''
      newPasskeyCredentialIdHex = ''
      newPasskeyNotes = ''
      newPasskeyTagsRaw = ''
      newPasskeyFavorite = false
      newPasskeyBusy = false
      newPasskeyError = ''
      recoveryVisible = false
      recoveryVaultPath = ''
      recoveryBackups = []
      recoverySelectedBackupPath = ''
      recoveryBusy = false
      recoveryError = ''
      quickUnlockForCurrent = { available: true, configured: false, enabled: false, error: null }
      quickUnlockBusy = false
      void refreshQuickUnlockForPath()
      settingsError = ''
      clearRevealedPassword()
      lastResult = `Vault locked (${reason})`
    })

    activityListener = () => {
      if (!status) {
        return
      }
      const now = Date.now()
      if (now - lastActivityPingAt < 10_000) {
        return
      }
      lastActivityPingAt = now
      npw.appActivity().catch(() => {})
    }
    window.addEventListener('mousemove', activityListener)
    window.addEventListener('mousedown', activityListener)
    window.addEventListener('keydown', activityListener)
    window.addEventListener('touchstart', activityListener)
  })

  onDestroy(() => {
    stopTotpImportCamera()
    clearTotpInterval()
    if (typeof detachVaultLocked === 'function') {
      detachVaultLocked()
    }
    if (activityListener) {
      window.removeEventListener('mousemove', activityListener)
      window.removeEventListener('mousedown', activityListener)
      window.removeEventListener('keydown', activityListener)
      window.removeEventListener('touchstart', activityListener)
    }
  })

  const createVault = async () => {
    try {
      await npw.vaultCreate({
        path: vaultPath,
        masterPassword,
        label: vaultLabel
      })
      lastResult = `Created vault at ${vaultPath}`
      pushToast({ kind: 'success', title: lastResult, timeoutMs: 4000 })
      await refreshRecents()
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({ kind: 'error', title: 'Create vault failed', detail: message })
    }
  }

  const unlockVault = async () => {
    try {
      status = await npw.vaultUnlock({
        path: vaultPath,
        masterPassword
      })
      masterPassword = ''
      lastResult = `Vault unlocked: ${status.path}`
      pushToast({ kind: 'success', title: 'Vault unlocked', timeoutMs: 3500 })
      await refreshRecents()
      await refreshItems()
      await refreshQuickUnlockForCurrent()
    } catch (error) {
      const message = formatError(error)
      const shouldOfferRecovery =
        message.includes('authentication failed') || message.startsWith('invalid header:')
      if (shouldOfferRecovery) {
        try {
          const opened = await openRecoveryWizard(vaultPath)
          if (opened) {
            lastResult =
              'Unlock failed (authentication failed). If your password is correct, the vault may be corrupted. Recovery wizard opened.'
            pushToast({ kind: 'error', title: 'Unlock failed', detail: lastResult })
            return
          }
        } catch {
          // Best-effort: recovery wizard is not required for wrong-password cases.
        }
      }
      lastResult = message
      pushToast({
        kind: 'error',
        title: 'Unlock failed',
        detail: message,
        retryLabel: 'Retry',
        retry: unlockVault
      })
    }
  }

  const quickUnlockVault = async () => {
    quickUnlockBusy = true
    try {
      status = await npw.vaultUnlockQuick({ path: vaultPath })
      masterPassword = ''
      lastResult = `Vault quick-unlocked: ${status.path}`
      pushToast({ kind: 'success', title: 'Vault quick-unlocked', timeoutMs: 3500 })
      await refreshRecents()
      await refreshItems()
      await refreshQuickUnlockForCurrent()
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({
        kind: 'error',
        title: 'Quick Unlock failed',
        detail: message,
        retryLabel: 'Retry',
        retry: quickUnlockVault
      })
    } finally {
      quickUnlockBusy = false
    }
  }

  const setQuickUnlockEnabled = async (nextEnabled) => {
    if (!status) {
      return
    }

    quickUnlockBusy = true
    try {
      if (nextEnabled) {
        const confirmed = confirm(
          'Warning: Enabling Quick Unlock stores key material in your OS keychain. Anyone who can access your OS user session/keychain may unlock this vault without the master password. Enable Quick Unlock for this vault?'
        )
        if (!confirmed) {
          return
        }
        await npw.quickUnlockEnable()
        lastResult = 'Quick Unlock enabled'
        pushToast({ kind: 'info', title: 'Quick Unlock enabled', timeoutMs: 3500 })
      } else {
        await npw.quickUnlockDisable()
        lastResult = 'Quick Unlock disabled'
        pushToast({ kind: 'info', title: 'Quick Unlock disabled', timeoutMs: 3500 })
      }
      await refreshQuickUnlockForCurrent()
      await refreshQuickUnlockForPath()
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({
        kind: 'error',
        title: nextEnabled ? 'Enable Quick Unlock failed' : 'Disable Quick Unlock failed',
        detail: message,
        retryLabel: 'Retry',
        retry: () => setQuickUnlockEnabled(nextEnabled)
      })
    } finally {
      quickUnlockBusy = false
    }
  }

  const formatBackupTimestamp = (timestamp) => {
    const parsed = Number(timestamp)
    if (!Number.isFinite(parsed)) {
      return String(timestamp)
    }
    return new Date(parsed * 1000).toLocaleString()
  }

  const closeRecoveryWizard = () => {
    recoveryVisible = false
    recoveryVaultPath = ''
    recoveryBackups = []
    recoverySelectedBackupPath = ''
    recoveryBusy = false
    recoveryError = ''
  }

  const openRecoveryWizard = async (path) => {
    recoveryVaultPath = path
    recoveryError = ''
    recoveryBusy = true
    try {
      recoveryBackups = await npw.vaultBackupsList({ path })
      recoverySelectedBackupPath = recoveryBackups[0]?.path ?? ''
      recoveryVisible = recoveryBackups.length > 0
      return recoveryVisible
    } finally {
      recoveryBusy = false
    }
  }

  const clearRevealedPassword = () => {
    revealedPassword = null
    if (revealPasswordTimeoutId) {
      clearTimeout(revealPasswordTimeoutId)
      revealPasswordTimeoutId = null
    }
  }

  const recoverFromSelectedBackup = async () => {
    if (!recoveryVaultPath || !recoverySelectedBackupPath) {
      return
    }
    if (masterPassword.trim().length === 0) {
      recoveryError = 'Master password is required to verify a backup before restoring.'
      return
    }
    recoveryBusy = true
    recoveryError = ''
    try {
      await npw.vaultCheck({ path: recoverySelectedBackupPath, masterPassword })
      const result = await npw.vaultRecoverFromBackup({
        path: recoveryVaultPath,
        backupPath: recoverySelectedBackupPath
      })
      if (result?.corruptPath) {
        lastResult = `Preserved corrupt vault at ${result.corruptPath}`
      }
      status = await npw.vaultUnlock({
        path: recoveryVaultPath,
        masterPassword
      })
      masterPassword = ''
      closeRecoveryWizard()
      lastResult = `Recovered vault from backup and unlocked: ${status.path}`
      pushToast({ kind: 'success', title: 'Recovered vault from backup', timeoutMs: 4500 })
      await refreshRecents()
      await refreshItems()
    } catch (error) {
      recoveryError = formatError(error)
      pushToast({ kind: 'error', title: 'Recovery failed', detail: recoveryError })
    } finally {
      recoveryBusy = false
    }
  }

  const lockVault = async () => {
    try {
      await npw.vaultLock()
      status = null
      items = []
      selectedItem = null
      loginDetail = null
      loginEditTitle = ''
      loginEditUrls = [{ url: '', matchType: 'exact' }]
      loginEditUsername = ''
      loginEditNotes = ''
      loginEditTagsRaw = ''
      loginEditFavorite = false
      loginEditBusy = false
      loginEditError = ''
      noteDetail = null
      noteEditTitle = ''
      noteEditBody = ''
      noteEditTagsRaw = ''
      noteEditFavorite = false
      noteEditBusy = false
      noteEditError = ''
      passkeyDetail = null
      passkeyEditTitle = ''
      passkeyEditNotes = ''
      passkeyEditTagsRaw = ''
      passkeyEditFavorite = false
      passkeyEditBusy = false
      passkeyEditError = ''
      totp = null
      totpQrUrl = null
      totpQrVisible = false
      closeTotpImport()
      clearImportState()
      closeEncryptedExport()
      clearTotpInterval()
      newNoteTitle = ''
      newNoteBody = ''
      newNoteTagsRaw = ''
      newNoteFavorite = false
      newLoginTitle = ''
      newLoginUrls = [{ url: '', matchType: 'exact' }]
      newLoginUsername = ''
      newLoginPassword = ''
      newLoginNotes = ''
      newLoginTagsRaw = ''
      newLoginFavorite = false
      newPasskeyTitle = ''
      newPasskeyRpId = ''
      newPasskeyRpName = ''
      newPasskeyUserDisplayName = ''
      newPasskeyCredentialIdHex = ''
      newPasskeyNotes = ''
      newPasskeyTagsRaw = ''
      newPasskeyFavorite = false
      newPasskeyBusy = false
      newPasskeyError = ''
      closeRecoveryWizard()
      quickUnlockForCurrent = { available: true, configured: false, enabled: false, error: null }
      quickUnlockBusy = false
      await refreshQuickUnlockForPath()
      clearRevealedPassword()
      lastResult = 'Vault locked'
      pushToast({ kind: 'info', title: 'Vault locked', timeoutMs: 3500 })
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({
        kind: 'error',
        title: 'Lock vault failed',
        detail: message,
        retryLabel: 'Retry',
        retry: lockVault
      })
    }
  }

  const refreshRecents = async () => {
    recents = await npw.vaultRecentsList()
    await refreshQuickUnlockForPath()
  }

  const refreshQuickUnlockForPath = async () => {
    const safePath = vaultPath.trim()
    if (safePath.length === 0) {
      quickUnlockForPath = { available: true, configured: false, enabled: false, error: null }
      return
    }
    try {
      quickUnlockForPath = await npw.quickUnlockStatusForPath({ path: safePath })
    } catch (error) {
      quickUnlockForPath = { available: false, configured: false, enabled: false, error: formatError(error) }
    }
  }

  const refreshQuickUnlockForCurrent = async () => {
    if (!status) {
      quickUnlockForCurrent = { available: true, configured: false, enabled: false, error: null }
      return
    }
    try {
      quickUnlockForCurrent = await npw.quickUnlockStatusCurrent()
    } catch (error) {
      quickUnlockForCurrent = { available: false, configured: true, enabled: false, error: formatError(error) }
    }
  }

  const refreshConfig = async () => {
    settingsError = ''
    try {
      appConfig = await npw.configLoad()
      if (appConfig?.security) {
        settingsClipboardTimeoutSeconds = appConfig.security.clipboardTimeoutSeconds
        settingsAutoLockMinutes = appConfig.security.autoLockMinutes
        settingsLockOnSuspend = appConfig.security.lockOnSuspend
        settingsRevealRequiresConfirm = appConfig.security.revealRequiresConfirm
      }
      if (appConfig?.logging?.level) {
        settingsLogLevel = appConfig.logging.level
      }
    } catch (error) {
      settingsError = formatError(error)
      pushToast({
        kind: 'error',
        title: 'Load settings failed',
        detail: settingsError,
        retryLabel: 'Retry',
        retry: refreshConfig
      })
    }
  }

  const saveSettings = async () => {
    settingsSaving = true
    settingsError = ''
    try {
      appConfig = await npw.configSet({
        key: 'security.clipboard_timeout_seconds',
        value: String(Number(settingsClipboardTimeoutSeconds))
      })
      appConfig = await npw.configSet({
        key: 'security.auto_lock_minutes',
        value: String(Number(settingsAutoLockMinutes))
      })
      appConfig = await npw.configSet({
        key: 'security.lock_on_suspend',
        value: String(Boolean(settingsLockOnSuspend))
      })
      appConfig = await npw.configSet({
        key: 'security.reveal_requires_confirm',
        value: String(Boolean(settingsRevealRequiresConfirm))
      })
      appConfig = await npw.configSet({
        key: 'logging.level',
        value: String(settingsLogLevel)
      })
      lastResult = 'Saved settings'
      pushToast({ kind: 'success', title: 'Saved settings', timeoutMs: 3500 })
      await refreshConfig()
    } catch (error) {
      settingsError = formatError(error)
      pushToast({
        kind: 'error',
        title: 'Save settings failed',
        detail: settingsError,
        retryLabel: 'Retry',
        retry: saveSettings
      })
    } finally {
      settingsSaving = false
    }
  }

  const openRecent = (vault) => {
    vaultPath = vault.path
    if (vault.label) {
      vaultLabel = vault.label
    }
    lastResult = `Selected vault: ${vault.path}`
    void refreshQuickUnlockForPath()
  }

  const removeRecent = async (vault) => {
    try {
      await npw.vaultRecentsRemove({ path: vault.path })
      await refreshRecents()
      lastResult = `Removed ${vault.path} from recents`
      pushToast({ kind: 'success', title: 'Removed recent vault', timeoutMs: 3500 })
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({ kind: 'error', title: 'Remove recent failed', detail: message })
    }
  }

  const pickOpenVault = async () => {
    if (!bridgeAvailable) {
      pushToast({
        kind: 'error',
        title: 'Desktop bridge unavailable',
        detail: 'This UI must be run inside Electron. Run `pnpm --filter desktop dev`.'
      })
      return
    }
    try {
      const picked = await npw.vaultDialogOpen()
      if (!picked) {
        return
      }
      vaultPath = picked
      lastResult = `Selected vault: ${picked}`
      await refreshQuickUnlockForPath()
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({ kind: 'error', title: 'Open vault dialog failed', detail: message })
    }
  }

  const pickCreateVault = async () => {
    if (!bridgeAvailable) {
      pushToast({
        kind: 'error',
        title: 'Desktop bridge unavailable',
        detail: 'This UI must be run inside Electron. Run `pnpm --filter desktop dev`.'
      })
      return
    }
    try {
      const picked = await npw.vaultDialogCreate()
      if (!picked) {
        return
      }
      vaultPath = picked
      lastResult = `Selected new vault path: ${picked}`
      await refreshQuickUnlockForPath()
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({ kind: 'error', title: 'Create vault dialog failed', detail: message })
    }
  }

  const refreshItems = async () => {
    try {
      items = await npw.itemList({ query: query.length > 0 ? query : null })
      if (selectedItem && !items.some((item) => item.id === selectedItem.id)) {
        selectedItem = null
        loginDetail = null
        noteDetail = null
        passkeyDetail = null
        totp = null
        totpQrUrl = null
        totpQrVisible = false
        clearTotpInterval()
      }
      lastResult = `Loaded ${items.length} items`
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({
        kind: 'error',
        title: 'Load items failed',
        detail: message,
        retryLabel: 'Retry',
        retry: refreshItems
      })
    }
  }

  const clearImportState = () => {
    importType = null
    importInputPath = ''
    importPreview = null
    importDecisions = {}
    importBusy = false
    importError = ''
  }

  const startImportCsv = async () => {
    importBusy = true
    importError = ''
    try {
      const picked = await npw.importDialogCsv()
      if (!picked) {
        return
      }
      importType = 'csv'
      importInputPath = picked
      importPreview = await npw.importCsvPreview({ inputPath: picked })
      const nextDecisions = {}
      for (const dup of importPreview.duplicates ?? []) {
        nextDecisions[dup.sourceIndex] = 'skip'
      }
      importDecisions = nextDecisions
      lastResult = `Import preview loaded (${importPreview.candidates} candidates)`
      pushToast({ kind: 'info', title: 'CSV import preview ready', timeoutMs: 3500 })
    } catch (error) {
      importError = formatError(error)
      lastResult = importError
      pushToast({ kind: 'error', title: 'CSV import preview failed', detail: importError })
      clearImportState()
    } finally {
      importBusy = false
    }
  }

  const startImportBitwarden = async () => {
    importBusy = true
    importError = ''
    try {
      const picked = await npw.importDialogBitwarden()
      if (!picked) {
        return
      }
      importType = 'bitwarden'
      importInputPath = picked
      importPreview = await npw.importBitwardenPreview({ inputPath: picked })
      const nextDecisions = {}
      for (const dup of importPreview.duplicates ?? []) {
        nextDecisions[dup.sourceIndex] = 'skip'
      }
      importDecisions = nextDecisions
      lastResult = `Import preview loaded (${importPreview.candidates} candidates)`
      pushToast({ kind: 'info', title: 'Bitwarden import preview ready', timeoutMs: 3500 })
    } catch (error) {
      importError = formatError(error)
      lastResult = importError
      pushToast({ kind: 'error', title: 'Bitwarden import preview failed', detail: importError })
      clearImportState()
    } finally {
      importBusy = false
    }
  }

  const setImportDecision = (sourceIndex, action) => {
    importDecisions = { ...importDecisions, [sourceIndex]: action }
  }

  const applyImport = async () => {
    if (!importPreview || !importType || !importInputPath) {
      return
    }
    importBusy = true
    importError = ''
    try {
      const decisions = Object.entries(importDecisions).map(([sourceIndex, action]) => ({
        sourceIndex: Number(sourceIndex),
        action: String(action)
      }))
      const result =
        importType === 'csv'
          ? await npw.importCsvApply({ inputPath: importInputPath, decisions })
          : await npw.importBitwardenApply({ inputPath: importInputPath, decisions })

      await refreshItems()
      lastResult = `Imported ${result.imported} items (skipped ${result.skipped}, overwritten ${result.overwritten})`
      pushToast({ kind: 'success', title: 'Import complete', detail: lastResult, timeoutMs: 4500 })
      clearImportState()
    } catch (error) {
      importError = formatError(error)
      lastResult = importError
      pushToast({
        kind: 'error',
        title: 'Import failed',
        detail: importError,
        retryLabel: 'Retry',
        retry: applyImport
      })
    } finally {
      importBusy = false
    }
  }

  const exportCsv = async ({ includeSecrets }) => {
    try {
      const outputPath = await npw.exportDialogCsv()
      if (!outputPath) {
        return
      }
      let acknowledged = false
      if (includeSecrets) {
        acknowledged = confirm('Warning: plaintext export includes passwords and note bodies. Continue?')
        if (!acknowledged) {
          return
        }
      }
      const count = await npw.exportCsv({ outputPath, includeSecrets, acknowledged })
      lastResult = `Exported ${count} items to ${outputPath}`
      pushToast({ kind: 'success', title: lastResult, timeoutMs: 4500 })
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({ kind: 'error', title: 'CSV export failed', detail: message })
    }
  }

  const exportJson = async ({ includeSecrets }) => {
    try {
      const outputPath = await npw.exportDialogJson()
      if (!outputPath) {
        return
      }
      let acknowledged = false
      if (includeSecrets) {
        acknowledged = confirm('Warning: plaintext export includes passwords and note bodies. Continue?')
        if (!acknowledged) {
          return
        }
      }
      const count = await npw.exportJson({ outputPath, includeSecrets, acknowledged })
      lastResult = `Exported ${count} items to ${outputPath}`
      pushToast({ kind: 'success', title: lastResult, timeoutMs: 4500 })
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({ kind: 'error', title: 'JSON export failed', detail: message })
    }
  }

  const openEncryptedExport = async () => {
    encryptedExportError = ''
    const picked = await npw.exportDialogEncrypted()
    if (!picked) {
      return
    }
    encryptedExportOutputPath = picked
    encryptedExportPassword = ''
    encryptedExportPasswordConfirm = ''
    encryptedExportMasterPassword = ''
    encryptedExportRedacted = false
    encryptedExportVisible = true
  }

  const closeEncryptedExport = () => {
    encryptedExportVisible = false
    encryptedExportOutputPath = ''
    encryptedExportPassword = ''
    encryptedExportPasswordConfirm = ''
    encryptedExportMasterPassword = ''
    encryptedExportRedacted = false
    encryptedExportBusy = false
    encryptedExportError = ''
  }

  const submitEncryptedExport = async () => {
    if (!encryptedExportOutputPath) {
      return
    }
    if (encryptedExportPassword.trim().length === 0) {
      encryptedExportError = 'Export password cannot be empty'
      return
    }
    if (encryptedExportPassword !== encryptedExportPasswordConfirm) {
      encryptedExportError = 'Export passwords do not match'
      return
    }
    if (encryptedExportMasterPassword.trim().length === 0) {
      encryptedExportError = 'Master password is required to validate encrypted export'
      return
    }
    if (encryptedExportPassword === encryptedExportMasterPassword) {
      encryptedExportError = 'Export password must differ from the vault master password'
      return
    }

    encryptedExportBusy = true
    encryptedExportError = ''
    try {
      const outputPath = encryptedExportOutputPath
      const count = await npw.exportEncrypted({
        outputPath,
        exportPassword: encryptedExportPassword,
        masterPassword: encryptedExportMasterPassword,
        redacted: encryptedExportRedacted
      })
      lastResult = `Wrote encrypted export with ${count} items to ${outputPath}`
      pushToast({ kind: 'success', title: 'Encrypted export written', detail: lastResult, timeoutMs: 4500 })
      closeEncryptedExport()
    } catch (error) {
      encryptedExportError = formatError(error)
      lastResult = encryptedExportError
      pushToast({ kind: 'error', title: 'Encrypted export failed', detail: encryptedExportError })
    } finally {
      encryptedExportBusy = false
    }
  }

  const addNote = async () => {
    try {
      const id = await npw.noteAdd({
        title: newNoteTitle,
        body: newNoteBody,
        tags: parseTagsRaw(newNoteTagsRaw),
        favorite: newNoteFavorite
      })
      newNoteTitle = ''
      newNoteBody = ''
      newNoteTagsRaw = ''
      newNoteFavorite = false
      await refreshItems()
      const created = items.find((item) => item.id === id)
      if (created) {
        await selectItem(created)
      }
      lastResult = `Created note ${id}`
      pushToast({ kind: 'success', title: 'Created note', timeoutMs: 3500 })
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({ kind: 'error', title: 'Create note failed', detail: message })
    }
  }

  const updateNote = async () => {
    if (!noteDetail) {
      return
    }

    const id = noteDetail.id
    noteEditBusy = true
    noteEditError = ''
    try {
      await npw.noteUpdate({
        id,
        title: noteEditTitle,
        body: noteEditBody,
        tags: parseTagsRaw(noteEditTagsRaw),
        favorite: noteEditFavorite
      })
      await refreshItems()
      const refreshed = items.find((item) => item.id === id)
      if (refreshed) {
        await selectItem(refreshed)
      }
      lastResult = `Updated note ${id}`
      pushToast({ kind: 'success', title: 'Updated note', timeoutMs: 3500 })
    } catch (error) {
      noteEditError = formatError(error)
      lastResult = noteEditError
      pushToast({ kind: 'error', title: 'Update note failed', detail: noteEditError })
    } finally {
      noteEditBusy = false
    }
  }

  const addLogin = async () => {
    try {
      const id = await npw.loginAdd({
        title: newLoginTitle,
        urls: normalizeUrlInputs(newLoginUrls),
        username: newLoginUsername.length > 0 ? newLoginUsername : null,
        password: newLoginPassword,
        notes: newLoginNotes,
        tags: parseTagsRaw(newLoginTagsRaw),
        favorite: newLoginFavorite
      })
      newLoginTitle = ''
      newLoginUrls = [{ url: '', matchType: 'exact' }]
      newLoginUsername = ''
      newLoginPassword = ''
      newLoginNotes = ''
      newLoginTagsRaw = ''
      newLoginFavorite = false
      await refreshItems()
      const created = items.find((item) => item.id === id)
      if (created) {
        await selectItem(created)
      }
      lastResult = `Created login ${id}`
      pushToast({ kind: 'success', title: 'Created login', timeoutMs: 3500 })
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({ kind: 'error', title: 'Create login failed', detail: message })
    }
  }

  const updateLogin = async () => {
    if (!loginDetail) {
      return
    }

    const id = loginDetail.id
    loginEditBusy = true
    loginEditError = ''
    try {
      await npw.loginUpdate({
        id,
        title: loginEditTitle,
        urls: normalizeUrlInputs(loginEditUrls),
        username: loginEditUsername.trim().length > 0 ? loginEditUsername : null,
        notes: loginEditNotes.length > 0 ? loginEditNotes : null,
        tags: parseTagsRaw(loginEditTagsRaw),
        favorite: loginEditFavorite
      })
      await refreshItems()
      const refreshed = items.find((item) => item.id === id)
      if (refreshed) {
        await selectItem(refreshed)
      }
      lastResult = `Updated login ${id}`
      pushToast({ kind: 'success', title: 'Updated login', timeoutMs: 3500 })
    } catch (error) {
      loginEditError = formatError(error)
      lastResult = loginEditError
      pushToast({ kind: 'error', title: 'Update login failed', detail: loginEditError })
    } finally {
      loginEditBusy = false
    }
  }

  const updatePasskeyRef = async () => {
    if (!passkeyDetail) {
      return
    }

    const id = passkeyDetail.id
    passkeyEditBusy = true
    passkeyEditError = ''
    try {
      await npw.passkeyRefUpdate({
        id,
        title: passkeyEditTitle,
        notes: passkeyEditNotes.length > 0 ? passkeyEditNotes : null,
        tags: parseTagsRaw(passkeyEditTagsRaw),
        favorite: passkeyEditFavorite
      })
      await refreshItems()
      const refreshed = items.find((item) => item.id === id)
      if (refreshed) {
        await selectItem(refreshed)
      }
      lastResult = `Updated passkey reference ${id}`
      pushToast({ kind: 'success', title: 'Updated passkey reference', timeoutMs: 3500 })
    } catch (error) {
      passkeyEditError = formatError(error)
      lastResult = passkeyEditError
      pushToast({ kind: 'error', title: 'Update passkey failed', detail: passkeyEditError })
    } finally {
      passkeyEditBusy = false
    }
  }

  const addPasskeyRef = async () => {
    newPasskeyBusy = true
    newPasskeyError = ''
    try {
      const id = await npw.passkeyRefAdd({
        title: newPasskeyTitle,
        rpId: newPasskeyRpId,
        rpName: newPasskeyRpName.trim().length > 0 ? newPasskeyRpName : null,
        userDisplayName: newPasskeyUserDisplayName.trim().length > 0 ? newPasskeyUserDisplayName : null,
        credentialIdHex: newPasskeyCredentialIdHex,
        notes: newPasskeyNotes.trim().length > 0 ? newPasskeyNotes : null,
        tags: parseTagsRaw(newPasskeyTagsRaw),
        favorite: newPasskeyFavorite
      })
      newPasskeyTitle = ''
      newPasskeyRpId = ''
      newPasskeyRpName = ''
      newPasskeyUserDisplayName = ''
      newPasskeyCredentialIdHex = ''
      newPasskeyNotes = ''
      newPasskeyTagsRaw = ''
      newPasskeyFavorite = false
      await refreshItems()
      const created = items.find((item) => item.id === id)
      if (created) {
        await selectItem(created)
      }
      lastResult = `Created passkey reference ${id}`
      pushToast({ kind: 'success', title: 'Created passkey reference', timeoutMs: 3500 })
    } catch (error) {
      newPasskeyError = formatError(error)
      lastResult = newPasskeyError
      pushToast({ kind: 'error', title: 'Create passkey failed', detail: newPasskeyError })
    } finally {
      newPasskeyBusy = false
    }
  }

  const deleteSelectedItem = async () => {
    if (!selectedItem) {
      return
    }
    const confirmed = confirm(`Delete "${selectedItem.title}"?`)
    if (!confirmed) {
      return
    }

    const id = selectedItem.id
    try {
      const deleted = await npw.itemDelete({ id })
      selectedItem = null
      loginDetail = null
      noteDetail = null
      passkeyDetail = null
      totp = null
      clearTotpInterval()
      await refreshItems()
      lastResult = deleted ? `Deleted item ${id}` : `Item not found: ${id}`
      pushToast({ kind: 'info', title: deleted ? 'Deleted item' : 'Item not found', timeoutMs: 3500 })
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({ kind: 'error', title: 'Delete failed', detail: message })
    }
  }

  const selectItem = async (item) => {
    clearRevealedPassword()
    selectedItem = item
    loginDetail = null
    noteDetail = null
    passkeyDetail = null
    totp = null
    totpQrUrl = null
    totpQrVisible = false
    clearTotpInterval()
    if (!item) {
      return
    }
    const itemId = item.id
    try {
      if (item.itemType === 'login') {
        loginDetail = await npw.loginGet({ id: itemId })
        loginEditTitle = loginDetail.title
        loginEditUrls = ensureUrlEditorRows(loginDetail.urls)
        loginEditUsername = loginDetail.username ?? ''
        loginEditNotes = loginDetail.notes ?? ''
        loginEditTagsRaw = formatTagsRaw(loginDetail.tags)
        loginEditFavorite = !!loginDetail.favorite
        loginEditError = ''
        loginEditBusy = false
        lastResult = `Loaded item ${itemId}`
        if (loginDetail.hasTotp) {
          await refreshTotp(itemId)
          totpInterval = setInterval(async () => {
            if (!selectedItem || selectedItem.id !== itemId) {
              clearTotpInterval()
              return
            }
            try {
              if (totp && totp.remaining > 1) {
                totp = { ...totp, remaining: totp.remaining - 1 }
                return
              }
              await refreshTotp(itemId)
            } catch {
              totp = null
              clearTotpInterval()
            }
          }, 1000)
        }
        return
      }

      if (item.itemType === 'note') {
        noteDetail = await npw.noteGet({ id: itemId })
        noteEditTitle = noteDetail.title
        noteEditBody = noteDetail.body
        noteEditTagsRaw = formatTagsRaw(noteDetail.tags)
        noteEditFavorite = !!noteDetail.favorite
        noteEditError = ''
        noteEditBusy = false
        lastResult = `Loaded item ${itemId}`
        return
      }

      if (item.itemType === 'passkey_ref') {
        passkeyDetail = await npw.passkeyRefGet({ id: itemId })
        passkeyEditTitle = passkeyDetail.title
        passkeyEditNotes = passkeyDetail.notes ?? ''
        passkeyEditTagsRaw = formatTagsRaw(passkeyDetail.tags)
        passkeyEditFavorite = !!passkeyDetail.favorite
        passkeyEditError = ''
        passkeyEditBusy = false
        lastResult = `Loaded item ${itemId}`
        return
      }

      lastResult = `Item type ${item.itemType} detail view not implemented yet`
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({ kind: 'error', title: 'Load item failed', detail: message })
    }
  }

  const copyUsername = async () => {
    if (!selectedItem) {
      return
    }
    try {
      await npw.loginCopyUsername({ id: selectedItem.id })
      const timeoutSeconds = Number(settingsClipboardTimeoutSeconds)
      const message =
        Number.isFinite(timeoutSeconds) && timeoutSeconds > 0
          ? `Copied username to clipboard (auto-clears in ${timeoutSeconds}s)`
          : 'Copied username to clipboard (auto-clear disabled)'
      lastResult = message
      pushToast({ kind: 'success', title: message, timeoutMs: 4000 })
    } catch (error) {
      lastResult = formatError(error)
      pushToast({
        kind: 'error',
        title: 'Copy username failed',
        detail: formatError(error),
        retryLabel: 'Retry',
        retry: copyUsername
      })
    }
  }

  const copyPassword = async () => {
    if (!selectedItem) {
      return
    }
    try {
      await npw.loginCopyPassword({ id: selectedItem.id })
      const timeoutSeconds = Number(settingsClipboardTimeoutSeconds)
      const message =
        Number.isFinite(timeoutSeconds) && timeoutSeconds > 0
          ? `Copied password to clipboard (auto-clears in ${timeoutSeconds}s)`
          : 'Copied password to clipboard (auto-clear disabled)'
      lastResult = message
      pushToast({ kind: 'success', title: message, timeoutMs: 4000 })
    } catch (error) {
      lastResult = formatError(error)
      pushToast({
        kind: 'error',
        title: 'Copy password failed',
        detail: formatError(error),
        retryLabel: 'Retry',
        retry: copyPassword
      })
    }
  }

  const revealPassword = async () => {
    if (!selectedItem) {
      return
    }
    if (settingsRevealRequiresConfirm) {
      const confirmed = confirm('Reveal password for 30 seconds?')
      if (!confirmed) {
        return
      }
    }
    try {
      const password = await npw.loginRevealPassword({ id: selectedItem.id })
      clearRevealedPassword()
      revealedPassword = password
      revealPasswordTimeoutId = setTimeout(() => {
        revealedPassword = null
        revealPasswordTimeoutId = null
      }, 30_000)
      lastResult = 'Password revealed for 30 seconds'
      pushToast({ kind: 'info', title: 'Password revealed for 30 seconds', timeoutMs: 4000 })
    } catch (error) {
      lastResult = formatError(error)
      pushToast({
        kind: 'error',
        title: 'Reveal password failed',
        detail: formatError(error),
        retryLabel: 'Retry',
        retry: revealPassword
      })
    }
  }

  const hidePassword = () => {
    clearRevealedPassword()
  }

  const generateReplacePassword = async () => {
    if (!selectedItem) {
      return
    }
    const confirmed = confirm('Generate a new password and replace the current one?')
    if (!confirmed) {
      return
    }
    try {
      clearRevealedPassword()
      const mode = await npw.loginGenerateReplacePassword({ id: selectedItem.id })
      lastResult = `Generated new ${mode} password and replaced`
      pushToast({ kind: 'success', title: 'Generated and replaced password', timeoutMs: 3500 })
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({ kind: 'error', title: 'Generate and replace failed', detail: message })
    }
  }

  const copyTotp = async () => {
    if (!selectedItem) {
      return
    }
    try {
      await npw.loginCopyTotp({ id: selectedItem.id })
      const timeoutSeconds = Number(settingsClipboardTimeoutSeconds)
      const message =
        Number.isFinite(timeoutSeconds) && timeoutSeconds > 0
          ? `Copied TOTP to clipboard (auto-clears in ${timeoutSeconds}s)`
          : 'Copied TOTP to clipboard (auto-clear disabled)'
      lastResult = message
      pushToast({ kind: 'success', title: message, timeoutMs: 4000 })
    } catch (error) {
      lastResult = formatError(error)
      pushToast({
        kind: 'error',
        title: 'Copy TOTP failed',
        detail: formatError(error),
        retryLabel: 'Retry',
        retry: copyTotp
      })
    }
  }

  const refreshTotp = async (id) => {
    totp = await npw.loginTotpGet({ id })
  }

  const toggleTotpQr = async () => {
    if (!selectedItem) {
      return
    }
    if (totpQrVisible) {
      totpQrVisible = false
      return
    }

    try {
      const svg = await npw.loginTotpQrSvg({ id: selectedItem.id })
      totpQrUrl = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`
      totpQrVisible = true
      lastResult = 'Rendered TOTP QR code'
      pushToast({ kind: 'info', title: 'Rendered TOTP QR code', timeoutMs: 3500 })
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({
        kind: 'error',
        title: 'Export QR failed',
        detail: message,
        retryLabel: 'Retry',
        retry: toggleTotpQr
      })
    }
  }

  const openTotpImport = () => {
    if (!selectedItem) {
      return
    }
    totpImportVisible = true
    totpImportValue = ''
    totpImportError = ''
    totpImportBusy = false
    stopTotpImportCamera()
  }

  const closeTotpImport = () => {
    stopTotpImportCamera()
    totpImportVisible = false
    totpImportValue = ''
    totpImportError = ''
    totpImportBusy = false
  }

  const stopTotpImportCamera = () => {
    if (totpImportFrameId) {
      cancelAnimationFrame(totpImportFrameId)
      totpImportFrameId = null
    }
    if (totpImportStream) {
      for (const track of totpImportStream.getTracks()) {
        track.stop()
      }
      totpImportStream = null
    }
    if (totpImportVideo) {
      totpImportVideo.srcObject = null
    }
    if (totpImportCanvas) {
      totpImportCanvas.width = 0
      totpImportCanvas.height = 0
    }
    totpImportCanvas = null
    totpImportContext = null
  }

  const scanTotpImportFrame = () => {
    if (!totpImportStream || !totpImportVideo || !totpImportContext || !totpImportCanvas) {
      return
    }

    const width = totpImportVideo.videoWidth
    const height = totpImportVideo.videoHeight
    if (!width || !height) {
      totpImportFrameId = requestAnimationFrame(scanTotpImportFrame)
      return
    }

    totpImportCanvas.width = width
    totpImportCanvas.height = height
    totpImportContext.drawImage(totpImportVideo, 0, 0, width, height)
    const imageData = totpImportContext.getImageData(0, 0, width, height)
    const decoded = jsQR(imageData.data, imageData.width, imageData.height)
    if (decoded?.data) {
      totpImportValue = decoded.data
      pushToast({ kind: 'success', title: 'Scanned QR code', timeoutMs: 3500 })
      stopTotpImportCamera()
      return
    }

    totpImportFrameId = requestAnimationFrame(scanTotpImportFrame)
  }

  const startTotpImportCamera = async () => {
    totpImportError = ''
    stopTotpImportCamera()
    try {
      if (!navigator.mediaDevices?.getUserMedia) {
        throw new Error('Camera is not supported in this environment.')
      }
      totpImportStream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: { facingMode: 'environment' }
      })
      if (!totpImportVideo) {
        throw new Error('Camera preview is not ready.')
      }
      totpImportVideo.srcObject = totpImportStream
      await totpImportVideo.play()
      totpImportCanvas = document.createElement('canvas')
      totpImportContext = totpImportCanvas.getContext('2d', { willReadFrequently: true })
      if (!totpImportContext) {
        throw new Error('Unable to initialize camera frame reader.')
      }
      scanTotpImportFrame()
    } catch (error) {
      totpImportError = formatError(error)
      stopTotpImportCamera()
    }
  }

  const submitTotpImport = async () => {
    if (!selectedItem) {
      return
    }
    const value = totpImportValue.trim()
    if (value.length === 0) {
      totpImportError = 'Paste an otpauth:// URI or base32 secret, or scan a QR code.'
      return
    }

    const id = selectedItem.id
    totpImportBusy = true
    totpImportError = ''
    stopTotpImportCamera()
    try {
      await npw.loginTotpSet({ id, value })
      await refreshItems()
      const refreshed = items.find((item) => item.id === id)
      if (refreshed) {
        await selectItem(refreshed)
      }
      totpImportVisible = false
      totpImportValue = ''
      pushToast({ kind: 'success', title: 'Imported TOTP', timeoutMs: 3500 })
    } catch (error) {
      totpImportError = formatError(error)
      pushToast({ kind: 'error', title: 'TOTP import failed', detail: totpImportError })
    } finally {
      totpImportBusy = false
    }
  }

  const openPasskeySite = async () => {
    if (!selectedItem) {
      return
    }
    try {
      await npw.passkeyOpenSite({ id: selectedItem.id })
      lastResult = 'Opened relying party site'
      pushToast({ kind: 'info', title: 'Opened relying party site', timeoutMs: 3500 })
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({
        kind: 'error',
        title: 'Open site failed',
        detail: message,
        retryLabel: 'Retry',
        retry: openPasskeySite
      })
    }
  }

  const openPasskeyManager = async () => {
    try {
      await npw.passkeyOpenManager()
      lastResult = 'Opened OS passkey manager'
      pushToast({ kind: 'info', title: 'Opened OS passkey manager', timeoutMs: 3500 })
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({
        kind: 'error',
        title: 'Open passkey manager failed',
        detail: message,
        retryLabel: 'Retry',
        retry: openPasskeyManager
      })
    }
  }

  const clearTotpInterval = () => {
    if (totpInterval) {
      clearInterval(totpInterval)
      totpInterval = null
    }
  }

  const formatError = (error) => {
    if (error instanceof Error) {
      return error.message
    }
    return String(error)
  }
</script>

<main class="app">
  {#if toasts.length > 0}
    <div class="toast-host" aria-live="polite">
      {#each toasts as toast (toast.id)}
        <div class="toast" data-kind={toast.kind}>
          <div class="toast-header">
            <strong>{toast.title}</strong>
            <button
              class="toast-close secondary"
              type="button"
              on:click={() => dismissToast(toast.id)}
              aria-label="Dismiss"
            >
              ×
            </button>
          </div>
          {#if toast.detail}
            <details>
              <summary>Details</summary>
              <pre class="toast-detail">{toast.detail}</pre>
            </details>
          {/if}
          {#if toast.retry}
            <div class="toast-actions">
              <button type="button" on:click={() => toast.retry()}>
                {toast.retryLabel ?? 'Retry'}
              </button>
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}

  <header class="topbar">
    <div class="wordmark">
      <span class="mark" aria-hidden="true"></span>
      <div>
        <h1>{APP_TITLE}</h1>
        <p class="subhead">{bridgeStatus}</p>
      </div>
    </div>
    <div class="topbar-meta">
      <span class="chip" data-tone={bridgeAvailable ? 'ok' : 'warn'}>
        {bridgeAvailable ? 'Bridge ready' : 'Electron required'}
      </span>
      {#if status}
        <span class="chip" data-tone="neutral">{status.label} · {status.itemCount} items</span>
      {:else}
        <span class="chip" data-tone="neutral">Locked</span>
      {/if}
    </div>
  </header>

  <div class="layout">
    <aside class="sidebar">

  <section class="picker">
    <h2>Recent Vaults</h2>
    {#if recents.length === 0}
      <p class="muted">No recent vaults yet.</p>
    {:else}
      <ul class="recent-list">
        {#each recents as vault (vault.path)}
          <li class="recent">
            <div class="recent-meta">
              <strong>{vault.label || '(unlabeled)'}</strong>
              <span class="muted">{vault.path}</span>
            </div>
            <div class="actions">
              <button type="button" on:click={() => openRecent(vault)}>Use</button>
              <button class="quiet-destructive" type="button" on:click={() => removeRecent(vault)}>Remove</button>
            </div>
          </li>
        {/each}
      </ul>
    {/if}
    <div class="actions">
      <button type="button" on:click={pickCreateVault} disabled={!bridgeAvailable}>Create New Vault…</button>
      <button type="button" on:click={pickOpenVault} disabled={!bridgeAvailable}>Open Existing Vault…</button>
    </div>
  </section>

  <section class="settings">
    <h2>Settings</h2>
    {#if appConfig?.configPath}
      <p class="muted">Config path: <span class="mono">{appConfig.configPath}</span></p>
    {/if}

    <label>
      Auto-lock minutes
      <input type="number" min="1" max="60" step="1" bind:value={settingsAutoLockMinutes} />
    </label>

    <label>
      Lock on suspend / lock screen
      <input type="checkbox" bind:checked={settingsLockOnSuspend} />
    </label>

    <label>
      Clipboard timeout (seconds)
      <input type="number" min="0" max="90" step="1" bind:value={settingsClipboardTimeoutSeconds} />
    </label>

    {#if Number(settingsClipboardTimeoutSeconds) === 0}
      <p class="callout">Warning: clipboard auto-clear is disabled.</p>
    {/if}

    <label>
      Reveal requires confirmation
      <input type="checkbox" bind:checked={settingsRevealRequiresConfirm} />
    </label>

    <label>
      Log level
      <select bind:value={settingsLogLevel}>
        <option value="error">error</option>
        <option value="warn">warn</option>
        <option value="info">info</option>
        <option value="debug">debug</option>
      </select>
    </label>

    {#if settingsError}
      <p class="callout">{settingsError}</p>
    {/if}

    <div class="actions">
      <button type="button" on:click={saveSettings} disabled={settingsSaving || !bridgeAvailable}>
        {settingsSaving ? 'Saving…' : 'Save Settings'}
      </button>
      <button class="secondary" type="button" on:click={refreshConfig} disabled={settingsSaving || !bridgeAvailable}>
        Reload
      </button>
    </div>
	  </section>

	  <section class="vault">
	    <h2>Vault</h2>

	    <label>
	      Vault path
	      <input bind:value={vaultPath} on:blur={refreshQuickUnlockForPath} />
	    </label>

	    <label>
	      Vault label
	      <input bind:value={vaultLabel} />
	    </label>

	    <label>
	      Master password
	      <input bind:value={masterPassword} type="password" />
	    </label>

	    <div class="actions">
	      <button on:click={createVault} disabled={!bridgeAvailable}>Create Vault</button>
	      <button on:click={unlockVault} disabled={!bridgeAvailable}>Unlock Vault</button>
	      {#if !status && quickUnlockForPath.configured}
	        <button
	          class="secondary"
	          type="button"
	          on:click={quickUnlockVault}
	          disabled={!bridgeAvailable || quickUnlockBusy || !quickUnlockForPath.available || !quickUnlockForPath.enabled}
	        >
	          Quick Unlock
	        </button>
	      {/if}
	      <button class="secondary" on:click={lockVault} disabled={!bridgeAvailable || !status}>Lock Vault</button>
	    </div>

	    {#if !status && quickUnlockForPath.error}
	      <p class="callout">{quickUnlockForPath.error}</p>
	    {/if}
	  </section>

	  {#if status}
	    <details class="quick-unlock fold">
	      <summary>
	        <span>Quick Unlock</span>
	        <span class="summary-meta">
	          {#if quickUnlockForCurrent.error}
	            Error
	          {:else if !quickUnlockForCurrent.available}
	            Unavailable
	          {:else if quickUnlockForCurrent.enabled}
	            Enabled
	          {:else}
	            Disabled
	          {/if}
	        </span>
	      </summary>
	      <div class="fold-body">
	        <p class="muted">
	          Store key material in your OS keychain so this vault can be unlocked without the master password.
	        </p>
	        <label class="inline">
	          <input
	            type="checkbox"
	            checked={quickUnlockForCurrent.enabled}
	            on:change={(event) => setQuickUnlockEnabled(event.currentTarget.checked)}
	            disabled={quickUnlockBusy || !quickUnlockForCurrent.available}
	          />
	          Enable Quick Unlock for this vault
	        </label>
	        {#if quickUnlockForCurrent.error}
	          <p class="callout">{quickUnlockForCurrent.error}</p>
	        {:else if !quickUnlockForCurrent.available}
	          <p class="callout">Quick Unlock is unavailable on this system.</p>
	        {/if}
	      </div>
	    </details>
	  {/if}

	    </aside>

    <section class="workspace">
      <label class="search">
        <span class="label">Search</span>
        <input
          bind:value={query}
          on:input={refreshItems}
          disabled={!status}
          placeholder="Search titles, usernames, tags…"
        />
      </label>

      <div class="workspace-grid">
	        <div class="workspace-left">
	          {#if status}
	            <section class="items">
	              <div class="card-head">
	                <h2>Items</h2>
	                <button class="ghost" type="button" on:click={refreshItems} disabled={!status}>Refresh</button>
	              </div>
	              <div class="filters">
	                <label>
	                  Type
	                  <select bind:value={filterType}>
                    <option value="all">All</option>
                    <option value="login">Logins</option>
                    <option value="note">Notes</option>
                    <option value="passkey_ref">Passkey refs</option>
                  </select>
                </label>
                <label class="inline">
                  <input type="checkbox" bind:checked={filterFavoritesOnly} />
                  Favorites only
                </label>
                <label>
                  Tag
                  <input bind:value={filterTag} list="tag-suggestions" placeholder="work" />
                </label>
                <datalist id="tag-suggestions">
                  {#each availableTags as tag (tag)}
                    <option value={tag}></option>
                  {/each}
                </datalist>
              </div>

              {#if itemsView.length === 0}
                <p class="muted">No items found.</p>
              {:else}
                <ul class="item-list">
                  {#each itemsView as item (item.id)}
                    <li class:selected={selectedItem?.id === item.id}>
                      <button class="row" type="button" on:click={() => selectItem(item)}>
                        <strong>{item.title}</strong>
                        <span class="meta">
                          <span class="type-badge">{item.itemType}</span>
                          {#if item.favorite}
                            · ★
                          {/if}
                          {#if item.subtitle}
                            · {item.subtitle}
                          {/if}
                          {#if item.url}
                            · {item.url}
                          {/if}
                          {#if item.tags && item.tags.length > 0}
                            · {item.tags.slice(0, 3).join(', ')}
                          {/if}
                          {#if item.hasTotp}
                            · TOTP
                          {/if}
                        </span>
                      </button>
                    </li>
                  {/each}
                </ul>
              {/if}
            </section>
          {/if}
        </div>

        <div class="workspace-right">
  {#if status}
    <details class="import-export fold">
      <summary>
        <span>Import / Export</span>
        <span class="summary-meta">CSV, Bitwarden JSON, encrypted export</span>
      </summary>
      <div class="fold-body">
        <div class="import-export-grid">
        <div class="import-panel">
          <h3>Import</h3>
          <p class="muted">Imports are previewed first. Suspected duplicates require a decision per item.</p>
          <div class="actions">
            <button type="button" on:click={startImportCsv} disabled={importBusy}>Import CSV…</button>
            <button type="button" on:click={startImportBitwarden} disabled={importBusy}>Import Bitwarden JSON…</button>
          </div>

          {#if importPreview}
            <div class="import-preview">
              <p class="muted">
                Preview loaded ({importPreview.importType}) from <span class="mono">{importInputPath}</span>
              </p>
              <p class="muted">
                {importPreview.candidates} candidates · {importPreview.duplicates.length} duplicates
              </p>

              {#if importPreview.warnings && importPreview.warnings.length > 0}
                <details>
                  <summary>Warnings ({importPreview.warnings.length})</summary>
                  <ul class="plain-list">
                    {#each importPreview.warnings as warning, index (index)}
                      <li class="muted">{warning}</li>
                    {/each}
                  </ul>
                </details>
              {/if}

              {#if importPreview.duplicates && importPreview.duplicates.length > 0}
                <div class="duplicate-list" role="list">
                  {#each importPreview.duplicates as dup (dup.sourceIndex)}
                    <div class="duplicate" role="listitem">
                      <div class="duplicate-meta">
                        <strong>{dup.title}</strong>
                        <div class="muted">
                          Imported: {dup.itemType}
                          {#if dup.username}
                            · {dup.username}
                          {/if}
                          {#if dup.primaryUrl}
                            · {dup.primaryUrl}
                          {/if}
                        </div>
                        <div class="muted">
                          Existing: <span class="mono">{dup.existingId.slice(0, 8)}</span> · {dup.existingTitle}
                          {#if dup.existingUsername}
                            · {dup.existingUsername}
                          {/if}
                          {#if dup.existingPrimaryUrl}
                            · {dup.existingPrimaryUrl}
                          {/if}
                        </div>
                      </div>
                      <div class="duplicate-actions">
                        <label class="inline">
                          <input
                            type="radio"
                            name={`dup-${dup.sourceIndex}`}
                            value="skip"
                            checked={(importDecisions[dup.sourceIndex] ?? 'skip') === 'skip'}
                            on:change={() => setImportDecision(dup.sourceIndex, 'skip')}
                            disabled={importBusy}
                          />
                          Skip
                        </label>
                        <label class="inline">
                          <input
                            type="radio"
                            name={`dup-${dup.sourceIndex}`}
                            value="overwrite"
                            checked={(importDecisions[dup.sourceIndex] ?? 'skip') === 'overwrite'}
                            on:change={() => setImportDecision(dup.sourceIndex, 'overwrite')}
                            disabled={importBusy}
                          />
                          Overwrite
                        </label>
                        <label class="inline">
                          <input
                            type="radio"
                            name={`dup-${dup.sourceIndex}`}
                            value="keep_both"
                            checked={(importDecisions[dup.sourceIndex] ?? 'skip') === 'keep_both'}
                            on:change={() => setImportDecision(dup.sourceIndex, 'keep_both')}
                            disabled={importBusy}
                          />
                          Keep both
                        </label>
                      </div>
                    </div>
                  {/each}
                </div>
              {:else}
                <p class="muted">No suspected duplicates found.</p>
              {/if}

              {#if importError}
                <p class="callout">{importError}</p>
              {/if}

              <div class="actions">
                <button type="button" on:click={applyImport} disabled={importBusy}>
                  {importBusy ? 'Importing…' : 'Apply Import'}
                </button>
                <button class="secondary" type="button" on:click={clearImportState} disabled={importBusy}>Clear Preview</button>
              </div>
            </div>
          {/if}
        </div>

        <div class="export-panel">
          <h3>Export</h3>
          <p class="muted">
            Redacted exports exclude passwords and note bodies. Plaintext exports require explicit confirmation.
          </p>
          <div class="actions">
            <button type="button" on:click={() => exportCsv({ includeSecrets: false })}>Export CSV (redacted)…</button>
            <button type="button" on:click={() => exportCsv({ includeSecrets: true })}>Export CSV (plaintext)…</button>
            <button type="button" on:click={() => exportJson({ includeSecrets: false })}>Export JSON (redacted)…</button>
            <button type="button" on:click={() => exportJson({ includeSecrets: true })}>Export JSON (plaintext)…</button>
            <button type="button" on:click={openEncryptedExport}>Encrypted Export…</button>
          </div>
        </div>
      </div>
      </div>
    </details>
  {/if}

  {#if status}
    <section class="add-login">
      <h2>Add Login</h2>
      <label>
        Title
        <input bind:value={newLoginTitle} />
      </label>
      <div class="field">
        <div class="label">URLs</div>
        <div class="url-editor">
          {#each newLoginUrls as entry, index (index)}
            <div class="inline">
              <select bind:value={entry.matchType}>
                <option value="exact">Exact</option>
                <option value="domain">Domain</option>
                <option value="subdomain">Subdomain</option>
              </select>
              <input bind:value={entry.url} placeholder="https://example.com" />
              <button
                class="quiet-destructive"
                type="button"
                disabled={newLoginUrls.length === 1}
                on:click={() => {
                  const next = newLoginUrls.filter((_entry, i) => i !== index)
                  newLoginUrls = next.length > 0 ? next : [{ url: '', matchType: 'exact' }]
                }}
              >
                Remove
              </button>
            </div>
          {/each}
          <div class="actions">
            <button
              class="secondary"
              type="button"
              on:click={() => (newLoginUrls = [...newLoginUrls, { url: '', matchType: 'exact' }])}
            >
              Add URL
            </button>
          </div>
        </div>
      </div>
      <label>
        Username
        <input bind:value={newLoginUsername} />
      </label>
      <label>
        Password
        <input bind:value={newLoginPassword} type="password" />
      </label>
      <label>
        Notes
        <textarea bind:value={newLoginNotes} rows="4"></textarea>
      </label>
      <label>
        Tags (semicolon separated)
        <input bind:value={newLoginTagsRaw} placeholder="work; personal" />
      </label>
      <label class="inline">
        <input type="checkbox" bind:checked={newLoginFavorite} />
        Favorite
      </label>
      <div class="actions">
        <button on:click={addLogin} disabled={newLoginTitle.trim().length === 0}>Save Login</button>
      </div>
    </section>
  {/if}

  {#if status}
    <details class="add-note fold">
      <summary>
        <span>Add Note</span>
        <span class="summary-meta">Encrypted body</span>
      </summary>
      <div class="fold-body">
      <label>
        Title
        <input bind:value={newNoteTitle} />
      </label>
      <label>
        Body
        <textarea bind:value={newNoteBody} rows="4"></textarea>
      </label>
      <label>
        Tags (semicolon separated)
        <input bind:value={newNoteTagsRaw} placeholder="work; personal" />
      </label>
      <label class="inline">
        <input type="checkbox" bind:checked={newNoteFavorite} />
        Favorite
      </label>
      <div class="actions">
        <button on:click={addNote} disabled={newNoteTitle.trim().length === 0}>Save Note</button>
      </div>
      </div>
    </details>
  {/if}

  {#if status}
    <details class="add-passkey fold">
      <summary>
        <span>Add Passkey Reference</span>
        <span class="summary-meta">No passkeys stored</span>
      </summary>
      <div class="fold-body">
        <p class="muted">This is a reference entry only. npw does not store passkeys.</p>
      <label>
        Title
        <input bind:value={newPasskeyTitle} disabled={newPasskeyBusy} />
      </label>
      <label>
        Relying Party ID
        <input bind:value={newPasskeyRpId} placeholder="github.com" disabled={newPasskeyBusy} />
      </label>
      <label>
        Relying Party Name (optional)
        <input bind:value={newPasskeyRpName} disabled={newPasskeyBusy} />
      </label>
      <label>
        User Display Name (optional)
        <input bind:value={newPasskeyUserDisplayName} disabled={newPasskeyBusy} />
      </label>
      <label>
        Credential ID (hex)
        <input bind:value={newPasskeyCredentialIdHex} placeholder="0123abcd..." disabled={newPasskeyBusy} />
      </label>
      <label>
        Notes
        <textarea bind:value={newPasskeyNotes} rows="4" disabled={newPasskeyBusy}></textarea>
      </label>
      <label>
        Tags (semicolon separated)
        <input bind:value={newPasskeyTagsRaw} placeholder="work; personal" disabled={newPasskeyBusy} />
      </label>
      <label class="inline">
        <input type="checkbox" bind:checked={newPasskeyFavorite} disabled={newPasskeyBusy} />
        Favorite
      </label>
      {#if newPasskeyError}
        <p class="callout">{newPasskeyError}</p>
      {/if}
      <div class="actions">
        <button
          on:click={addPasskeyRef}
          disabled={
            newPasskeyBusy ||
            newPasskeyTitle.trim().length === 0 ||
            newPasskeyRpId.trim().length === 0 ||
            newPasskeyCredentialIdHex.trim().length === 0
          }
        >
          {newPasskeyBusy ? 'Saving…' : 'Save Passkey Reference'}
        </button>
      </div>
      </div>
    </details>
  {/if}

  <pre class="result">{lastResult}</pre>

  {#if status}
    <details class="debug fold">
      <summary>
        <span>Debug status</span>
        <span class="summary-meta">Session snapshot</span>
      </summary>
      <div class="fold-body">
        <pre class="note mono">{JSON.stringify(status, null, 2)}</pre>
      </div>
    </details>
  {/if}

  {#if status && selectedItem && loginDetail}
    <section class="detail">
      <h2>Login</h2>
      <p class="muted">{loginDetail.id}</p>
      <div class="actions">
        <button type="button" on:click={updateLogin} disabled={loginEditBusy || loginEditTitle.trim().length === 0}>
          {loginEditBusy ? 'Saving…' : 'Save'}
        </button>
        <button class="destructive" on:click={deleteSelectedItem}>Delete</button>
      </div>

      <label>
        Title
        <input bind:value={loginEditTitle} disabled={loginEditBusy} />
      </label>

      <label>
        Username
        <div class="inline">
          <input bind:value={loginEditUsername} disabled={loginEditBusy} />
          <button on:click={copyUsername} disabled={!loginDetail.username}>Copy</button>
        </div>
      </label>

      <div class="field">
        <div class="label">Password</div>
        <div class="inline">
          <span class:mono={revealedPassword != null}>
            {#if revealedPassword != null}
              {revealedPassword}
            {:else}
              {loginDetail.hasPassword ? '••••••••' : '(none)'}
            {/if}
          </span>
          <button on:click={copyPassword} disabled={!loginDetail.hasPassword}>Copy</button>
          {#if loginDetail.hasPassword}
            {#if revealedPassword != null}
              <button class="secondary" type="button" on:click={hidePassword}>Hide</button>
            {:else}
              <button class="secondary" type="button" on:click={revealPassword}>Reveal</button>
            {/if}
          {/if}
          <button class="secondary" type="button" on:click={generateReplacePassword}>Generate &amp; Replace</button>
        </div>
      </div>

      <div class="field">
        <div class="label">TOTP</div>
        {#if loginDetail.hasTotp}
          {#if totp}
            <div class="inline">
              <span class="totp">{totp.code}</span>
              <span class="muted">{totp.remaining}s</span>
              <button on:click={copyTotp}>Copy</button>
              <button on:click={toggleTotpQr}>{totpQrVisible ? 'Hide QR' : 'Export QR'}</button>
            </div>
            {#if totpQrVisible && totpQrUrl}
              <div class="qr">
                <img class="qr-img" src={totpQrUrl} alt="TOTP QR" />
              </div>
            {/if}
          {:else}
            <div class="muted">(loading...)</div>
          {/if}
        {:else}
          <div class="inline">
            <span class="muted">(none)</span>
            <button class="secondary" type="button" on:click={openTotpImport}>Import QR / Paste</button>
          </div>
        {/if}
      </div>

      <div class="field">
        <div class="label">URLs</div>
        <div class="url-editor">
          {#each loginEditUrls as entry, index (index)}
            <div class="inline">
              <select bind:value={entry.matchType} disabled={loginEditBusy}>
                <option value="exact">Exact</option>
                <option value="domain">Domain</option>
                <option value="subdomain">Subdomain</option>
              </select>
              <input bind:value={entry.url} placeholder="https://example.com" disabled={loginEditBusy} />
              <button
                class="quiet-destructive"
                type="button"
                disabled={loginEditBusy || loginEditUrls.length === 1}
                on:click={() => {
                  const next = loginEditUrls.filter((_entry, i) => i !== index)
                  loginEditUrls = next.length > 0 ? next : [{ url: '', matchType: 'exact' }]
                }}
              >
                Remove
              </button>
            </div>
          {/each}
          <div class="actions">
            <button
              class="secondary"
              type="button"
              disabled={loginEditBusy}
              on:click={() => (loginEditUrls = [...loginEditUrls, { url: '', matchType: 'exact' }])}
            >
              Add URL
            </button>
          </div>
        </div>
      </div>

      <label>
        Notes
        <textarea bind:value={loginEditNotes} rows="6" disabled={loginEditBusy}></textarea>
      </label>

      <label>
        Tags (semicolon separated)
        <input bind:value={loginEditTagsRaw} placeholder="work; personal" disabled={loginEditBusy} />
      </label>

      <label class="inline">
        <input type="checkbox" bind:checked={loginEditFavorite} disabled={loginEditBusy} />
        Favorite
      </label>

      {#if loginEditError}
        <p class="callout">{loginEditError}</p>
      {/if}
    </section>
  {/if}

  {#if status && selectedItem && noteDetail}
    <section class="detail">
      <h2>Note</h2>
      <p class="muted">{noteDetail.id}</p>
      <div class="actions">
        <button type="button" on:click={updateNote} disabled={noteEditBusy || noteEditTitle.trim().length === 0}>
          {noteEditBusy ? 'Saving…' : 'Save'}
        </button>
        <button class="destructive" on:click={deleteSelectedItem}>Delete</button>
      </div>

      <label>
        Title
        <input bind:value={noteEditTitle} disabled={noteEditBusy} />
      </label>

      <label>
        Body
        <textarea bind:value={noteEditBody} rows="10" disabled={noteEditBusy}></textarea>
      </label>

      <label>
        Tags (semicolon separated)
        <input bind:value={noteEditTagsRaw} placeholder="work; personal" disabled={noteEditBusy} />
      </label>

      <label class="inline">
        <input type="checkbox" bind:checked={noteEditFavorite} disabled={noteEditBusy} />
        Favorite
      </label>

      {#if noteEditError}
        <p class="callout">{noteEditError}</p>
      {/if}
    </section>
  {/if}

  {#if status && selectedItem && passkeyDetail}
    <section class="detail">
      <h2>Passkey Reference</h2>
      <p class="muted">{passkeyDetail.id}</p>
      <p class="callout">This app does not store passkeys. This is a reference entry.</p>
      <div class="actions">
        <button
          type="button"
          on:click={updatePasskeyRef}
          disabled={passkeyEditBusy || passkeyEditTitle.trim().length === 0}
        >
          {passkeyEditBusy ? 'Saving…' : 'Save'}
        </button>
        <button on:click={openPasskeySite}>Open Site</button>
        <button on:click={openPasskeyManager}>Open Passkey Manager</button>
        <button class="destructive" on:click={deleteSelectedItem}>Delete</button>
      </div>

      <label>
        Title
        <input bind:value={passkeyEditTitle} disabled={passkeyEditBusy} />
      </label>

      <div class="field">
        <div class="label">Relying Party ID</div>
        <div>{passkeyDetail.rpId}</div>
      </div>

      {#if passkeyDetail.rpName}
        <div class="field">
          <div class="label">Relying Party Name</div>
          <div>{passkeyDetail.rpName}</div>
        </div>
      {/if}

      {#if passkeyDetail.userDisplayName}
        <div class="field">
          <div class="label">User</div>
          <div>{passkeyDetail.userDisplayName}</div>
        </div>
      {/if}

      <div class="field">
        <div class="label">Credential ID (hex)</div>
        <pre class="note mono">{passkeyDetail.credentialIdHex}</pre>
      </div>

      <label>
        Notes
        <textarea bind:value={passkeyEditNotes} rows="6" disabled={passkeyEditBusy}></textarea>
      </label>

      <label>
        Tags (semicolon separated)
        <input bind:value={passkeyEditTagsRaw} placeholder="work; personal" disabled={passkeyEditBusy} />
      </label>

      <label class="inline">
        <input type="checkbox" bind:checked={passkeyEditFavorite} disabled={passkeyEditBusy} />
        Favorite
      </label>

      {#if passkeyEditError}
        <p class="callout">{passkeyEditError}</p>
      {/if}
    </section>
  {/if}

        </div>
      </div>
    </section>
  </div>

  {#if totpImportVisible}
    <div class="modal-backdrop">
      <dialog class="modal" open aria-labelledby="totp-import-title">
        <h2 id="totp-import-title">Import TOTP</h2>
        <p class="muted">
          Scan a QR code or paste an <span class="mono">otpauth://</span> URI or base32 secret. Camera access is used
          only on this screen.
        </p>

        <div class="totp-import">
          <div class="totp-import-preview">
            <video class="camera" bind:this={totpImportVideo} autoplay playsinline muted></video>
            {#if !totpImportStream}
              <p class="muted">Camera is off.</p>
            {/if}
            <div class="actions">
              <button type="button" on:click={startTotpImportCamera} disabled={totpImportBusy || totpImportStream}>
                {totpImportStream ? 'Camera On' : 'Start Camera'}
              </button>
              <button
                class="secondary"
                type="button"
                on:click={stopTotpImportCamera}
                disabled={totpImportBusy || !totpImportStream}
              >
                Stop Camera
              </button>
            </div>
          </div>

          <label>
            otpauth:// URI or base32 secret
            <textarea bind:value={totpImportValue} rows="3" disabled={totpImportBusy}></textarea>
          </label>
        </div>

        {#if totpImportError}
          <p class="callout">{totpImportError}</p>
        {/if}

        <div class="actions">
          <button class="secondary" type="button" on:click={closeTotpImport} disabled={totpImportBusy}>Cancel</button>
          <button
            type="button"
            on:click={submitTotpImport}
            disabled={totpImportBusy || totpImportValue.trim().length === 0}
          >
            {totpImportBusy ? 'Importing…' : 'Import TOTP'}
          </button>
        </div>
      </dialog>
    </div>
  {/if}

  {#if encryptedExportVisible}
    <div class="modal-backdrop">
      <dialog class="modal" open aria-labelledby="encrypted-export-title">
        <h2 id="encrypted-export-title">Encrypted Export</h2>
        <p class="muted">
          Writes a portable <span class="mono">.npw</span> export protected by a new export password. The export password
          MUST differ from the vault master password.
        </p>
        <p class="muted">
          Output path: <span class="mono">{encryptedExportOutputPath}</span>
        </p>

        <label>
          Export password
          <input type="password" bind:value={encryptedExportPassword} disabled={encryptedExportBusy} />
        </label>

        <label>
          Confirm export password
          <input type="password" bind:value={encryptedExportPasswordConfirm} disabled={encryptedExportBusy} />
        </label>

        <label>
          Master password (verification)
          <input type="password" bind:value={encryptedExportMasterPassword} disabled={encryptedExportBusy} />
        </label>

        <label class="inline">
          <input type="checkbox" bind:checked={encryptedExportRedacted} disabled={encryptedExportBusy} />
          Redacted export (exclude secrets)
        </label>

        {#if encryptedExportError}
          <p class="callout">{encryptedExportError}</p>
        {/if}

        <div class="actions">
          <button class="secondary" type="button" on:click={closeEncryptedExport} disabled={encryptedExportBusy}>
            Cancel
          </button>
          <button type="button" on:click={submitEncryptedExport} disabled={encryptedExportBusy}>
            {encryptedExportBusy ? 'Working…' : 'Write Encrypted Export'}
          </button>
        </div>
      </dialog>
    </div>
  {/if}

  {#if recoveryVisible}
    <div class="modal-backdrop">
      <dialog class="modal" open aria-labelledby="recovery-title">
        <h2 id="recovery-title">Recovery Wizard</h2>
        <p class="muted">
          Restore an encrypted backup to recover from a corrupted vault file. Restoring will overwrite the vault file and
          preserve the current file as <span class="mono">.corrupt</span>.
        </p>

        {#if recoveryBackups.length === 0}
          <p class="muted">No backups found.</p>
        {:else}
          <div class="backup-list" role="list">
            {#each recoveryBackups as backup (backup.path)}
              <label class="backup-row" role="listitem">
                <input
                  type="radio"
                  name="recovery-backup"
                  value={backup.path}
                  bind:group={recoverySelectedBackupPath}
                  disabled={recoveryBusy}
                />
                <div class="backup-meta">
                  <strong>{backup.label || '(unlabeled)'}</strong>
                  <span class="muted">
                    {backup.itemCount} items · {formatBackupTimestamp(backup.timestamp)}
                  </span>
                  <span class="muted mono backup-path">{backup.path}</span>
                </div>
              </label>
            {/each}
          </div>
        {/if}

        {#if recoveryError}
          <p class="callout">{recoveryError}</p>
        {/if}

        <div class="actions">
          <button class="secondary" type="button" on:click={closeRecoveryWizard} disabled={recoveryBusy}>Cancel</button>
          <button type="button" on:click={recoverFromSelectedBackup} disabled={recoveryBusy || !recoverySelectedBackupPath}>
            {recoveryBusy ? 'Working…' : 'Restore Selected Backup'}
          </button>
        </div>
      </dialog>
    </div>
  {/if}
</main>

<style>
  .app {
    height: 100vh;
    display: grid;
    grid-template-rows: auto 1fr;
    gap: 1rem;
    padding: 1.15rem;
  }

  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.85rem 1rem;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--panel);
    box-shadow: var(--shadow-sm);
    backdrop-filter: blur(10px);
  }

  .wordmark {
    display: flex;
    align-items: center;
    gap: 0.85rem;
    min-width: 0;
  }

  .mark {
    width: 2.35rem;
    height: 2.35rem;
    border-radius: 0.95rem;
    background:
      radial-gradient(70% 70% at 30% 25%, rgba(255, 255, 255, 0.9), transparent 55%),
      conic-gradient(from 210deg, rgba(11, 114, 133, 0.95), rgba(180, 83, 9, 0.82), rgba(6, 118, 71, 0.82), rgba(11, 114, 133, 0.95));
    box-shadow: 0 10px 22px rgba(11, 27, 38, 0.22);
  }

  .topbar h1 {
    margin: 0;
    font-size: 1.15rem;
    letter-spacing: 0.01em;
  }

  .subhead {
    margin: 0.05rem 0 0;
    font-size: 0.9rem;
    color: var(--ink-2);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 55vw;
  }

  .topbar-meta {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  .chip {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.35rem 0.65rem;
    border-radius: 999px;
    border: 1px solid var(--border);
    background: rgba(255, 255, 255, 0.55);
    color: var(--ink-2);
    font-size: 0.85rem;
    font-weight: 650;
  }

  .chip[data-tone='ok'] {
    border-color: rgba(6, 118, 71, 0.35);
    background: rgba(6, 118, 71, 0.12);
    color: var(--success);
  }

  .chip[data-tone='warn'] {
    border-color: rgba(180, 83, 9, 0.35);
    background: rgba(180, 83, 9, 0.12);
    color: rgba(120, 53, 15, 0.95);
  }

  .layout {
    display: grid;
    grid-template-columns: 22.5rem minmax(0, 1fr);
    gap: 1rem;
    align-items: start;
    min-height: 0;
  }

  .sidebar,
  .workspace {
    display: grid;
    gap: 0.85rem;
    min-height: 0;
    overflow: auto;
    padding-right: 0.35rem;
  }

  .workspace-grid {
    display: grid;
    grid-template-columns: minmax(0, 26rem) minmax(0, 1fr);
    gap: 0.85rem;
    align-items: start;
  }

  .workspace-left,
  .workspace-right {
    display: grid;
    gap: 0.85rem;
    align-content: start;
    min-width: 0;
  }

  .picker,
  .settings,
  .vault,
  .quick-unlock,
  .import-export,
  .add-login,
  .add-note,
  .add-passkey,
  .items,
  .debug,
  .detail,
  .search {
    display: grid;
    gap: 0.85rem;
    padding: 0.9rem;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--panel);
    box-shadow: var(--shadow-sm);
    backdrop-filter: blur(10px);
  }

  .fold {
    display: block;
    padding: 0;
  }

  .fold > summary {
    list-style: none;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.9rem;
    font-weight: 750;
    color: var(--ink);
    user-select: none;
  }

  .fold > summary::-webkit-details-marker {
    display: none;
  }

  .fold > summary::marker {
    content: '';
  }

  .fold > summary .summary-meta {
    margin-left: auto;
    font-weight: 650;
    font-size: 0.85rem;
    color: var(--ink-3);
    text-align: right;
  }

  .fold > summary::after {
    content: '>';
    color: var(--ink-3);
    transform: rotate(-90deg);
    transition: transform 140ms ease, color 140ms ease;
  }

  .fold[open] > summary::after {
    transform: rotate(0deg);
    color: var(--ink-2);
  }

  .fold[open] > summary {
    border-bottom: 1px solid var(--border);
  }

  .fold-body {
    padding: 0.9rem;
    display: grid;
    gap: 0.85rem;
  }

  .picker h2,
  .settings h2,
  .vault h2,
  .add-login h2,
  .items h2,
  .detail h2 {
    margin: 0;
    font-size: 1rem;
    letter-spacing: 0.02em;
  }

  .card-head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 0.85rem;
  }

  .card-head button {
    padding: 0.4rem 0.7rem;
  }

  label {
    display: grid;
    gap: 0.4rem;
    font-weight: 650;
    color: var(--ink-2);
    font-size: 0.9rem;
  }

  input,
  textarea,
  select {
    padding: 0.6rem 0.75rem;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-md);
    background: rgba(255, 255, 255, 0.72);
    color: var(--ink);
  }

  input::placeholder,
  textarea::placeholder {
    color: rgba(11, 27, 38, 0.48);
  }

  input:disabled,
  textarea:disabled,
  select:disabled {
    opacity: 0.75;
    background: rgba(255, 255, 255, 0.5);
  }

  textarea {
    resize: vertical;
  }

  .actions {
    display: flex;
    gap: 0.65rem;
    flex-wrap: wrap;
    margin-top: 0.25rem;
  }

  button {
    border: 1px solid rgba(4, 55, 66, 0.32);
    border-radius: 999px;
    padding: 0.55rem 0.9rem;
    cursor: pointer;
    background:
      radial-gradient(80% 120% at 20% 0%, rgba(255, 255, 255, 0.35), transparent 55%),
      linear-gradient(135deg, rgba(11, 114, 133, 0.95), rgba(4, 55, 66, 0.95));
    color: rgba(255, 255, 255, 0.96);
    box-shadow: 0 2px 6px rgba(11, 27, 38, 0.15);
    transition: transform 120ms ease, filter 120ms ease, box-shadow 120ms ease;
  }

  button:hover:not(:disabled) {
    filter: brightness(1.03) saturate(1.02);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(11, 27, 38, 0.2);
  }

  button:active:not(:disabled) {
    transform: translateY(0);
    filter: brightness(0.99);
  }

  button:disabled {
    cursor: not-allowed;
    opacity: 0.6;
    box-shadow: none;
    transform: none;
  }

  button.secondary {
    border-color: var(--border);
    background: rgba(255, 255, 255, 0.65);
    color: var(--ink);
    box-shadow: none;
  }

  button.secondary:hover:not(:disabled) {
    background: rgba(255, 255, 255, 0.82);
    box-shadow: none;
  }

  button.destructive {
    border-color: rgba(180, 35, 24, 0.35);
    background: rgba(180, 35, 24, 0.08);
    color: var(--danger);
    box-shadow: none;
  }

  button.destructive:hover:not(:disabled) {
    background: rgba(180, 35, 24, 0.15);
    box-shadow: none;
    filter: none;
    transform: none;
  }

  button.quiet-destructive {
    border-color: transparent;
    background: transparent;
    color: var(--danger);
    box-shadow: none;
    padding: 0.45rem 0.7rem;
    font-size: 0.85rem;
  }

  button.quiet-destructive:hover:not(:disabled) {
    background: rgba(180, 35, 24, 0.08);
    box-shadow: none;
    filter: none;
    transform: none;
  }

  button.ghost {
    border-color: transparent;
    background: transparent;
    color: var(--ink-3);
    box-shadow: none;
    padding: 0.35rem 0.6rem;
    font-size: 0.85rem;
  }

  button.ghost:hover:not(:disabled) {
    color: var(--ink-2);
    background: rgba(11, 27, 38, 0.05);
    box-shadow: none;
    filter: none;
    transform: none;
  }

  pre {
    margin: 0;
    background: rgba(255, 255, 255, 0.5);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0.55rem 0.75rem;
    white-space: pre-wrap;
    word-break: break-word;
    font-size: 0.85rem;
    color: var(--ink-2);
    box-shadow: none;
  }

  .result {
    min-height: 1.6rem;
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--ink-3);
    opacity: 0.6;
    border: none;
    background: transparent;
    padding: 0.35rem 0;
    border-radius: 0;
    transition: opacity 200ms ease;
  }

  .result:hover {
    opacity: 1;
  }

  .toast-host {
    position: fixed;
    top: 1rem;
    right: 1rem;
    width: min(26rem, calc(100vw - 2rem));
    display: grid;
    gap: 0.65rem;
    z-index: 1100;
  }

  @keyframes toast-in {
    from {
      transform: translateY(-6px);
      opacity: 0;
    }
    to {
      transform: translateY(0);
      opacity: 1;
    }
  }

  @keyframes panel-in {
    from {
      opacity: 0;
      transform: translateY(4px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  .toast {
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: rgba(255, 255, 255, 0.92);
    padding: 0.85rem;
    box-shadow: var(--shadow-lg);
    display: grid;
    gap: 0.5rem;
    animation: toast-in 160ms ease-out;
  }

  .items,
  .add-login,
  .detail,
  .import-export {
    animation: panel-in 180ms ease-out;
  }

  .toast[data-kind='error'] {
    border-color: rgba(180, 35, 24, 0.35);
    background: rgba(180, 35, 24, 0.08);
  }

  .toast[data-kind='success'] {
    border-color: rgba(6, 118, 71, 0.35);
    background: rgba(6, 118, 71, 0.08);
  }

  .toast[data-kind='info'] {
    border-color: rgba(11, 114, 133, 0.35);
    background: rgba(11, 114, 133, 0.08);
  }

  .toast-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
  }

  .toast-close {
    padding: 0 0.7rem;
    height: 2rem;
  }

  .toast-detail {
    background: rgba(11, 27, 38, 0.05);
    border-color: rgba(11, 27, 38, 0.12);
  }

  .toast-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
  }

  .recent-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 0.55rem;
  }

  .recent {
    display: flex;
    gap: 0.75rem;
    justify-content: space-between;
    align-items: center;
    border: 1px solid rgba(11, 27, 38, 0.1);
    border-radius: var(--radius-md);
    padding: 0.65rem 0.75rem;
    background: rgba(255, 255, 255, 0.62);
    transition: background 140ms ease, border-color 140ms ease, transform 140ms ease;
  }

  .recent:hover {
    background: rgba(255, 255, 255, 0.82);
    border-color: rgba(11, 27, 38, 0.16);
    transform: translateY(-1px);
  }

  .recent-meta {
    display: grid;
    gap: 0.1rem;
    min-width: 0;
  }

  .recent-meta span {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    direction: rtl;
    text-align: left;
    font-size: 0.8rem;
    max-width: 100%;
  }

  .filters {
    display: grid;
    gap: 0.65rem;
    grid-template-columns: 1fr 1fr;
    align-items: end;
  }

  .filters .inline {
    grid-column: 1 / -1;
  }

  .items ul {
    margin: 0;
    padding-left: 1.25rem;
  }

  .item-list {
    list-style: none;
    padding-left: 0;
    display: grid;
    gap: 0.45rem;
  }

  .row {
    width: 100%;
    text-align: left;
    border: 1px solid rgba(11, 27, 38, 0.12);
    border-radius: var(--radius-md);
    padding: 0.7rem 0.8rem;
    background: rgba(255, 255, 255, 0.6);
    color: inherit;
    box-shadow: 0 1px 0 rgba(11, 27, 38, 0.05);
    transition: transform 120ms ease, background 120ms ease, border-color 120ms ease;
  }

  .row:hover {
    transform: translateY(-1px);
    background: rgba(255, 255, 255, 0.75);
    border-color: rgba(11, 27, 38, 0.18);
  }

  li.selected .row {
    border-color: var(--accent);
    border-left: 3px solid var(--accent);
    background: rgba(11, 114, 133, 0.07);
    box-shadow: none;
  }

  .meta {
    display: block;
    font-size: 0.85rem;
    color: var(--ink-3);
    margin-top: 0.2rem;
  }

  .type-badge {
    display: inline-block;
    padding: 0.1rem 0.45rem;
    border-radius: 999px;
    font-size: 0.75rem;
    font-weight: 650;
    letter-spacing: 0.02em;
    background: rgba(11, 114, 133, 0.1);
    color: var(--accent);
    margin-right: 0.35rem;
  }

  .muted {
    color: var(--ink-3);
    margin: 0;
  }

  .detail {
    display: grid;
    gap: 0.75rem;
    border-color: rgba(11, 114, 133, 0.25);
    background: rgba(255, 255, 255, 0.88);
  }

  .add-login {
    gap: 0.65rem;
  }

  .add-note .fold-body,
  .add-passkey .fold-body {
    gap: 0.65rem;
  }

  .detail .actions button.destructive {
    margin-left: auto;
  }

  .field {
    display: grid;
    gap: 0.35rem;
  }

  .label {
    font-weight: 750;
    color: var(--ink-2);
  }

  .inline {
    display: flex;
    align-items: center;
    gap: 0.55rem;
    flex-wrap: wrap;
  }

  .totp {
    font-variant-numeric: tabular-nums;
    letter-spacing: 0.08em;
  }

  .qr {
    margin-top: 0.5rem;
    padding: 0.75rem;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: rgba(255, 255, 255, 0.82);
    width: fit-content;
  }

  .qr-img {
    display: block;
    width: 256px;
    height: 256px;
  }

  .note {
    background: rgba(255, 255, 255, 0.55);
    border: 1px solid var(--border);
    font-size: 0.8rem;
    line-height: 1.5;
    max-height: 22rem;
    overflow: auto;
  }

  .mono {
    font-family: var(--font-mono);
  }

  .callout {
    margin: 0;
    padding: 0.75rem 0.85rem;
    border: 1px solid rgba(180, 83, 9, 0.28);
    border-radius: var(--radius-lg);
    background: rgba(180, 83, 9, 0.12);
    color: rgba(120, 53, 15, 0.96);
  }

  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(11, 27, 38, 0.55);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 1rem;
    z-index: 1000;
  }

  .modal {
    width: min(44rem, 92vw);
    max-height: 90vh;
    overflow: auto;
    background: rgba(255, 255, 255, 0.92);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 1rem;
    box-shadow: var(--shadow-lg);
    display: grid;
    gap: 0.85rem;
    backdrop-filter: blur(12px);
  }

  .totp-import {
    display: grid;
    gap: 0.85rem;
  }

  .totp-import-preview {
    display: grid;
    gap: 0.5rem;
  }

  .camera {
    width: 100%;
    aspect-ratio: 4 / 3;
    background: rgba(11, 27, 38, 0.92);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }

  .backup-list {
    display: grid;
    gap: 0.6rem;
  }

  .backup-row {
    display: flex;
    gap: 0.75rem;
    align-items: flex-start;
    padding: 0.75rem 0.85rem;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: rgba(255, 255, 255, 0.72);
  }

  .backup-row input {
    margin-top: 0.2rem;
  }

  .backup-meta {
    display: grid;
    gap: 0.2rem;
    width: 100%;
  }

  .backup-path {
    font-size: 0.85rem;
    word-break: break-word;
  }

  .picker,
  .settings {
    border-color: transparent;
    background: rgba(255, 255, 255, 0.45);
    box-shadow: none;
  }

  .vault {
    border-color: var(--border-strong);
  }

  @media (max-width: 1100px) {
    .layout {
      grid-template-columns: 1fr;
      max-width: 44rem;
      margin-inline: auto;
    }

    .workspace-grid {
      grid-template-columns: 1fr;
    }

    .subhead {
      max-width: 82vw;
    }
  }
</style>
