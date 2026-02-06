<script>
  import { onDestroy, onMount } from 'svelte'
  import { APP_TITLE, formatStatus } from './lib/app'
  import jsQR from 'jsqr'

  let vaultPath = '/tmp/npw-desktop.npw'
  let vaultLabel = 'Desktop Vault'
  let masterPassword = ''
  let query = ''
  let bridgeStatus = 'initializing'
  let lastResult = ''
  let status = null
  let items = []
  let selectedItem = null
  let loginDetail = null
  let noteDetail = null
  let passkeyDetail = null
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
  let newLoginTitle = ''
  let newLoginUrl = ''
  let newLoginUsername = ''
  let newLoginPassword = ''
  let newLoginNotes = ''
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

  onMount(async () => {
    try {
      const banner = await window.npw.coreBanner()
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

    detachVaultLocked = window.npw.onVaultLocked(({ reason }) => {
      status = null
      items = []
      selectedItem = null
      loginDetail = null
      noteDetail = null
      passkeyDetail = null
      totp = null
      totpQrUrl = null
      totpQrVisible = false
      closeTotpImport()
      clearTotpInterval()
      masterPassword = ''
      recoveryVisible = false
      recoveryVaultPath = ''
      recoveryBackups = []
      recoverySelectedBackupPath = ''
      recoveryBusy = false
      recoveryError = ''
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
      window.npw.appActivity().catch(() => {})
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
      await window.npw.vaultCreate({
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
      status = await window.npw.vaultUnlock({
        path: vaultPath,
        masterPassword
      })
      masterPassword = ''
      lastResult = `Vault unlocked: ${status.path}`
      pushToast({ kind: 'success', title: 'Vault unlocked', timeoutMs: 3500 })
      await refreshRecents()
      await refreshItems()
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
      recoveryBackups = await window.npw.vaultBackupsList({ path })
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
      await window.npw.vaultCheck({ path: recoverySelectedBackupPath, masterPassword })
      const result = await window.npw.vaultRecoverFromBackup({
        path: recoveryVaultPath,
        backupPath: recoverySelectedBackupPath
      })
      if (result?.corruptPath) {
        lastResult = `Preserved corrupt vault at ${result.corruptPath}`
      }
      status = await window.npw.vaultUnlock({
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
      await window.npw.vaultLock()
      status = null
      items = []
      selectedItem = null
      loginDetail = null
      noteDetail = null
      passkeyDetail = null
      totp = null
      totpQrUrl = null
      totpQrVisible = false
      clearTotpInterval()
      closeRecoveryWizard()
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
    recents = await window.npw.vaultRecentsList()
  }

  const refreshConfig = async () => {
    settingsError = ''
    try {
      appConfig = await window.npw.configLoad()
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
      appConfig = await window.npw.configSet({
        key: 'security.clipboard_timeout_seconds',
        value: String(Number(settingsClipboardTimeoutSeconds))
      })
      appConfig = await window.npw.configSet({
        key: 'security.auto_lock_minutes',
        value: String(Number(settingsAutoLockMinutes))
      })
      appConfig = await window.npw.configSet({
        key: 'security.lock_on_suspend',
        value: String(Boolean(settingsLockOnSuspend))
      })
      appConfig = await window.npw.configSet({
        key: 'security.reveal_requires_confirm',
        value: String(Boolean(settingsRevealRequiresConfirm))
      })
      appConfig = await window.npw.configSet({
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
  }

  const removeRecent = async (vault) => {
    try {
      await window.npw.vaultRecentsRemove({ path: vault.path })
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
    try {
      const picked = await window.npw.vaultDialogOpen()
      if (!picked) {
        return
      }
      vaultPath = picked
      lastResult = `Selected vault: ${picked}`
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({ kind: 'error', title: 'Open vault dialog failed', detail: message })
    }
  }

  const pickCreateVault = async () => {
    try {
      const picked = await window.npw.vaultDialogCreate()
      if (!picked) {
        return
      }
      vaultPath = picked
      lastResult = `Selected new vault path: ${picked}`
    } catch (error) {
      const message = formatError(error)
      lastResult = message
      pushToast({ kind: 'error', title: 'Create vault dialog failed', detail: message })
    }
  }

  const refreshItems = async () => {
    try {
      items = await window.npw.itemList({ query: query.length > 0 ? query : null })
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

  const addNote = async () => {
    try {
      const id = await window.npw.noteAdd({ title: newNoteTitle, body: newNoteBody })
      newNoteTitle = ''
      newNoteBody = ''
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

  const addLogin = async () => {
    try {
      const id = await window.npw.loginAdd({
        title: newLoginTitle,
        url: newLoginUrl.length > 0 ? newLoginUrl : null,
        username: newLoginUsername.length > 0 ? newLoginUsername : null,
        password: newLoginPassword,
        notes: newLoginNotes
      })
      newLoginTitle = ''
      newLoginUrl = ''
      newLoginUsername = ''
      newLoginPassword = ''
      newLoginNotes = ''
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
      const deleted = await window.npw.itemDelete({ id })
      selectedItem = null
      loginDetail = null
      noteDetail = null
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
        loginDetail = await window.npw.loginGet({ id: itemId })
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
        noteDetail = await window.npw.noteGet({ id: itemId })
        lastResult = `Loaded item ${itemId}`
        return
      }

      if (item.itemType === 'passkey_ref') {
        passkeyDetail = await window.npw.passkeyRefGet({ id: itemId })
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
      await window.npw.loginCopyUsername({ id: selectedItem.id })
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
      await window.npw.loginCopyPassword({ id: selectedItem.id })
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
      const password = await window.npw.loginRevealPassword({ id: selectedItem.id })
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
      const mode = await window.npw.loginGenerateReplacePassword({ id: selectedItem.id })
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
      await window.npw.loginCopyTotp({ id: selectedItem.id })
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
    totp = await window.npw.loginTotpGet({ id })
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
      const svg = await window.npw.loginTotpQrSvg({ id: selectedItem.id })
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
      await window.npw.loginTotpSet({ id, value })
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
      await window.npw.passkeyOpenSite({ id: selectedItem.id })
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
      await window.npw.passkeyOpenManager()
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

<main class="shell">
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

  <h1>{APP_TITLE}</h1>
  <p>{bridgeStatus}</p>

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
              <button class="secondary" type="button" on:click={() => removeRecent(vault)}>Remove</button>
            </div>
          </li>
        {/each}
      </ul>
    {/if}
    <div class="actions">
      <button type="button" on:click={pickCreateVault}>Create New Vault…</button>
      <button type="button" on:click={pickOpenVault}>Open Existing Vault…</button>
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
      <button type="button" on:click={saveSettings} disabled={settingsSaving}>
        {settingsSaving ? 'Saving…' : 'Save Settings'}
      </button>
      <button class="secondary" type="button" on:click={refreshConfig} disabled={settingsSaving}>Reload</button>
    </div>
  </section>

  <label>
    Vault path
    <input bind:value={vaultPath} />
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
    <button on:click={createVault}>Create Vault</button>
    <button on:click={unlockVault}>Unlock Vault</button>
    <button on:click={lockVault} disabled={!status}>Lock Vault</button>
  </div>

  <label>
    Search
    <input bind:value={query} on:input={refreshItems} disabled={!status} />
  </label>

  {#if status}
    <section class="add-login">
      <h2>Add Login</h2>
      <label>
        Title
        <input bind:value={newLoginTitle} />
      </label>
      <label>
        URL
        <input bind:value={newLoginUrl} />
      </label>
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
      <div class="actions">
        <button on:click={addLogin} disabled={newLoginTitle.trim().length === 0}>Save Login</button>
      </div>
    </section>
  {/if}

  {#if status}
    <section class="add-note">
      <h2>Add Note</h2>
      <label>
        Title
        <input bind:value={newNoteTitle} />
      </label>
      <label>
        Body
        <textarea bind:value={newNoteBody} rows="4"></textarea>
      </label>
      <div class="actions">
        <button on:click={addNote} disabled={newNoteTitle.trim().length === 0}>Save Note</button>
      </div>
    </section>
  {/if}

  <div class="actions">
    <button on:click={refreshItems} disabled={!status}>Refresh Items</button>
  </div>

  <pre class="result">{lastResult}</pre>

  {#if status}
    <pre>{JSON.stringify(status, null, 2)}</pre>
  {/if}

  {#if status}
    <section class="items">
      <h2>Items</h2>
      {#if items.length === 0}
        <p class="muted">No items found.</p>
      {:else}
        <ul class="item-list">
          {#each items as item (item.id)}
            <li class:selected={selectedItem?.id === item.id}>
              <button class="row" type="button" on:click={() => selectItem(item)}>
                <strong>{item.title}</strong>
                <span class="meta">
                  {item.itemType}
                  {#if item.subtitle}
                    · {item.subtitle}
                  {/if}
                  {#if item.url}
                    · {item.url}
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

  {#if status && selectedItem && loginDetail}
    <section class="detail">
      <h2>Login</h2>
      <p class="muted">{loginDetail.id}</p>
      <div class="actions">
        <button class="secondary" on:click={deleteSelectedItem}>Delete</button>
      </div>

      <div class="field">
        <div class="label">Title</div>
        <div>{loginDetail.title}</div>
      </div>

      <div class="field">
        <div class="label">Username</div>
        <div class="inline">
          <span>{loginDetail.username ?? '(none)'}</span>
          <button on:click={copyUsername} disabled={!loginDetail.username}>Copy</button>
        </div>
      </div>

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
        {#if loginDetail.urls.length === 0}
          <div class="muted">(none)</div>
        {:else}
          <ul class="urls">
            {#each loginDetail.urls as url, index (index)}
              <li>{url}</li>
            {/each}
          </ul>
        {/if}
      </div>

      {#if loginDetail.notes}
        <div class="field">
          <div class="label">Notes</div>
          <pre class="note">{loginDetail.notes}</pre>
        </div>
      {/if}
    </section>
  {/if}

  {#if status && selectedItem && noteDetail}
    <section class="detail">
      <h2>Note</h2>
      <p class="muted">{noteDetail.id}</p>
      <div class="actions">
        <button class="secondary" on:click={deleteSelectedItem}>Delete</button>
      </div>

      <div class="field">
        <div class="label">Title</div>
        <div>{noteDetail.title}</div>
      </div>

      <div class="field">
        <div class="label">Body</div>
        <pre class="note">{noteDetail.body}</pre>
      </div>
    </section>
  {/if}

  {#if status && selectedItem && passkeyDetail}
    <section class="detail">
      <h2>Passkey Reference</h2>
      <p class="muted">{passkeyDetail.id}</p>
      <p class="callout">This app does not store passkeys. This is a reference entry.</p>
      <div class="actions">
        <button on:click={openPasskeySite}>Open Site</button>
        <button on:click={openPasskeyManager}>Open Passkey Manager</button>
        <button class="secondary" on:click={deleteSelectedItem}>Delete</button>
      </div>

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

      {#if passkeyDetail.notes}
        <div class="field">
          <div class="label">Notes</div>
          <pre class="note">{passkeyDetail.notes}</pre>
        </div>
      {/if}
    </section>
  {/if}

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
  .shell {
    display: grid;
    gap: 0.75rem;
    width: min(40rem, 90vw);
  }

  label {
    display: grid;
    gap: 0.35rem;
    font-weight: 600;
  }

  input,
  textarea,
  select {
    padding: 0.55rem 0.6rem;
    border: 1px solid #7a919f;
    border-radius: 0.35rem;
    font: inherit;
  }

  textarea {
    resize: vertical;
  }

  .actions {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  .picker {
    display: grid;
    gap: 0.75rem;
    padding: 0.75rem;
    border: 1px solid #93a8b5;
    border-radius: 0.75rem;
    background: #f4fbff;
  }

  .picker h2 {
    margin: 0;
  }

  .add-note,
  .add-login {
    display: grid;
    gap: 0.75rem;
    padding: 0.75rem;
    border: 1px solid #93a8b5;
    border-radius: 0.75rem;
    background: #f4fbff;
  }

  .add-note h2,
  .add-login h2 {
    margin: 0;
  }

  .recent-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 0.5rem;
  }

  .recent {
    display: flex;
    gap: 0.75rem;
    justify-content: space-between;
    align-items: center;
    border: 1px solid #dde8ee;
    border-radius: 0.5rem;
    padding: 0.6rem 0.75rem;
    background: #ffffff;
  }

  .recent-meta {
    display: grid;
    gap: 0.15rem;
    min-width: 0;
  }

  .recent-meta span {
    word-break: break-word;
  }

  button {
    border: 1px solid #31536b;
    border-radius: 0.35rem;
    padding: 0.55rem 0.8rem;
    cursor: pointer;
    background: #23465f;
    color: #f4fbff;
    font: inherit;
  }

  button.secondary {
    border-color: #93a8b5;
    background: #dde8ee;
    color: #23465f;
  }

  pre {
    margin: 0;
    background: #dde8ee;
    border: 1px solid #93a8b5;
    border-radius: 0.5rem;
    padding: 0.75rem;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .result {
    min-height: 3.5rem;
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

  .toast {
    border: 1px solid #93a8b5;
    border-radius: 0.75rem;
    background: #ffffff;
    padding: 0.75rem;
    box-shadow: 0 16px 45px rgba(0, 0, 0, 0.22);
    display: grid;
    gap: 0.5rem;
  }

  .toast[data-kind='error'] {
    border-color: #f1a1a1;
    background: #fff1f1;
  }

  .toast[data-kind='success'] {
    border-color: #8fd8a6;
    background: #f0fdf4;
  }

  .toast[data-kind='info'] {
    border-color: #8ab7ea;
    background: #eff6ff;
  }

  .toast-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
  }

  .toast-close {
    padding: 0 0.55rem;
    height: 2rem;
  }

  .toast-detail {
    background: rgba(35, 70, 95, 0.08);
    border-color: rgba(35, 70, 95, 0.2);
  }

  .toast-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
  }

  .items h2 {
    margin: 0;
  }

  .items ul {
    margin: 0;
    padding-left: 1.25rem;
  }

  .item-list {
    list-style: none;
    padding-left: 0;
    display: grid;
    gap: 0.35rem;
  }

  .row {
    width: 100%;
    text-align: left;
    border: 1px solid #93a8b5;
    border-radius: 0.5rem;
    padding: 0.6rem 0.75rem;
    background: #f4fbff;
    color: inherit;
  }

  li.selected .row {
    border-color: #31536b;
    box-shadow: 0 0 0 2px rgba(49, 83, 107, 0.15);
  }

  .meta {
    display: block;
    font-size: 0.9rem;
    opacity: 0.75;
    margin-top: 0.15rem;
  }

  .muted {
    opacity: 0.75;
    margin: 0;
  }

  .detail {
    display: grid;
    gap: 0.75rem;
  }

  .field {
    display: grid;
    gap: 0.25rem;
  }

  .label {
    font-weight: 700;
  }

  .inline {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  .totp {
    font-variant-numeric: tabular-nums;
    letter-spacing: 0.08em;
  }

  .qr {
    margin-top: 0.5rem;
    padding: 0.75rem;
    border: 1px solid #93a8b5;
    border-radius: 0.5rem;
    background: #ffffff;
    width: fit-content;
  }

  .qr-img {
    display: block;
    width: 256px;
    height: 256px;
  }

  .urls {
    margin: 0;
    padding-left: 1.25rem;
  }

  .note {
    background: #f4fbff;
    border: 1px solid #93a8b5;
  }

  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;
  }

  .callout {
    margin: 0;
    padding: 0.6rem 0.75rem;
    border: 1px solid #e0d2a3;
    border-radius: 0.5rem;
    background: #fff6d7;
  }

  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(12, 21, 27, 0.55);
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
    background: #ffffff;
    border: 1px solid #93a8b5;
    border-radius: 0.75rem;
    padding: 1rem;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.35);
    display: grid;
    gap: 0.75rem;
  }

  .totp-import {
    display: grid;
    gap: 0.75rem;
  }

  .totp-import-preview {
    display: grid;
    gap: 0.5rem;
  }

  .camera {
    width: 100%;
    aspect-ratio: 4 / 3;
    background: rgba(12, 21, 27, 0.9);
    border: 1px solid #93a8b5;
    border-radius: 0.5rem;
  }

  .backup-list {
    display: grid;
    gap: 0.5rem;
  }

  .backup-row {
    display: flex;
    gap: 0.75rem;
    align-items: flex-start;
    padding: 0.6rem 0.75rem;
    border: 1px solid #93a8b5;
    border-radius: 0.5rem;
    background: #f4fbff;
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
</style>
