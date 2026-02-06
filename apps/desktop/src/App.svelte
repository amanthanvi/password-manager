<script>
  import { onDestroy, onMount } from 'svelte'
  import { APP_TITLE, formatStatus } from './lib/app'

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
  let totp = null
  let totpInterval = null
  let recents = []

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
  })

  onDestroy(() => {
    clearTotpInterval()
  })

  const createVault = async () => {
    try {
      await window.npw.vaultCreate({
        path: vaultPath,
        masterPassword,
        label: vaultLabel
      })
      lastResult = `Created vault at ${vaultPath}`
      await refreshRecents()
    } catch (error) {
      lastResult = formatError(error)
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
      await refreshRecents()
      await refreshItems()
    } catch (error) {
      lastResult = formatError(error)
    }
  }

  const lockVault = async () => {
    try {
      await window.npw.vaultLock()
      status = null
      items = []
      selectedItem = null
      loginDetail = null
      totp = null
      clearTotpInterval()
      lastResult = 'Vault locked'
    } catch (error) {
      lastResult = formatError(error)
    }
  }

  const refreshRecents = async () => {
    recents = await window.npw.vaultRecentsList()
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
    } catch (error) {
      lastResult = formatError(error)
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
      lastResult = formatError(error)
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
      lastResult = formatError(error)
    }
  }

  const refreshItems = async () => {
    try {
      items = await window.npw.itemList({ query: query.length > 0 ? query : null })
      if (selectedItem && !items.some((item) => item.id === selectedItem.id)) {
        selectedItem = null
        loginDetail = null
        totp = null
        clearTotpInterval()
      }
      lastResult = `Loaded ${items.length} items`
    } catch (error) {
      lastResult = formatError(error)
    }
  }

  const selectItem = async (item) => {
    selectedItem = item
    loginDetail = null
    totp = null
    clearTotpInterval()
    if (!item) {
      return
    }
    if (item.itemType !== 'login') {
      lastResult = `Item type ${item.itemType} detail view not implemented yet`
      return
    }
    const itemId = item.id
    try {
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
    } catch (error) {
      lastResult = formatError(error)
    }
  }

  const copyUsername = async () => {
    if (!selectedItem) {
      return
    }
    try {
      await window.npw.loginCopyUsername({ id: selectedItem.id })
      lastResult = 'Copied username to clipboard'
    } catch (error) {
      lastResult = formatError(error)
    }
  }

  const copyPassword = async () => {
    if (!selectedItem) {
      return
    }
    try {
      await window.npw.loginCopyPassword({ id: selectedItem.id })
      lastResult = 'Copied password to clipboard (auto-clears)'
    } catch (error) {
      lastResult = formatError(error)
    }
  }

  const copyTotp = async () => {
    if (!selectedItem) {
      return
    }
    try {
      await window.npw.loginCopyTotp({ id: selectedItem.id })
      lastResult = 'Copied TOTP to clipboard (auto-clears)'
    } catch (error) {
      lastResult = formatError(error)
    }
  }

  const refreshTotp = async (id) => {
    totp = await window.npw.loginTotpGet({ id })
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
          <span>{loginDetail.hasPassword ? '••••••••' : '(none)'}</span>
          <button on:click={copyPassword} disabled={!loginDetail.hasPassword}>Copy</button>
        </div>
      </div>

      {#if loginDetail.hasTotp}
        <div class="field">
          <div class="label">TOTP</div>
          {#if totp}
            <div class="inline">
              <span class="totp">{totp.code}</span>
              <span class="muted">{totp.remaining}s</span>
              <button on:click={copyTotp}>Copy</button>
            </div>
          {:else}
            <div class="muted">(loading...)</div>
          {/if}
        </div>
      {/if}

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

  input {
    padding: 0.55rem 0.6rem;
    border: 1px solid #7a919f;
    border-radius: 0.35rem;
    font: inherit;
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

  .urls {
    margin: 0;
    padding-left: 1.25rem;
  }

  .note {
    background: #f4fbff;
    border: 1px solid #93a8b5;
  }
</style>
