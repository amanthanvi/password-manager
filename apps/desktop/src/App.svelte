<script>
  import { onMount } from 'svelte'
  import { APP_TITLE, formatStatus } from './lib/app'

  let vaultPath = '/tmp/npw-desktop.npw'
  let vaultLabel = 'Desktop Vault'
  let masterPassword = ''
  let query = ''
  let bridgeStatus = 'initializing'
  let lastResult = ''
  let status = null
  let items = []

  onMount(async () => {
    try {
      const banner = await window.npw.coreBanner()
      bridgeStatus = formatStatus(banner)
    } catch (error) {
      bridgeStatus = formatStatus(formatError(error))
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
      lastResult = 'Vault locked'
    } catch (error) {
      lastResult = formatError(error)
    }
  }

  const refreshItems = async () => {
    try {
      items = await window.npw.itemList({ query: query.length > 0 ? query : null })
      lastResult = `Loaded ${items.length} items`
    } catch (error) {
      lastResult = formatError(error)
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
        <ul>
          {#each items as item (item.id)}
            <li>
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
            </li>
          {/each}
        </ul>
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

  button {
    border: 1px solid #31536b;
    border-radius: 0.35rem;
    padding: 0.55rem 0.8rem;
    cursor: pointer;
    background: #23465f;
    color: #f4fbff;
    font: inherit;
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
</style>
