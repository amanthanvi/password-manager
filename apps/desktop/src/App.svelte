<script>
  import { onMount } from 'svelte'
  import { APP_TITLE, formatStatus } from './lib/app'

  let vaultPath = '/tmp/npw-desktop.npw'
  let vaultLabel = 'Desktop Vault'
  let masterPassword = ''
  let bridgeStatus = 'initializing'
  let lastResult = ''
  let status = null

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
      await loadStatus()
    } catch (error) {
      lastResult = formatError(error)
    }
  }

  const loadStatus = async () => {
    try {
      status = await window.npw.vaultStatus({ path: vaultPath })
      lastResult = `Loaded status for ${status.path}`
    } catch (error) {
      lastResult = formatError(error)
    }
  }

  const checkVault = async () => {
    try {
      status = await window.npw.vaultCheck({
        path: vaultPath,
        masterPassword
      })
      lastResult = `Vault check passed for ${status.path}`
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
    <button on:click={loadStatus}>Load Status</button>
    <button on:click={checkVault}>Check Vault</button>
  </div>

  <p>{lastResult}</p>

  {#if status}
    <pre>{JSON.stringify(status, null, 2)}</pre>
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
</style>
