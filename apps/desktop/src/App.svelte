<script lang="ts">
  import { APP_TITLE, formatStatus } from './lib/app'

  const bridgeStatus = typeof window.npw === 'undefined' ? 'bridge unavailable' : window.npw.ping()
</script>

<main class="shell">
  <h1>{APP_TITLE}</h1>
  <p>{formatStatus(bridgeStatus)}</p>
</main>

<style>
  .shell {
    display: grid;
    gap: 0.75rem;
    width: min(40rem, 90vw);
  }
</style>
