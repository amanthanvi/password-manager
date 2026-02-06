import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

// https://vite.dev/config/
export default defineConfig({
  // Required for loading built assets via `file://` in Electron production mode.
  base: './',
  plugins: [svelte()],
})
