# Getting Started

## CLI quickstart
1. Create a vault:
   - `printf 'correct horse battery staple\n' | cargo run -q -p npw-cli -- --non-interactive vault init /tmp/personal.npw --label Personal`
2. Check vault integrity:
   - `printf 'correct horse battery staple\n' | cargo run -q -p npw-cli -- --non-interactive vault check /tmp/personal.npw`
3. Inspect vault header metadata:
   - `cargo run -q -p npw-cli -- vault status /tmp/personal.npw`

## Desktop quickstart
1. Run the desktop app in dev mode (starts Electron + Vite and builds the native addon):
   - `pnpm --filter desktop dev`
2. Optional: run the renderer only (limited: no native dialogs/config/vault access):
   - `pnpm --filter desktop dev:web`
