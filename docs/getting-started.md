# Getting Started

## CLI quickstart
1. Create a vault:
   - `printf 'correct horse battery staple\n' | cargo run -q -p npw-cli -- --non-interactive vault init /tmp/personal.npw --label Personal`
2. Check vault integrity:
   - `printf 'correct horse battery staple\n' | cargo run -q -p npw-cli -- --non-interactive vault check /tmp/personal.npw`
3. Inspect vault header metadata:
   - `cargo run -q -p npw-cli -- vault status /tmp/personal.npw`

## Desktop quickstart
1. Build desktop app assets + native addon:
   - `pnpm --filter desktop build`
2. Run desktop renderer dev server:
   - `pnpm --filter desktop dev`
