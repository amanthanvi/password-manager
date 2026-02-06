# Contributing to npw

## Prerequisites
- Node.js 23+
- pnpm 10+
- Rust 1.93.0

## Setup
1. `pnpm install`
2. `pnpm run check`

## Golden commands
- `pnpm run lint`
- `pnpm run typecheck`
- `pnpm run test`
- `pnpm run build`
- `pnpm run check`

## Development notes
- Rust lives under `crates/`.
- Electron + Svelte desktop app lives under `apps/desktop`.
- Native Node addon is built from `crates/npw-addon` and copied to `apps/desktop/native/npw-addon.node` by `scripts/build-addon.mjs`.

## Pull request expectations
- Keep diffs focused and reviewable.
- Add or update tests for behavioral changes.
- Run `pnpm run check` before pushing.
