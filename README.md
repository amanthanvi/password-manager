# npw Password Manager

Local-first password manager with a Rust core/CLI and an Electron + Svelte desktop app.

## Features (v0.1.0)

- Offline-first encrypted vaults (`.npw`) with backups and recovery
- Logins, secure notes, TOTP (RFC 6238), and passkey reference items
- Import: CSV and Bitwarden JSON (with duplicate detection)
- Export: redacted/plaintext and encrypted export
- Optional OS keychain "Quick Unlock" (opt-in per vault)
- No networking by default

## Tooling

- Node.js 23+
- pnpm 10+
- Rust 1.93.0

## Workspace commands

- `pnpm install`
- `pnpm run lint`
- `pnpm run typecheck`
- `pnpm run test`
- `pnpm run build`
- `pnpm run check`

## Getting started

- CLI + desktop quickstart: `docs/getting-started.md`
- Import/export notes: `docs/import-export.md`
- Backups and recovery: `docs/backups-recovery.md`

## Docs

- Contributor guide: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`
- User docs: `docs/getting-started.md`

## License

Apache-2.0. See `LICENSE`.
