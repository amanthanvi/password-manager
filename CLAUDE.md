# npw — Project Instructions

## Project

Local-first FOSS password manager. Rust crypto core + CLI, Electron + Svelte GUI.
Full specification: `SPEC.md`.

## Tech Stack

- **Core**: Rust (crypto, vault I/O, domain logic, CLI)
- **GUI**: Electron main process (TypeScript) + Svelte renderer
- **Bridge**: napi-rs (Rust N-API addon)
- **Crypto**: Argon2id (KDF), XChaCha20-Poly1305 (AEAD), HKDF-SHA256
- **Serialization**: CBOR (ciborium)
- **Config**: TOML (XDG paths)
- **Build**: Cargo + pnpm/bun

## btca (Context-Aware Codebase Search)

btca is configured as an MCP server for this project. Agent-specific configs
are committed to the repo — each agent reads its own file automatically:

- Claude Code: `.mcp.json`
- Codex CLI: `.codex/config.toml`
- OpenCode: `opencode.json`

Resources are defined in `btca.config.jsonc` (shared across all agents).

### Available resources

Query these by name with the btca `ask` tool:

| Resource | What it covers |
|----------|---------------|
| `svelte` | Svelte framework (GUI renderer) |
| `electron` | Electron docs (desktop platform) |
| `napi-rs` | Rust N-API bindings (main process addon) |
| `rustcrypto-password-hashes` | Argon2id crate source |
| `rustcrypto-aeads` | XChaCha20-Poly1305 crate source |

### Usage pattern

1. Call `listResources` first to confirm available resources.
2. Call `ask` with the exact resource name and a specific question.
3. Resource names are case-sensitive and must match exactly.

### Setup on a new device

```bash
./scripts/setup-btca.sh
```

## Verification

No verification scripts exist yet. Will be added when source code is introduced.
