# `npw` v0.1.0 Execution Plan (`PLAN.md`)

Status: Active
Owner: Codex (execution agent)
Branch: `main`
Source spec: `SPEC.md`

## 1. Shipping Goal
Deliver a complete `v0.1.0` implementation of `npw` that satisfies all MUST requirements in `SPEC.md`, with passing tests/lints/checks after each implemented plan step, and frequent commits pushed to `origin/main`.

## 2. Operating Constraints
- Keep diffs small to medium.
- Commit and push frequently on `main`.
- Run full available checks after each step and fix regressions before proceeding.
- Update `SPEC.md` when implementation-driven clarifications are required.

## 3. Golden Commands
These become authoritative once scaffolded in Step 1:
- `pnpm install`
- `pnpm run lint`
- `pnpm run typecheck`
- `pnpm run test`
- `pnpm run check`
- `pnpm run build`

## 4. Milestones

### M1. Workspace and tooling bootstrap
- Initialize Rust workspace and crates (`core`, `storage`, `domain`, `cli`, `addon`).
- Initialize Electron + Svelte + TypeScript workspace under `apps/desktop`.
- Add root scripts, formatting/linting config, and baseline CI skeleton.
- Validation: all Golden Commands pass.

### M2. Vault format and crypto core (SPEC G/H)
- Implement NPW1 header parsing/validation and CBOR envelope/payload handling.
- Implement Argon2id, HKDF-SHA256, XChaCha20-Poly1305, AAD binding.
- Implement secure random generation and KDF parameter bounds.
- Validation: unit/property tests for roundtrip + AAD tamper failures.

### M3. Storage, atomic writes, locks, backups (SPEC D9/D10/H9/H10)
- Add file locking and first-writer-wins semantics.
- Implement atomic save pipeline and secure permissions.
- Implement backup creation + compaction policy + recovery listing.
- Validation: integration tests for lock contention, crash-safe writes, backup compaction.

### M4. Domain model, schemas, search index (SPEC D2/D5/H5/H8)
- Implement strict schemas for login/note/passkey_ref/totp.
- Add tombstone deletes and schema validation.
- Implement encrypted search index build/query/rebuild behavior.
- Validation: schema tests + search index property tests.

### M5. Password features + TOTP core (SPEC D3/D6/G3)
- Implement charset + diceware generators.
- Integrate strength scoring (`zxcvbn`) + minimum policy.
- Implement RFC 6238 TOTP generation and deterministic `--at` behavior.
- Validation: RFC vectors + generator tests + strength policy tests.

### M6. CLI implementation parity (SPEC J + D11)
- Implement config system (TOML/XDG), JSON output contract, exit codes.
- Implement vault/item/search/totp/passkey/import/export/config/recover/migrate commands.
- Implement structured logs and redaction-safe audit events.
- Validation: CLI integration tests for top acceptance scenarios.

### M7. Import/export + migration workflows (SPEC D7/H7/H11)
- Implement CSV + Bitwarden JSON imports and duplicate handling.
- Implement redacted/plaintext/encrypted exports with warnings.
- Implement migration prompts, `--upgrade`, and downgrade guardrails.
- Validation: import/export/migration integration tests.

### M8. N-API bridge and Electron hardening (SPEC I)
- Implement `napi-rs` bridge from Electron main to Rust core.
- Enforce IPC allowlist and argument validation.
- Apply Electron hardening (`contextIsolation`, `nodeIntegration=false`, CSP, sandbox).
- Validation: bridge tests and renderer IPC restriction checks.

### M9. GUI flows and UX parity (SPEC K/L)
- Implement required screens and CRUD/search/filter flows.
- Add clipboard timeout behavior and auto-lock controls.
- Implement TOTP QR import/export UI and passkey reference UI/actions.
- Validation: Playwright smoke flows + desktop tests.

### M10. Release hardening and security gates (SPEC O/P/W)
- Add coverage gates, fuzz harnesses/targets, and nightly fuzz CI.
- Add dependency audits, SBOM generation, and release pipeline scripts.
- Wire artifact packaging/signing workflow scaffolds.
- Validation: CI matrix green and gate checks passing.

### M11. Documentation and spec reconciliation (SPEC Q/S/U)
- Add user, contributor, and security policy docs.
- Reconcile implementation details and update `SPEC.md` decision/acceptance sections as needed.
- Validation: docs lint and manual checklist pass.

### M12. Final v0.1.0 verification
- Run full suite (tests/lints/typecheck/build/fuzz quick pass).
- Resolve remaining defects.
- Publish final status summary and next-release backlog.
- Validation: all Golden Commands pass.

## 5. Execution Log
- [x] Plan approved by user (`pnpm` selected; dependency additions pre-approved).
- [x] M1 complete: monorepo scaffolded (Rust workspace, Electron+Svelte app, root scripts, CI skeleton, Golden Commands operational).
- [x] M2 complete: NPW1 core parser/writer and crypto pipeline implemented (Argon2id, HKDF-SHA256, XChaCha20-Poly1305, AAD binding) with roundtrip/tamper/KDF-bound tests.
- [x] M3 complete: CLI `vault init/check/unlock/status`, `config get/set/list`, and `generate` (charset+diceware baseline) implemented with config + storage plumbing.
- [ ] M4 in progress: N-API addon now exposes vault APIs, Electron IPC allowlist wired, preload bridge added, and renderer flow calls native methods.
