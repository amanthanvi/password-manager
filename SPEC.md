# `[NAME PENDING]` — v0.1.0 Implementation Specification (SPEC.md)

**Status:** Draft for implementation and security review  
**Audience:** Maintainers, contributors, implementers, security reviewers  
**Normative language:** The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** are to be interpreted as described in **RFC 2119** and **RFC 8174**.

---

## Table of Contents

- [A. Executive Summary](#a-executive-summary)
- [B. Goals / Non-Goals](#b-goals--non-goals)
- [C. Personas and Use Cases](#c-personas-and-use-cases)
- [D. Functional Requirements (v0.1.0)](#d-functional-requirements-v010)
- [E. Non-Functional Requirements](#e-non-functional-requirements)
- [F. Threat Model and Security Posture](#f-threat-model-and-security-posture)
- [G. Cryptography and Key Management (implementation-grade)](#g-cryptography-and-key-management-implementation-grade)
- [H. Data Model and Storage Format](#h-data-model-and-storage-format)
- [I. Application Architecture](#i-application-architecture)
- [J. CLI Specification](#j-cli-specification)
- [K. GUI Specification (Electron)](#k-gui-specification-electron)
- [L. Cross-Platform OS Integration](#l-cross-platform-os-integration)
- [M. Networking (Default: none)](#m-networking-default-none)
- [N. Observability, Telemetry, and Logging](#n-observability-telemetry-and-logging)
- [O. QA, Test Plan, and Security Validation](#o-qa-test-plan-and-security-validation)
- [P. Release Engineering and Supply Chain Security](#p-release-engineering-and-supply-chain-security)
- [Q. Documentation Deliverables](#q-documentation-deliverables)
- [R. Milestones and Delivery Plan](#r-milestones-and-delivery-plan)
- [S. Acceptance Criteria (v0.1.0)](#s-acceptance-criteria-v010)
- [T. Open Questions / Future Work](#t-open-questions--future-work)
- [U. Decision Log (v0.1.0)](#u-decision-log-v010)
- [V. Security Defaults Summary (One Page)](#v-security-defaults-summary-one-page)
- [License (Project Requirement)](#license-project-requirement)

---

## A. Executive Summary

`[NAME PENDING]` is a **local-first**, privacy-preserving **FOSS password manager** for Windows/macOS/Linux with:

- A **cross-platform CLI** for scripting, automation, and power users.
- A **cross-platform Electron GUI** for mainstream users.

### Primary value proposition

- **No cloud account required.**
- **Offline-first**: core functionality works without networking.
- **Security by design**: strong KDF, authenticated encryption, hardened IPC boundaries, and supply-chain controls.
- **Standards-aware passkey/WebAuthn support**: **organize and “use” passkeys safely without attempting to export private keys** that are typically bound to platform authenticators.

### v0.1.0 headline features

- Encrypted vault file format (`.npw`) with versioning and safe migration.
- Login items, secure notes, TOTP (RFC 6238) seeds + code generation.
- Passkey/WebAuthn **reference items** + OS-integrated “open/manage” actions.
- Import/export (CSV + Bitwarden JSON import; encrypted export supported).
- Scriptable CLI with stable `--json` output and deterministic exit codes.
- Electron GUI with accessibility baseline and secure UX defaults.
- Optional OS keychain integration for convenience **only when explicitly enabled**.

---

## B. Goals / Non-Goals

### Goals

1. **Security**
    - Vault confidentiality and integrity against offline attackers with vault-file access.
    - Strong, tunable KDF and modern AEAD encryption.
    - Safe defaults that minimize accidental leakage (clipboard timeouts, redacted logs).
2. **Privacy**
    - **No networking by default**, no mandatory telemetry.
    - Local-first: data stored on-device, user-controlled backups.
3. **Usability**
    - GUI suitable for non-technical users.
    - CLI suitable for automation with stable machine-readable output.
4. **Cross-platform**
    - Windows/macOS/Linux with explicit behaviors and secure file handling.
5. **FOSS / auditability**
    - Open development, reproducible builds where feasible, SBOM, and security policy.

### Non-Goals

- Running a hosted sync service or requiring accounts.
- Browser extension (autofill) in v0.1.0.
- Mobile clients in v0.1.0.
- Full protection against a fully compromised OS with active malware (see threat model).
- Forcing users into a single workflow: power users may use CLI only.

### Out of scope for v0.1.0

- End-to-end sync across devices.
- Encrypted binary attachments stored inside the vault (see Section H0).
- Team sharing, multi-user access control, enterprise policy controls.
- Custom WebAuthn authenticator implementation or exporting/importing passkey private keys.

---

## C. Personas and Use Cases

### Personas

1. **Everyday User (GUI-first)**
    - Wants to store logins, generate passwords, and copy TOTP codes.
    - Needs “simple and safe” defaults and clear warnings.
2. **Power User (CLI-first)**
    - Automates retrieval/copying of secrets and uses scripts.
    - Needs stable JSON output and reliable exit codes.
3. **Developer/Ops/Security Engineer (Hybrid)**
    - Wants reproducible builds, clear crypto spec, threat model, and security controls.
    - May enable OS keychain for convenience and expects minimal attack surface.

### Use cases + success criteria

1. **Create a new vault (offline)**
    - Success: vault file created with secure permissions; user can unlock with chosen master password; wrong password fails safely.
2. **Store a new login and copy password**
    - Success: item saved, searchable; password copied without revealing in UI by default; clipboard auto-clears.
3. **Add TOTP seed and generate codes**
    - Success: seed stored encrypted; code generated deterministically per RFC 6238; time skew handled with user options.
4. **Import from Bitwarden JSON**
    - Success: logins/notes/TOTP fields imported with mapping report; no plaintext export unless user confirms.
5. **“Use” a passkey safely**
    - Success: user can store passkey reference metadata and open the relying party origin / OS passkey manager from the item; app never stores passkey private keys.

---

## D. Functional Requirements (v0.1.0)

All requirements in this section are **testable** and MUST be met for v0.1.0 acceptance.

### D1. Vault lifecycle

- The system MUST support **creating** a new vault with a master password.
- The system MUST support **unlocking** a vault offline.
- The system MUST support **locking** the vault:
    - manual lock (user action),
    - auto-lock after inactivity,
    - lock on OS suspend/lock (best effort; MUST be implemented on Windows/macOS; SHOULD on Linux).
- The system MUST support **changing master password** (see Section G7).
- The system MUST support **vault health check** (verify header integrity, decryptability, schema validation).
- The system MUST support **multi-vault**:
    - GUI: select recent vaults; open by path.
    - CLI: `--vault <path>` on all relevant commands; default from config if set.

### D2. Item types and CRUD

The system MUST support CRUD for:

1. **Login item**
2. **Secure note**
3. **TOTP** (as part of login item by default; MAY be standalone later)
4. **Passkey / WebAuthn reference**

CRUD requirements:

- Items MUST have a stable unique ID (UUIDv4).
- Updates MUST be atomic and crash-safe.
- Deleting MUST support “soft delete” (tombstone) until compaction (v0.2+). In v0.1.0, tombstones MUST exist in payload.

### D3. Password generation

- The system MUST provide a CSPRNG-backed password generator with:
    - length (default 20; min 8; max 128),
    - character sets: lowercase, uppercase, digits, symbols (configurable),
    - optional “avoid ambiguous characters” flag.
- Production builds MUST use OS CSPRNG; test builds MAY allow deterministic seeds.

### D4. Clipboard handling

- Copy actions MUST be available in CLI and GUI.
- Clipboard contents MUST auto-clear after timeout (default 30 seconds).
- Clear behavior MUST be “best effort”:
    - MUST clear if clipboard still matches what the app set,
    - MUST NOT overwrite if user changed clipboard after copy.
- Clipboard timeout MUST be configurable (5–120 seconds) and can be disabled only with an explicit warning.

### D5. Search, filtering, favorites

- Search MUST be performed **only after unlock** (no plaintext index on disk).
- Search MUST support substring matching on: title, username, URL, tags.
- Filtering MUST support: type, tag, favorite.
- GUI SHOULD provide incremental search with debounce.

### D6. TOTP (RFC 6238)

- The system MUST support TOTP generation per RFC 6238 with:
    - default: 6 digits, 30s period, HMAC-SHA1,
    - support: SHA256, SHA512; digits 6 or 8; period 30 or 60.
- Inputs accepted:
    - base32 secret (CLI/GUI),
    - `otpauth://` URI (CLI/GUI),
    - QR code import (GUI).
- Time skew handling:
    - GUI MUST show current code and countdown.
    - CLI MUST support `--at <unix_seconds>` for deterministic output.

### D7. Import/export/backup

- Import MUST support:
    - CSV (defined schema below),
    - Bitwarden unencrypted JSON export (common format).
- Export MUST support:
    - CSV (redacted by default; secrets only with explicit flag),
    - JSON (redacted by default; secrets only with explicit flag),
    - **encrypted export** (“portable vault export”) protected by a user-specified password.
- Export MUST show warnings before writing secrets in plaintext.
- Automatic backups MUST be supported:
    - keep last N versions (default 10) in a backup directory adjacent to vault or user-configured.
    - backups MUST remain encrypted vault copies; plaintext exports MUST NOT be auto-backed-up.

#### CSV import schema (v0.1.0)

CSV MUST be UTF-8 with header row. Supported columns:

- `type` (`login` or `note`)
- `title`
- `username`
- `password`
- `url`
- `notes`
- `tags` (semicolon-separated)
- `totp_uri` (optional `otpauth://...`)
  Unknown columns MUST be ignored with a warning report.

### D8. Passkeys / WebAuthn support definition (v0.1.0)

v0.1.0 “support” MUST mean:

- Vault can store **Passkey Reference Items** (metadata and links).
- GUI MUST provide actions:
    - “Open site” (open default browser to an origin URL),
    - “Open OS passkey manager” (best effort per OS),
    - “Copy username” / “Copy relying party ID”.
- CLI MUST provide: list/show/open-site/copy-username.
- The application MUST NOT store or attempt to export/import **passkey private keys** in v0.1.0.

### D9. Concurrency and file locking

- The application MUST prevent concurrent writes to the same vault:
    - MUST use OS-level file locks where supported.
    - If lock cannot be acquired, MUST fail with deterministic error code (CLI exit code 5).
- Writes MUST be serialized across GUI and CLI.

### D10. Error handling and recovery

- Wrong password MUST fail without leaking details.
- Vault corruption:
    - GUI MUST offer restore from backups.
    - CLI MUST provide `vault backup --restore <file>`.
- Partial writes MUST not corrupt the current vault (atomic write requirement).
- The system MUST validate schemas and reject invalid payloads without silent truncation.

### D11. CLI parity vs GUI parity

- CLI MUST support:
    - vault create/unlock/lock/status/change-password/check,
    - item CRUD for login/note/passkey_ref,
    - list/search,
    - TOTP show/copy,
    - import/export (with warnings; non-interactive flags),
    - configuration commands.
- GUI MUST support everything CLI supports except:
    - some advanced import mapping MAY be CLI-first but MUST be documented.
- GUI-only in v0.1.0:
    - QR code scanning for TOTP.

---

## E. Non-Functional Requirements

### Security & privacy

- Vault MUST provide confidentiality and integrity against offline attackers with only the vault file.
- No plaintext secrets MUST be written to disk by default (including logs, caches, renderer storage).
- Networking MUST be disabled by default (Section M).

### Performance targets

Assumptions: Windows 10+/macOS 12+/Ubuntu 22.04+, x86_64 or arm64, SSD.

- Unlock time with default KDF: **SHOULD** be \(\le 1.5s\) on typical 2020+ laptop; **MUST** be \(\le 4s\) on slower machines (or user MUST be prompted to reduce KDF parameters).
- Search over 10,000 items: **SHOULD** return results in \(\le 200ms\) after initial in-memory index build post-unlock.
- Save operation: **SHOULD** complete in \(\le 300ms\) for typical vault sizes (<5MB decrypted payload).

### Reliability / crash safety

- Writes MUST be atomic (temp write + fsync + atomic rename + directory fsync best effort).
- Rolling encrypted backups MUST be maintained.

### UX responsiveness (GUI)

- KDF and encryption MUST run off the renderer thread.
- Operations >300ms MUST show progress affordances.

### Accessibility baseline

- GUI MUST support keyboard navigation for all core flows.
- GUI MUST expose accessible names/labels for inputs/buttons.
- GUI MUST provide visible focus indicators.
- GUI MUST NOT rely on color alone to convey status.

### Internationalization stance

- v0.1.0 SHOULD structure UI strings for future i18n but MAY ship English-only.

### Update policy

- v0.1.0 MUST ship with signed release artifacts (Section P).
- Auto-update/network checks MUST be opt-in and disabled by default (Section M).

### Supported OS versions

- Windows 10 (22H2) and Windows 11
- macOS 12+
- Linux: Ubuntu 22.04+ (AppImage), best effort elsewhere

---

## F. Threat Model and Security Posture

### Assets

1. Vault contents (passwords, notes, TOTP seeds)
2. Metadata (titles, URLs, tags) — encrypted at rest
3. Master password (transient in memory)
4. Derived keys and decrypted payload (memory)
5. Clipboard contents (OS-level)
6. Backups and exports

### Adversaries

- **A1:** Offline attacker with vault file copy
- **A2:** Thief with device (may access OS account)
- **A3:** Local unprivileged attacker (other OS user)
- **A4:** Network attacker (only if user enables networking)
- **A5:** Malware on user machine (partial threat)

### Attack surfaces

- Vault parser and migrations
- KDF parameter parsing
- Electron IPC boundary (renderer ↔ main)
- Clipboard
- Import parsers (CSV/JSON)
- Update path and dependencies

### In-scope threats

- Offline brute force
- Tampering with vault file
- Leaks via logs/caches/plaintext exports
- Renderer compromise escalating via IPC
- Supply-chain compromise

### Out-of-scope threats (explicit)

- Fully compromised OS (kernel-level malware) can exfiltrate secrets at entry time or from memory; v0.1.0 applies best-effort mitigations but MUST NOT claim to defeat this.
- Physical RAM extraction attacks are not comprehensively mitigated.
- Hardware/backdoored CPU/OS trust is assumed.

### Mitigations table

| Threat                    | Mitigation(s)                                                                              | Section |
| ------------------------- | ------------------------------------------------------------------------------------------ | ------- |
| Offline brute force       | Argon2id defaults + tunability; master password minimums; optional keychain off by default | G, L    |
| Vault tampering           | AEAD auth + strict parsing + AAD binding                                                   | G, H    |
| Corruption/partial writes | Atomic write; encrypted backups; recovery tooling                                          | H, D10  |
| Secret leaks in logs      | Redaction + strict logging policy                                                          | N       |
| Clipboard monitoring      | Auto-clear; no auto-copy; warnings                                                         | D4, K   |
| Renderer attacks          | Context isolation, no nodeIntegration, allowlisted IPC, CSP                                | I, K    |
| Import parser attacks     | Strict validation; size limits; fuzz tests                                                 | D7, O   |
| Supply chain              | Locked deps, SBOM, signed releases, provenance                                             | P       |

### Residual risks + user education

- Weak master password remains primary risk; UI MUST educate and provide strength guidance.
- Clipboard may be monitored; users MUST be warned.
- Plaintext exports are inherently risky; explicit warnings and confirmations required.

---

## G. Cryptography and Key Management (implementation-grade)

### G0. “Known unknown” #1 — Crypto core language + integration

#### Options

1. **Rust core library + Rust CLI + Node/Electron via N-API**
2. Go core + Go CLI + Node via cgo wrapper
3. TypeScript-only crypto (WebCrypto/libsodium-wrappers)
4. C/C++ core (libsodium) + bindings

#### Decision matrix

| Option       | Security | Performance | Cross-platform |      DX | Auditability | Maturity | Electron/Node integration |     Risk |
| ------------ | -------: | ----------: | -------------: | ------: | -----------: | -------: | ------------------------: | -------: |
| Rust + N-API |     High |        High |           High |     Med |         High |     High |                      High |  Low–Med |
| Go + cgo     | Med–High |        High |            Med |     Med |          Med |     High |                       Med |      Med |
| TS-only      |      Med |         Med |           High |    High |          Med |     High |                      High | Med–High |
| C/C++        |     High |        High |            Med | Low–Med |          Med |     High |                       Med |     High |

#### Recommended default (v0.1.0)

**Rust core** implementing crypto, vault I/O, parsers, migrations; reused by:

- **CLI:** native Rust binary.
- **GUI:** Electron **main process** calls Rust via **Node N-API** addon.

**Assumptions**

- Contributors can support Rust + Node toolchain.
- Rust crates selected are maintained and reviewable.
- Minimizing JS crypto reduces foot-guns and improves uniformity.

**Alternative (later / build option)**

- TS-only “portable mode” using WebCrypto for environments where native addons are undesirable (v0.2+), with separate security review.

---

### G1. Cryptographic primitives (MUST use exactly these in v0.1.0)

- KDF: **Argon2id v1.3**
- AEAD: **XChaCha20-Poly1305** (24-byte nonce, 32-byte key)
- HKDF: **HKDF-SHA256**
- TOTP: HMAC-SHA1 (default), SHA256, SHA512 per RFC 6238

### G2. KDF parameters (defaults + bounds)

Defaults (desktop):

- Memory: **256 MiB** (262,144 KiB)
- Time cost: **3**
- Parallelism: **1**
- Output length: **32 bytes**

Bounds:

- Memory: 64–1024 MiB (unless explicitly overridden)
- Time: 1–10
- Parallelism: 1–4

The KDF parameters MUST be stored in the vault header. The app SHOULD offer calibration targeting ~1 second unlock time.

### G3. Master password handling

- Master password MUST be NFKC-normalized then UTF-8 encoded.
- Master password MUST NOT be stored in plaintext anywhere.
- Password entry MUST not echo.
- Minimum requirement: at least 12 characters OR at least 4 words in passphrase mode.
- UI SHOULD provide offline strength guidance.

### G4. Key hierarchy

- `salt`: 16 random bytes (header)
- `kdf_key`: 32 bytes output of Argon2id
- `kek`: 32 bytes via HKDF from `kdf_key`
- `vault_key`: 32 random bytes generated at vault creation
- `payload_key`: 32 bytes via HKDF from `vault_key`

Derivation:

- `kdf_key = Argon2id(NFKC(master_password_utf8), salt, m, t, p, out=32)`
- `kek = HKDF-SHA256(ikm=kdf_key, salt=NULL, info="NPW:v1:KEK", L=32)`
- `payload_key = HKDF-SHA256(ikm=vault_key, salt=NULL, info="NPW:v1:PAYLOAD", L=32)`

### G5. Encryption and authentication

- Envelope: AEAD encrypt CBOR envelope plaintext with `kek` and random `env_nonce`.
- Payload: AEAD encrypt CBOR payload plaintext with `payload_key` and random `payload_nonce`.
- Both envelope and payload MUST authenticate header bytes as AAD (Section H4).

### G6. Randomness

- All salts/nonces/password generations MUST use OS CSPRNG.
- Rust MUST use `getrandom()`-backed RNG.

### G7. Key rotation / change master password

- Changing master password MUST:
    - derive new `kdf_key`/`kek` with a new random salt,
    - re-encrypt envelope containing `vault_key`,
    - MUST NOT require re-encrypting payload by default.
- Optional `--rotate-vault-key` MAY force full payload re-encryption with a new random `vault_key`.

### G8. Secure memory handling

Hard requirements:

- Rust core MUST zeroize secret keys and decrypted buffers as soon as practical.
- Secrets MUST NOT be logged.

Best-effort:

- Attempt to lock memory pages containing secrets (`mlock`/`VirtualLock`) where available; failure MUST NOT crash.
- Electron renderer SHOULD not receive secrets unless explicitly needed for display.

### G9. Metadata leakage minimization

- Header MUST contain only unlock-critical info.
- Vault name, item counts, timestamps, and user identifiers MUST NOT be plaintext in header.

### G10. TOTP seeds

- Seeds MUST be encrypted within payload.
- Revealing seed in GUI MUST require explicit confirmation.

### G11. Passkeys/WebAuthn private keys

- v0.1.0 MUST NOT store passkey private keys.
- Only metadata references are supported.

---

## H. Data Model and Storage Format

### H0. “Known unknown” #3 — Attachments in v0.1.0

#### Options

1. **Defer attachments** (store references only)
2. Encrypted external attachments (separate encrypted files)
3. Embedded attachments inside vault (chunked)
4. Hybrid

#### Decision matrix

| Option             | Security | Performance | Cross-platform |      DX | Auditability | Maturity | Electron fit | Risk |
| ------------------ | -------: | ----------: | -------------: | ------: | -----------: | -------: | -----------: | ---: |
| Defer              |     High |        High |           High |    High |         High |     High |         High |  Low |
| External encrypted |     High |        High |           High |     Med |          Med |      Med |         High |  Med |
| Embedded chunked   |     High |         Med |           High |     Med |          Med |      Med |          Med | High |
| Hybrid             |     High |         Med |            Med | Low–Med |          Med |      Med |          Med | High |

#### Recommended default (v0.1.0)

**Defer encrypted binary attachments.** v0.1.0 supports optional **file reference fields** (paths/URIs) with warnings that references are not encrypted and may reveal metadata.

**Alternative (v0.2+)**
Encrypted external attachments with chunked AEAD and transactional semantics.

---

### H1. Vault file format overview

- File extension: `.npw`
- Single vault per file
- Container format version: `1`
- Payload schema version: `schema = 1` inside payload

### H2. Binary layout (v1)

All integer fields are little-endian.

File structure:

```text
[Header (plain)] [Envelope ciphertext] [Payload ciphertext]
```

Header fields:

```text
offset size  field
0      4     magic = "NPW1"
4      2     format_version = 0x0001
6      2     header_flags (bitset; v1 all zero)
8      1     kdf_id (1 = Argon2id)
9      1     aead_id (1 = XChaCha20-Poly1305)
10     2     reserved (zero)
12     4     argon_m_kib (u32)
16     4     argon_t (u32)
20     4     argon_p (u32)
24     2     salt_len (u16) MUST be 16
26     16    salt
42     2     env_nonce_len (u16) MUST be 24
44     24    env_nonce
68     4     env_ct_len (u32) includes tag
72     N     env_ciphertext
72+N   2     payload_nonce_len (u16) MUST be 24
74+N   24    payload_nonce
98+N   8     payload_ct_len (u64) includes tag
106+N  M     payload_ciphertext
```

All length fields MUST be validated against file size and sane caps:

- `env_ct_len` MUST be between 48 and 4096 bytes (envelope is small).
- `payload_ct_len` MUST be <= 256 MiB in v0.1.0 (configurable build constant).

### H3. Envelope plaintext (CBOR)

Decrypted with `kek`. CBOR map:

- `vault_id`: 16 bytes random
- `vault_key`: 32 bytes random
- `created_at`: unix seconds
- `kdf_hint`: optional string (non-identifying)
- `reserved`: optional bytes

### H4. AAD binding

- Envelope AAD: header bytes from offset 0 through end of `env_ct_len` field (offset 72), excluding ciphertext.
- Payload AAD: header bytes from offset 0 through end of `payload_ct_len` field, excluding payload ciphertext.

### H5. Payload plaintext (CBOR)

Top-level map:

- `schema`: 1
- `app`: `{ name, version }`
- `updated_at`: unix seconds
- `items`: array of items
- `tombstones`: array
- `settings`: vault-local settings (encrypted)

Item schemas are defined in Section H (as earlier), including `login`, `note`, `passkey_ref`.

### H6. Serialization and parsing rules

- CBOR decoder MUST:
    - reject duplicate keys,
    - enforce types and bounds,
    - reject unknown required fields,
    - allow unknown optional fields only under a `reserved` namespace if present.
- Import parsers MUST enforce size limits (Section O).

### H7. Migration strategy

- App MUST support reading older payload `schema` versions within same container format and migrating forward.
- Migration MUST be transactional and crash-safe.

### H8. Indexing/search

- No persistent plaintext index. In-memory index built on unlock only.

### H9. Atomic writes and backups

Save algorithm MUST:

1. Acquire exclusive file lock.
2. Read current vault to verify decryptable (optional but recommended).
3. Write temp file with secure permissions.
4. `fsync` temp file.
5. Rotate backups (copy current vault to backup).
6. Atomic rename temp to vault.
7. Best-effort directory `fsync`.
8. Release lock.

### H10. Secure file permissions

- Unix-like: vault and backups MUST be `0600`.
- Windows: file ACL MUST allow only current user.
- App MUST warn if vault path is in a shared/world-readable directory.

### H11. Encrypted export format (`.npwx`)

Encrypted export MUST reuse the same container format (`NPW1`) with:

- `app.name` set to `"npw-export"`
- payload includes an `export_meta` map:
    - `exported_at`, `source_vault_id` (if known), `redacted` boolean
      The export password MUST be independent and uses its own salt/KDF parameters.

---

## I. Application Architecture

### I0. High-level component diagram (ASCII)

```text
+----------------------------+          +---------------------------+
|            CLI             |          |        Electron GUI       |
|  (Rust binary)             |          |                           |
|  +----------------------+  |          |  +---------------------+  |
|  | core (crypto+vault)  |  |          |  | Renderer (UI)       |  |
|  | storage+domain       |  |          |  | - no vault IO       |  |
|  +----------+-----------+  |          |  +----------+----------+  |
|             |              |          |             | IPC allowlist|
|        .npw vault          |          |  +----------v----------+  |
+-------------+--------------+          |  | Main process        |  |
                                       |  | - session mgr       |  |
                                       |  | - clipboard         |  |
                                       |  +----------+----------+  |
                                       |             | N-API       |
                                       |  +----------v----------+  |
                                       |  | Rust addon (core)   |  |
                                       |  +---------------------+  |
                                       +---------------------------+
```

### I1. Module responsibilities

- **core (Rust library)**
    - Vault format read/write, crypto, schema validation, migrations.
    - Import/export transforms (but NOT GUI dialogs).
    - TOTP generation.
- **storage (Rust)**
    - File locking, atomic writes, backups.
- **domain (Rust)**
    - Item validation, search, tag normalization.
- **CLI (Rust)**
    - Prompts, JSON output, exit codes, config.
- **Electron main (TS)**
    - Vault selection, session lifecycle, IPC handlers, clipboard, OS integration.
    - Calls Rust addon for all sensitive operations.
- **Electron renderer (TS/React/Vue/etc.)**
    - UI only; receives minimal non-secret data by default.

### I2. Electron hardening (MUST)

- `contextIsolation: true`
- `nodeIntegration: false`
- `sandbox: true` for renderer where feasible (platform constraints noted).
- CSP MUST be set to disallow remote content:
    - `default-src 'self'`
    - `script-src 'self'`
    - `img-src 'self' data:`
    - `connect-src 'none'` (unless user enables opt-in networking, then restrict to specific endpoints)
- The app MUST load UI from `file://` or packaged resources only.

### I3. IPC allowlist (example)

Renderer may call:

- `vault.listRecent()`
- `vault.openDialog()`
- `vault.unlock({ path, method })`
- `vault.lock()`
- `items.list({ filter })`
- `items.get({ id, reveal: false })`
- `items.copyField({ id, field })`
- `items.create/update/delete(...)`
- `totp.show({ id })` (returns code only if UI needs to display; otherwise copy handled in main)
- `settings.get/set(...)`

Main process MUST validate:

- types, lengths, and allowed values
- item IDs are UUID strings
- field names are from an enum

### I4. Dependency policy

- Lockfiles MUST be committed (Cargo.lock + npm/pnpm lockfile).
- CI MUST run dependency audits (Section O/P).
- Crypto MUST live in Rust core; JS MUST NOT implement vault encryption.

---

## J. CLI Specification

### J0. CLI name

- Binary: `npw`

### J1. Global flags

- `--vault <path>`
- `--json`
- `--no-color`
- `--quiet`
- `--config <path>`
- `--non-interactive`

### J2. Exit codes

- `0` success
- `1` general error
- `2` invalid usage
- `3` vault locked / no session
- `4` auth failed
- `5` vault file locked
- `6` corrupted/parse error
- `7` network disabled
- `8` permission denied

### J3. JSON output contract

All JSON outputs MUST include:

- `schema_version` (int)
- `ok` (bool)
- `error` object on failure

### J4. Secure prompting

- Password MUST NOT be accepted via CLI arg.
- Password MAY be accepted from stdin only with `--non-interactive` and explicit documentation of risk.
- Prompts MUST disable echo and clear buffers where feasible.

### J5. Commands (summary)

- Vault: `vault init|unlock|lock|status|check|change-password|backup`
- Items: `item add|get|list|edit|delete|restore|copy`
- Search: `search`
- TOTP: `totp add|show|copy`
- Passkeys: `passkey list|show|open-site`
- Import/Export: `import csv|bitwarden-json`, `export csv|json|encrypted`
- Config: `config get|set|list`

---

## K. GUI Specification (Electron)

### K0. Screen list (required for v0.1.0)

1. Vault Picker (recent vaults + open/create)
2. Create Vault
3. Unlock Vault
4. Main List (items + search/filter)
5. Item Detail (login/note/passkey_ref)
6. Add/Edit Item
7. Import/Export
8. Settings (security + preferences)
9. Backup/Recovery screen (restore from backup)

### K1. Vault Picker flow

**Wireframe**

```text
[NAME PENDING]
Recent Vaults:
- Personal (~/Secrets/personal.npw)  [Open]
- Work (~/Vaults/work.npw)          [Open]

[Create New Vault]  [Open Existing Vault]
```

Requirements:

- MUST display paths (to avoid confusion).
- MUST allow removing a vault from recent list without deleting file.
- Recent list MUST be stored in config (non-secret).

### K2. Create Vault flow

- MUST prompt for:
    - vault file location,
    - master password (twice),
    - optional KDF calibration (recommended toggle).
- MUST show password guidance and minimum requirements.
- MUST create file with secure permissions.

### K3. Unlock flow

- MUST support unlocking by master password.
- MAY support “Quick Unlock” via OS keychain only if enabled for that vault (Section L1).
- MUST show:
    - vault path,
    - unlock method,
    - failure message that does not reveal sensitive detail.
- Auto-lock timer MUST start after unlock.

### K4. Main List behavior

**Wireframe**

```text
[Search box..................] [Filter: All v]
Favorites ⭐
- Example.com        user@example.com   [TOTP badge]
- VPN                aman               [ ]

All Items
- ...
```

Requirements:

- MUST not display passwords by default.
- SHOULD show username and URL (configurable) after unlock.
- MUST support filters: type, tag, favorite.
- MUST support sorting: title, updated time.

### K5. Item Detail (Login)

Fields:

- Title, URLs, Username(s)
- Password field:
    - default: masked
    - actions: [Copy] [Reveal] [Generate & Replace]
- TOTP:
    - show 6-digit code + countdown ring/text
    - actions: [Copy code]
    - MUST not display TOTP secret by default
- Notes (collapsed by default if long)
- Tags, custom fields

Security UX:

- Reveal password MUST require explicit user action and SHOULD auto-hide after 30 seconds.
- Copy actions MUST show a toast that clipboard will clear in N seconds.

### K6. Item Detail (Secure Note)

- Body editor with plaintext (no rich text).
- Copy selected text action MAY be supported.

### K7. Passkey Reference Item UI

- Display `rpId`, origins, username/display name.
- Actions:
    - Open origin in browser
    - Open OS passkey manager (best effort)
- MUST clearly label: “This app does not store passkeys. This is a reference entry.”

### K8. Add/Edit item flows

- MUST validate required fields (title).
- MUST normalize tags (trim, collapse whitespace).
- Save MUST be atomic and show error if vault locked.

### K9. TOTP QR import

- Approach:
    - Use `getUserMedia` camera access in renderer **only** on the QR import screen.
    - QR decoding MUST happen locally (no network).
    - If camera denied/unavailable, MUST provide fallback: paste `otpauth://` URI or base32 secret.
- Security:
    - Camera stream MUST be stopped immediately after scan/cancel.
    - No frames MUST be persisted.

### K10. Settings screen (security critical)

Settings MUST include:

- Auto-lock timeout (default 5 minutes; range 1–60)
- Lock on suspend/lock screen (default on)
- Clipboard clear timeout (default 30 seconds)
- “Reveal secrets requires confirmation” (default on)
- OS keychain “Quick Unlock” per vault (default off)
- Networking toggles (if compiled in; default off)

### K11. Accessibility requirements (GUI)

- All interactive elements MUST be reachable by keyboard.
- Tab order MUST be logical.
- Screen reader labels MUST exist for inputs and buttons.
- Error messages MUST be announced (ARIA live region or equivalent).

---

## L. Cross-Platform OS Integration

### L0. “Known unknown” #2 — OS keychain usage

#### Options

1. **No keychain usage** (always require master password)
2. **Store master password in keychain** (auto-unlock)
3. **Store derived unlock material** (e.g., `vault_key` or `kek`) in keychain for “Quick Unlock”
4. Store only non-secret config in keychain (rarely useful)

#### Decision matrix

| Option                    |          Security | Performance | Cross-platform fit |   DX | Auditability | Ecosystem maturity | Electron/Node integration | Risk |
| ------------------------- | ----------------: | ----------: | -----------------: | ---: | -----------: | -----------------: | ------------------------: | ---: |
| No keychain               |              High |         Med |               High | High |         High |               High |                      High |  Low |
| Store master pw           |           Low–Med |        High |                Med |  Med |          Med |               High |                      High | High |
| Store `vault_key`/derived | Med–High (opt-in) |        High |           Med–High |  Med |          Med |               High |                  Med–High |  Med |
| Non-secret only           |              High |         Low |               High |  Low |         High |               High |                      High |  Low |

#### Recommended default (v0.1.0)

**Option 3 as an opt-in feature, OFF by default:** store **`vault_key`** (32 bytes) in OS keychain to allow “Quick Unlock”.

**Rationale**

- Preserves offline protection of vault file when keychain is unavailable (attacker with only file still faces Argon2id).
- Avoids storing master password.
- Provides convenience for users who accept OS-account trust.

**Security warning (MUST)**

- Enabling Quick Unlock means anyone who can access the OS user session/keychain may unlock the vault without the master password. GUI MUST present this warning and require explicit confirmation.

**Alternative (build option / future)**

- Option 1 (no keychain support) as a build profile for high-assurance environments.
- Option 2 MUST NOT be implemented in v0.1.0.

**Assumptions**

- OS keychains are reasonably protected by OS account controls.
- Users understand convenience vs security tradeoff via UX warnings.

#### Keychain integration requirements (v0.1.0)

- Keychain entries MUST be per-vault, keyed by `vault_id`.
- Stored secret: `vault_key` base64 (or raw bytes if API supports).
- Label/metadata MUST NOT include sensitive user info; use `[NAME PENDING] Vault Key (<vault_id_prefix>)`.
- Disabling Quick Unlock MUST delete the keychain entry.
- If keychain is unavailable (e.g., Linux headless without Secret Service), the app MUST disable the toggle and explain.

Platform notes:

- Windows: Credential Manager (Generic Credential) under current user.
- macOS: Keychain item under current user.
- Linux: Secret Service (freedesktop.org) via GNOME Keyring / KWallet; if unavailable, feature disabled.

### L1. Clipboard timeout implementation

- GUI: use Electron clipboard API in main process.
- CLI: use Rust clipboard crate; MUST document limitations on Wayland.
- Clipboard clear algorithm:
    - Store a hash (SHA-256) of the copied bytes plus a random per-copy token.
    - On timeout, read clipboard; if it matches exact copied value, clear it; else do nothing.

### L2. Auto-start / tray behavior

- v0.1.0: **No auto-start** and **no tray resident mode** by default.
- GUI MAY support “minimize to tray” later (v0.2+) with careful security review.

### L3. File dialogs and sandboxing

- GUI MUST use OS file dialogs for vault open/create.
- Renderer MUST not receive arbitrary filesystem paths unless needed for display; main retains canonical path.

### L4. Code signing/notarization requirements

- Windows: release installers/binaries MUST be Authenticode-signed.
- macOS: app MUST be code-signed and notarized.
- Linux: AppImage SHOULD be signed (detached signature) and checksums published.

---

## M. Networking (Default: none)

### M0. “Known unknown” #4 — Opt-in network features

#### Options

1. **No networking at all in v0.1.0** (compile-time excluded)
2. Opt-in **HaveIBeenPwned (HIBP) Pwned Passwords** checks using k-anonymity
3. Opt-in update check (no auto-download) against a release endpoint
4. Both 2 and 3, opt-in

#### Decision matrix

| Option       | Security |  Privacy | Performance | Cross-platform |   DX | Auditability | Maturity |     Risk |
| ------------ | -------: | -------: | ----------: | -------------: | ---: | -----------: | -------: | -------: |
| None         |     High |     High |        High |           High | High |         High |     High |      Low |
| HIBP k-anon  | Med–High | Med–High |         Med |           High |  Med |          Med |     High |      Med |
| Update check | Med–High |      Med |        High |           High |  Med |          Med |     High |      Med |
| Both         |      Med |      Med |         Med |           High |  Med |          Med |     High | Med–High |

#### Recommended default (v0.1.0)

**Option 1: No networking in v0.1.0, enforced by build configuration.**

**Assumptions**

- Networking increases attack surface (MITM, dependency sprawl, privacy concerns).
- Local-first product launch prioritizes correctness and security fundamentals.

**Alternative (v0.2+ or optional build)**

- Implement HIBP k-anonymity checks and/or update checks as separately opt-in modules behind compile-time feature flags and runtime toggles.

### M1. Enforcement (v0.1.0 MUST)

- Default builds MUST:
    - not include HTTP client dependencies in Rust core/CLI,
    - not call `fetch`, `XMLHttpRequest`, or open remote URLs except when user explicitly clicks “Open site” for a stored URL (which launches external browser).
- Electron renderer CSP MUST set `connect-src 'none'`.
- CI MUST include a test that scans built JS bundles for disallowed network primitives (best-effort) and fails if found outside allowlisted modules.

### M2. If networking is implemented later (spec for future compatibility)

If a networking feature is compiled in, it MUST:

- Be **opt-in** with explicit UX gating.
- Send the minimum data required; MUST NOT send vault contents, emails, or identifiers.
- Use TLS with system trust store; certificate pinning is NOT required but MAY be added with careful operational planning.
- Respect proxy environment variables only if user enables “Use system proxy”.

#### HIBP k-anonymity (future)

- Compute SHA-1 of password (per HIBP protocol).
- Send only first 5 hex chars prefix to endpoint.
- Use padding header if supported by endpoint to reduce response-size leakage.
- Compare suffixes locally; do not send full hash or password.

---

## N. Observability, Telemetry, and Logging

### N1. Logging requirements

- Default log level MUST be `WARN` and above.
- Logs MUST NEVER include:
    - master password,
    - derived keys,
    - vault_key,
    - passwords, TOTP secrets, decrypted note bodies,
    - full item records.
- Errors MUST be redacted:
    - Item IDs MAY be logged.
    - Vault path MAY be logged but SHOULD be redacted in “privacy mode”.

### N2. Debug logging

- Debug logs MAY be enabled via explicit user setting or env var:
    - CLI: `NPW_LOG=debug`
    - GUI: setting “Enable debug logging” (requires restart)
- Debug logs MUST still redact secrets. Redaction rules MUST be unit-tested.

### N3. Telemetry policy

- v0.1.0 MUST have **no telemetry**.
- Crash reporting MUST be off by default. If implemented later, MUST be opt-in and must scrub secrets.

---

## O. QA, Test Plan, and Security Validation

### O1. Test layers

- **Unit tests (Rust core)**
    - KDF parameter parsing bounds
    - Envelope/payload encryption-decryption roundtrips
    - CBOR schema validation
    - TOTP vectors (RFC 6238 test cases)
- **Integration tests**
    - Vault create → write → reopen across processes
    - Backup rotation correctness
    - File locking behavior (best-effort cross-platform)
- **E2E tests**
    - CLI workflows
    - GUI smoke tests (Playwright/Spectron alternative) with mocked IPC

### O2. Property tests (MUST)

- Vault roundtrip: random item sets serialize→encrypt→decrypt→parse equals original (modulo timestamps).
- AEAD invariants: tampering any header byte in AAD MUST cause decrypt failure.
- Import/export: export→import roundtrip preserves expected fields.

### O3. Fuzzing targets (MUST)

- Vault header parser
- CBOR payload parser
- Migration logic
- CSV/JSON import parsers

Fuzzing SHOULD run in CI on nightly schedule and on release branches.

### O4. Cross-platform CI matrix (MUST)

- Windows latest (x64)
- macOS latest (arm64 and/or x64)
- Ubuntu 22.04 (x64)

CI tasks:

- Build CLI
- Build Electron app
- Run unit/integration tests
- Lint/format checks
- Dependency audits
- SBOM generation (release)

### O5. Static analysis and linting

- Rust: `clippy` with deny warnings on CI; `rustfmt`.
- TS: ESLint + typecheck; formatting via Prettier.
- Security linters: check for dangerous Electron settings and CSP.

### O6. Security review checklist (pre-release gate)

- Verify KDF params and storage
- Verify AEAD AAD binding
- Verify no secrets in logs
- Verify renderer isolation, CSP, IPC allowlist
- Verify update/network disabled by default
- Verify file permissions and backup behavior
- Verify dependency audit results acceptable

### O7. Pre-release security gates for v0.1.0 (MUST)

- At least 1 internal security review sign-off.
- All fuzz targets run with no new crashes on release candidate.
- Reproducible build verification performed (Section P).

---

## P. Release Engineering and Supply Chain Security

### P1. Reproducible builds stance

- v0.1.0 SHOULD be reproducible “where feasible”:
    - CLI: reproducible builds SHOULD be achievable with locked Rust toolchain and Cargo.lock.
    - GUI: reproducibility is harder due to Electron packaging; project MUST document exact build environment and dependencies to approximate reproducibility.
- Build instructions MUST include pinned toolchain versions.

### P2. Signing requirements

- All release artifacts MUST be signed:
    - CLI: detached signatures + checksums.
    - GUI: platform-native signing (Windows Authenticode, macOS notarization).
- Release page MUST publish SHA-256 checksums.

### P3. SBOM generation

- Releases MUST include SBOMs:
    - Rust dependencies (SPDX or CycloneDX)
    - npm dependencies (CycloneDX recommended)
- SBOMs MUST be generated in CI and attached to release artifacts.

### P4. Provenance / SLSA stance

- v0.1.0 SHOULD generate build provenance attestation (SLSA level 2 target).
- CI MUST be configured to prevent secret leakage and restrict release signing keys.

### P5. Electron update mechanism

- v0.1.0 MUST NOT auto-update without explicit opt-in and network enablement.
- If later implemented:
    - update manifests MUST be signed,
    - downloads MUST be verified before install,
    - update channel MUST be configurable (stable/beta),
    - rollback strategy MUST be documented.

---

## Q. Documentation Deliverables

### Q1. User documentation (MUST)

- Getting started (create/unlock/lock)
- Backups and recovery
- Import/export guide with warnings
- TOTP guide
- Passkey reference explanation (what it is and is not)
- Threat model summary (plain language)
- Security defaults and how to change them

### Q2. Contributor documentation (MUST)

- Dev setup (Rust + Node toolchain)
- Architecture overview (core/storage/gui boundaries)
- Vault format spec link (this document)
- Coding standards and review process

### Q3. Security policy (MUST)

- Vulnerability reporting instructions (email or platform)
- Supported versions
- Disclosure timeline target (e.g., acknowledge within 7 days, fix within 90 days typical)
- Credit policy

---

## R. Milestones and Delivery Plan

### Phase 1 — Core vault + CLI (security foundation)

- Implement vault format v1, crypto, atomic writes, backups
- Implement core domain model + search
- Implement CLI commands for vault and items
- Unit/property tests + fuzz harness

### Phase 2 — Electron GUI + IPC hardening

- Implement main/renderer split, preload API, allowlisted IPC
- Implement vault picker/create/unlock, list/detail/add/edit
- Clipboard handling and auto-lock
- Accessibility baseline

### Phase 3 — Import/export + TOTP + passkey references

- CSV + Bitwarden JSON import
- Redacted exports + encrypted export
- TOTP QR scan flow
- Passkey reference item UI/actions

### Phase 4 — Release hardening

- Cross-platform CI green
- Signing pipelines
- SBOM generation
- Security review gates
- Documentation completion

**Definition of Done (v0.1.0)**

- Meets all acceptance criteria (Section S)
- Signed release artifacts published with checksums
- Security review completed
- No critical known vulnerabilities in dependencies (document exceptions)

---

## S. Acceptance Criteria (v0.1.0)

Release readiness checklist (MUST all pass):

### Vault/crypto

- [ ] Vault create/unlock/lock works offline on Windows/macOS/Linux
- [ ] Wrong password fails with exit code 4 (CLI) and safe UI error (GUI)
- [ ] Tampering with header/ciphertext causes decrypt failure
- [ ] Change master password works and preserves items
- [ ] Optional full rotation re-encrypts payload successfully

### Data integrity/reliability

- [ ] Atomic save verified via crash simulation test
- [ ] Rolling backups created and restore works
- [ ] File locking prevents concurrent writes (CLI+GUI)

### Features

- [ ] Login + note CRUD complete in CLI and GUI
- [ ] Search/filter/favorites work post-unlock
- [ ] Password generator meets requirements
- [ ] Clipboard auto-clear works as specified
- [ ] TOTP add/show/copy works; QR import works in GUI
- [ ] Passkey reference items supported and clearly labeled

### Security posture

- [ ] Renderer hardened (contextIsolation, no nodeIntegration, CSP)
- [ ] IPC allowlist enforced and tested
- [ ] No secrets in logs (tested via log redaction tests)
- [ ] Networking disabled by default and enforced

### Supply chain / release

- [ ] Signed artifacts + published checksums
- [ ] SBOMs generated and published
- [ ] Dependency audits run and reviewed
- [ ] Documentation deliverables complete

---

## T. Open Questions / Future Work

- Encrypted attachments (external files) design and transactional semantics (v0.2+).
- Sync design (opt-in, privacy-preserving, potentially third-party backends).
- Browser extension/autofill (high risk, separate threat model).
- Biometric unlock that binds keychain item to biometric prompt (macOS/Windows) with careful UX and security review.
- Secret “session lock” with memory-only reauth (PIN) separate from master password.
- Hardware key integration for 2FA code storage (not typical for TOTP but consider).

---

## U. Decision Log (v0.1.0)

1. **Crypto core language**: Rust core + N-API addon for Electron; Rust CLI.
    - Rationale: security, performance, auditability, consistent crypto implementation.
    - See: [G0](#g0-known-unknown-1--crypto-core-language--integration), [I](#i-application-architecture)

2. **OS keychain usage**: Opt-in Quick Unlock storing `vault_key` in OS keychain; OFF by default.
    - Rationale: convenience without storing master password; preserves file-only offline protection.
    - See: [L0](#l0-known-unknown-2--os-keychain-usage)

3. **Attachments**: Deferred for v0.1.0; only file references with warnings.
    - Rationale: reduces complexity and data-loss/security risks at launch.
    - See: [H0](#h0-known-unknown-3--attachments-in-v010)

4. **Networking**: None in v0.1.0; enforced by build and CSP; optional future opt-in.
    - Rationale: reduce attack surface and privacy risk; align with local-first launch.
    - See: [M0](#m0-known-unknown-4--opt-in-network-features)

5. **Passkeys/WebAuthn**: Reference-only; no private key storage.
    - Rationale: aligns with platform authenticator realities and avoids unsafe export assumptions.
    - See: [D8](#d8-passkeys--webauthn-support-definition-v010), [G11](#g11-passkeyswebauthn-private-keys)

---

## V. Security Defaults Summary (One Page)

**Vault/crypto**

- KDF: Argon2id, default \(m=256\) MiB, \(t=3\), \(p=1\)
- AEAD: XChaCha20-Poly1305
- Header binds via AAD; strict parsing; no plaintext metadata beyond unlock parameters

**App behavior**

- Networking: **disabled** (no HTTP deps; CSP `connect-src 'none'`)
- Telemetry: **none**
- Auto-lock: **5 minutes** inactivity (configurable)
- Lock on suspend/screen lock: **on** (best effort Linux)
- Clipboard clear: **30 seconds** (configurable)
- Reveal password: requires explicit action; SHOULD auto-hide after 30 seconds
- OS keychain Quick Unlock: **off by default**; explicit warning required to enable
- Exports: redacted by default; plaintext secrets require explicit flag + warning
- Backups: encrypted rolling backups, keep **10** by default

---

## License (Project Requirement)

### License options considered

1. **Apache-2.0** (permissive + explicit patent grant)
2. **MIT** (simple permissive)
3. **GPL-3.0-or-later** (strong copyleft)

### Recommended license (v0.1.0)

**Apache License 2.0**.

**Rationale**

- Encourages broad adoption and contributions (including corporate).
- Explicit patent grant improves downstream safety.
- Compatible with typical Rust and Electron ecosystem dependencies.

**Alternative**

- MIT for maximal simplicity (slightly weaker patent posture).
- GPL-3.0-or-later if the project explicitly wants copyleft guarantees (would affect ecosystem adoption and integration).
