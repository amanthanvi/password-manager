# `npw` — v0.1.0 Implementation Specification (SPEC.md)

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
- [K. GUI Specification (Electron + Svelte)](#k-gui-specification-electron--svelte)
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
- [W. Risk Register](#w-risk-register)
- [License (Project Requirement)](#license-project-requirement)

---

## A. Executive Summary

`npw` is a **local-first**, privacy-preserving **FOSS password manager** for Windows/macOS/Linux with:

- A **cross-platform CLI** for scripting, automation, and power users.
- A **cross-platform Electron GUI** (Svelte renderer) for mainstream users.

### Primary value proposition

- **No cloud account required.**
- **Offline-first**: core functionality works without networking.
- **Security by design**: strong KDF (Argon2id, 3–5s target), authenticated encryption, hardened IPC boundaries, and supply-chain controls.
- **Standards-aware passkey/WebAuthn support**: **organize and "use" passkeys safely without attempting to export private keys** that are typically bound to platform authenticators.

### v0.1.0 headline features

- Encrypted vault file format (`.npw`) with versioning, safe migration, and encrypted search index.
- Login items, secure notes, TOTP (RFC 6238) seeds + code generation + QR export.
- Passkey/WebAuthn **reference items** + OS-integrated "open/manage" actions.
- Import/export (CSV + Bitwarden JSON import with duplicate detection; redacted + encrypted export).
- Scriptable CLI with stable `--json` output and deterministic exit codes.
- Electron GUI (Svelte) with secure UX defaults.
- Optional OS keychain integration for convenience **only when explicitly enabled**.
- Password generator with both charset-random and diceware passphrase modes.

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
- Formal accessibility compliance (WCAG or otherwise) in v0.1.0 or foreseeable future.

### Out of scope for v0.1.0

- End-to-end sync across devices.
- Encrypted binary attachments stored inside the vault (see Section H0).
- Team sharing, multi-user access control, enterprise policy controls.
- Custom WebAuthn authenticator implementation or exporting/importing passkey private keys.
- Custom fields on items (strict schemas only in v0.1.0).

---

## C. Personas and Use Cases

### Personas

1. **Everyday User (GUI-first)**
    - Wants to store logins, generate passwords, and copy TOTP codes.
    - Needs "simple and safe" defaults and clear warnings.
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
    - Success: logins/notes/TOTP fields imported with mapping report; suspected duplicates flagged for user review; no plaintext export unless user confirms.
5. **"Use" a passkey safely**
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

1. **Login item** (see H5a for schema)
2. **Secure note** (see H5b for schema)
3. **TOTP** (as part of login item by default; MAY be standalone later) (see H5c for schema)
4. **Passkey / WebAuthn reference** (see H5d for schema)

CRUD requirements:

- Items MUST have a stable unique ID (UUIDv4).
- Updates MUST be atomic and crash-safe.
- Deleting MUST support "soft delete" (tombstone) until compaction (v0.2+). In v0.1.0, tombstones MUST exist in payload.
- v0.1.0 uses strict, fixed schemas per item type. No user-defined custom fields.

### D3. Password generation

The system MUST provide a CSPRNG-backed password generator with **two modes**:

#### Charset-random mode (default for site passwords)

- Length (default 20; min 8; max 128).
- Character sets: lowercase, uppercase, digits, symbols (configurable).
- Optional "avoid ambiguous characters" flag (`0`/`O`, `l`/`1`, `I`).
- Production builds MUST use OS CSPRNG; test builds MAY allow deterministic seeds.

#### Diceware passphrase mode (default for master password creation)

- Word count (default 5; min 4; max 10).
- Separator (default `-`; configurable: `-`, `.`, `_`, ` `, or custom single character).
- Optional digit/symbol injection (append one random digit + one random symbol).
- Word list: bundled EFF large word list (7,776 words) or equivalent.
- Production builds MUST use OS CSPRNG for word selection.

GUI and CLI MUST offer both modes. When creating a master password, the UI SHOULD default to diceware mode with guidance.

### D4. Clipboard handling

- Copy actions MUST be available in CLI and GUI.
- Clipboard contents MUST auto-clear after configurable timeout (default 30 seconds; range 10–90 seconds).
- Clear behavior MUST be "best effort":
    - MUST clear if clipboard still matches what the app set,
    - MUST NOT overwrite if user changed clipboard after copy.
- Clipboard timeout MUST be configurable and can be disabled only with an explicit warning.
- On macOS: MUST use `NSPasteboard` transient/concealed type to prevent clipboard history managers from capturing the value.
- On Windows: SHOULD set clipboard data with `CF_CLIPBOARD_VIEWER_IGNORE` flag where supported.
- Copy actions in GUI MUST show a toast indicating clipboard will clear in N seconds.

### D5. Search, filtering, favorites

- Search MUST be performed **only after unlock**.
- The vault file MUST contain an **encrypted search index** (see Section H8) covering: item titles, URLs, usernames, and tags.
- The index MUST be decrypted into memory on unlock and used for search queries.
- The index MUST be rebuilt and re-encrypted on every vault write.
- Search MUST support substring matching on: title, username, URL, tags.
- Filtering MUST support: type, tag, favorite.
- GUI SHOULD provide incremental search with debounce.

### D6. TOTP (RFC 6238)

- The system MUST act as a **full TOTP generator** — storing seeds and computing current codes on demand.
- TOTP generation MUST conform to RFC 6238 with:
    - default: 6 digits, 30s period, HMAC-SHA1,
    - support: SHA256, SHA512; digits 6 or 8; period 30 or 60.
- Inputs accepted:
    - base32 secret (CLI/GUI),
    - `otpauth://` URI (CLI/GUI),
    - QR code import (GUI).
- Time skew handling:
    - GUI MUST show current code and countdown timer.
    - CLI MUST support `--at <unix_seconds>` for deterministic output.
    - CLI `npw totp <item>` MUST output current code.

#### TOTP QR export

- The system MUST support exporting TOTP seeds as QR codes in **two formats**:
    1. **`otpauth://` URI** (default): Standard `otpauth://totp/label?secret=...&issuer=...&algorithm=...&digits=...&period=...` for interoperability with Google Authenticator, Authy, and other authenticator apps.
    2. **Encrypted QR**: Seed encrypted before encoding in QR. Only npw can scan it. For secure npw-to-npw transfer.
- Encrypted QR payload encoding (v0.1.0):
    - QR data MUST be ASCII: `npw:totp-qr1:<base64url_nopad(NPW1_BYTES)>`
    - `NPW1_BYTES` MUST be an `NPW1` container whose decrypted payload is a UTF-8 `otpauth://...` URI (no other fields); `vault_label` MUST be `"npw-totp-qr"`.
    - The QR password MUST be entered at export time and MUST NOT be the same as the vault master password.
- User MUST choose the format at export time.
- QR rendering MUST use a bundled library (no network dependency).

### D7. Import/export/backup

#### Import

- Import MUST support:
    - CSV (defined schema below),
    - Bitwarden unencrypted JSON export (common format).

#### Import duplicate detection

- On import, the system MUST check for suspected duplicates by matching on `(title + username + primary URL)`.
- When duplicates are detected, the system MUST present them to the user with options per item:
    - **Skip**: do not import the duplicate.
    - **Overwrite**: replace the existing item with the imported version.
    - **Keep both**: import as a new item alongside the existing one.
- In `--non-interactive` mode, the system MUST default to **skip** and log all skipped items.

#### Export

- Export MUST support:
    - CSV (redacted by default; secrets only with explicit flag),
    - JSON (redacted by default; secrets only with explicit flag),
    - **encrypted export** ("portable vault export") protected by a user-specified password.
- **Redacted export** MUST include: item titles, URLs, usernames, timestamps, and item types. MUST exclude: passwords, TOTP seeds, note bodies.
- Export MUST show warnings before writing secrets in plaintext.

#### Automatic backups

- Every successful vault write MUST trigger a backup.
- Backups MUST remain encrypted vault copies; plaintext exports MUST NOT be auto-backed-up.
- Backup directory: adjacent to vault or user-configured path.
- **Compaction rotation**:
    - Keep **all** backups from the last 24 hours.
    - Keep **one per day** for the preceding 7 days.
    - Keep **one per week** up to the configurable limit (default 10 retained after compaction).
- Compaction MUST run after each backup creation.

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

v0.1.0 "support" MUST mean:

- Vault can store **Passkey Reference Items** (metadata, links, and notes — see H5d for schema).
- GUI MUST provide actions:
    - "Open site" (open default browser to an origin URL),
    - "Open OS passkey manager" (best effort per OS),
    - "Copy username" / "Copy relying party ID".
- CLI MUST provide: list/show/open-site/copy-username.
- The application MUST NOT store or attempt to export/import **passkey private keys** in v0.1.0.

### D9. Concurrency and file locking

- The application MUST use **exclusive write locks** to prevent concurrent writes to the same vault.
- MUST use OS-level file locks (`flock` on Unix, `LockFileEx` on Windows).
- **First writer wins**: the process that acquires the lock proceeds; any second process attempting to write MUST receive an immediate error (CLI exit code 5: "vault file locked by another process").
- No queuing or retry — fail fast.
- Writes MUST be serialized across GUI and CLI.

### D10. Error handling and recovery

- Wrong password MUST fail without leaking details.
- Vault corruption (AEAD tag verification fails on open):
    - The system MUST refuse to open the corrupt file.
    - The system MUST launch a **recovery wizard**:
        - List available backups with timestamps and item counts (from plaintext header).
        - User picks which backup to restore.
    - GUI: modal recovery wizard dialog.
    - CLI: `npw recover` interactive command with same flow.
    - CLI: `npw recover --auto` for non-interactive restore of most recent valid backup.
- Partial writes MUST not corrupt the current vault (atomic write requirement).
- The system MUST validate schemas and reject invalid payloads without silent truncation.

### D11. CLI parity vs GUI parity

- CLI MUST support:
    - vault create/unlock/lock/status/check/change-password/backup,
    - item CRUD for login/note/passkey_ref,
    - list/search,
    - TOTP show/copy,
    - import/export (with warnings; non-interactive flags),
    - configuration commands,
    - recovery (`npw recover`),
    - migration (`npw migrate`, `npw downgrade`).
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

- **KDF / unlock time**: MUST target **3–5 seconds** on a typical 2020+ laptop with default parameters (m=512 MiB, t=4, p=4). This prioritizes resistance to GPU-based attacks over unlock speed. On significantly slower hardware, users MAY reduce KDF parameters via config.
- **Search over 10,000 items**: SHOULD return results in ≤200ms after index decryption on unlock.
- **Save operation**: SHOULD complete in ≤300ms for typical vault sizes (<5MB decrypted payload), excluding KDF time. Includes index rebuild + backup + compaction.

### Reliability / crash safety

- Writes MUST be atomic (temp write + fsync + atomic rename + directory fsync best effort).
- Rolling encrypted backups MUST be maintained with compaction (see D7).

### UX responsiveness (GUI)

- KDF and encryption MUST run off the renderer thread.
- Operations >300ms MUST show progress affordances.

### Accessibility

Not a target for v0.1.0 or foreseeable future. No formal compliance requirements (WCAG or otherwise). Basic keyboard navigation and semantic HTML are provided as general UX quality but are not driven by accessibility goals.

### Internationalization stance

- v0.1.0 SHOULD structure UI strings for future i18n but MAY ship English-only.

### Update policy

- v0.1.0 MUST ship with signed release artifacts (Section P).
- Auto-update/network checks MUST NOT exist in v0.1.0 (Section M).

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
- Electron IPC boundary (renderer → main)
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
| Offline brute force       | Argon2id defaults (3–5s target) + tunability; master password minimums; keychain off by default | G, L    |
| Vault tampering           | AEAD auth + strict parsing + AAD binding                                                   | G, H    |
| Corruption/partial writes | Atomic write; encrypted backups with compaction; recovery wizard                            | H, D10  |
| Secret leaks in logs      | Redaction + strict logging policy + audit trail                                            | N       |
| Clipboard monitoring      | Auto-clear with concealed flags; no auto-copy; warnings                                    | D4, K   |
| Renderer attacks          | Context isolation, no nodeIntegration, allowlisted IPC, CSP                                | I, K    |
| Import parser attacks     | Strict validation; size limits; fuzz tests                                                 | D7, O   |
| Supply chain              | Locked deps, SBOM, cargo-audit in CI, signed releases, provenance                         | P       |

### Residual risks + user education

- Weak master password remains primary risk; UI MUST educate and provide strength guidance (zxcvbn-based).
- Clipboard may be monitored; users MUST be warned.
- Plaintext exports are inherently risky; explicit warnings and confirmations required.

### F5. Failure modes table

| Failure | Detection | Impact | Recovery |
| ------- | --------- | ------ | -------- |
| Vault file corruption (AEAD tag mismatch) | Decryption fails with auth error | Vault inaccessible | Recovery wizard: list backups, user picks restore target. `npw recover` CLI. |
| Backup file corruption | Backup decryption fails during recovery | Specific backup unusable | Skip corrupt backup, try next oldest. Warn user if no valid backups remain. |
| Vault file locked by another process | `flock`/`LockFileEx` returns `EWOULDBLOCK` | Write rejected | Immediate error (exit 5). User closes other process or waits. |
| Disk full during write | `write()`/`fsync()` returns `ENOSPC` | Temp file incomplete; original vault intact (atomic write) | Error message with disk space info. Original vault preserved. |
| Crash during atomic write | Temp file exists alongside vault on next open | No data loss (rename didn't complete) | On next open, detect orphaned temp file. Warn user, offer cleanup. |
| OS keychain unavailable | Secret Service / Credential Manager API error | Quick Unlock disabled | Graceful fallback to master password. Disable Quick Unlock toggle. Inform user. |
| mlock fails (RLIMIT_MEMLOCK) | `mlock()` returns `ENOMEM` | Secrets may be swapped to disk | Log warning, continue with zeroize-only. Do not crash. |
| IPC call to Rust addon hangs/crashes | Main process unresponsive or Node addon throws | GUI frozen or inconsistent state | Hard restart: kill main process, show "vault locked" dialog, force re-authentication. |
| Import CSV/JSON malformed | Parser rejects invalid input | Import aborted | Error report with line numbers / field names. No partial import committed. |
| Schema migration fails | Migration function returns error | Vault stays at old version | Abort migration, restore from pre-migration backup (auto-created). Inform user. |

---

## G. Cryptography and Key Management (implementation-grade)

### G0. Crypto core language — DECIDED

**Decision: Rust core** implementing crypto, vault I/O, parsers, migrations; reused by:

- **CLI:** native Rust binary.
- **GUI:** Electron **main process** calls Rust via **Node N-API** addon (loaded directly in main process, not a utility process).

#### Decision matrix (historical)

| Option       | Security | Performance | Cross-platform |      DX | Auditability | Maturity | Electron/Node integration |     Risk |
| ------------ | -------: | ----------: | -------------: | ------: | -----------: | -------: | ------------------------: | -------: |
| Rust + N-API |     High |        High |           High |     Med |         High |     High |                      High |  Low–Med |
| Go + cgo     | Med–High |        High |            Med |     Med |          Med |     High |                       Med |      Med |
| TS-only      |      Med |         Med |           High |    High |          Med |     High |                      High | Med–High |
| C/C++        |     High |        High |            Med | Low–Med |          Med |     High |                       Med |     High |

**Rationale:** Security, performance, auditability, consistent crypto implementation. Rust addon runs in Electron main process (not utility process) because the hard-restart IPC policy (see I5) means an addon crash triggers a full restart regardless — a utility process would add an IPC hop and complexity without meaningful benefit.

---

### G1. Cryptographic primitives (MUST use exactly these in v0.1.0)

- KDF: **Argon2id v1.3**
- AEAD: **XChaCha20-Poly1305** (24-byte nonce, 32-byte key)
- HKDF: **HKDF-SHA256**
- TOTP: HMAC-SHA1 (default), SHA256, SHA512 per RFC 6238

### G2. KDF parameters (defaults + bounds)

Defaults (desktop, targeting 3–5 second unlock on typical 2020+ laptop):

- Memory: **512 MiB** (524,288 KiB)
- Time cost: **4**
- Parallelism: **4**
- Output length: **32 bytes**

Bounds:

- Memory: 64–1024 MiB (unless explicitly overridden)
- Time: 1–10
- Parallelism: 1–4

The KDF parameters MUST be stored in the vault header. The KDF parameter bounds MUST be validated on vault open (reject out-of-bounds values).

### G3. Master password handling

- Master password MUST be NFKC-normalized then UTF-8 encoded.
- Master password MUST NOT be stored in plaintext anywhere.
- Password entry MUST not echo.
- Minimum requirement: at least 12 characters OR at least 4 words in passphrase mode.

#### Password strength guidance

The system MUST provide offline password strength guidance using a **combined approach**:

1. **zxcvbn-based pattern matching**: Port or bind to the zxcvbn algorithm for pattern-aware entropy estimation. Provides meaningful feedback to users (e.g., "this is a common dictionary word", "this matches a keyboard pattern").
2. **Entropy calculation**: Character-class entropy estimation as a secondary signal.
3. **Hard minimum rules**: Password MUST be at least 12 characters (or 4 words in passphrase mode). Password MUST be rejected if zxcvbn score is below 3 (out of 0–4), with an explanation of why and how to improve.

Strength guidance MUST be displayed during vault creation and master password change. It SHOULD also be available during site password generation (informational only, not blocking).

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

- Rust core MUST zeroize secret keys and decrypted buffers as soon as practical (using the `zeroize` crate with `Zeroize` derive or explicit `.zeroize()`).
- Secrets MUST NOT be logged.
- Rust core MUST attempt to `mlock`/`VirtualLock` memory pages containing sensitive material (`vault_key`, `kdf_key`, `kek`, `payload_key`, decrypted item buffers).
    - If `mlock` fails (e.g., `RLIMIT_MEMLOCK` exceeded), MUST log a warning and continue with zeroize-only. MUST NOT crash.
    - Practical scope: only the key material and active decrypted buffer need locking (~1MB typical).
- Electron renderer SHOULD not receive secrets unless explicitly needed for display.

Best-effort:

- Disable core dumps where platform APIs allow (`prctl(PR_SET_DUMPABLE, 0)` on Linux, equivalent on other platforms).

### G9. Metadata leakage stance

The vault header contains **plaintext** fields required for decryption, plus two optional metadata fields accepted as a trade-off for multi-vault UX:

- **Vault label**: optional user-chosen name (0–64 bytes UTF-8). Defaults to empty. Enables identifying vault files without decrypting.
- **Item count**: u32 count of items in payload. Enables "vault has N items" display without decryption.

These fields leak the vault name and item cardinality to anyone with file access. This trade-off is accepted for usability when managing multiple vault files. Users who require maximum privacy SHOULD leave the vault label empty (the item count cannot be omitted as it is part of the header format).

All other metadata (titles, URLs, tags, timestamps, user identifiers) MUST be encrypted in the payload.

### G10. TOTP seeds

- Seeds MUST be encrypted within payload.
- Revealing seed in GUI MUST require explicit confirmation.

### G11. Passkeys/WebAuthn private keys

- v0.1.0 MUST NOT store passkey private keys.
- Only metadata references are supported (see H5d).

---

## H. Data Model and Storage Format

### H0. Attachments — DECIDED: Deferred

**Decision: Defer encrypted binary attachments.** v0.1.0 supports optional **file reference fields** (paths/URIs) with warnings that references are not encrypted and may reveal metadata.

Encrypted external attachments with chunked AEAD and transactional semantics are deferred to v0.2+.

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
offset  size    field
0       4       magic = "NPW1"
4       2       format_version = 0x0001
6       2       header_flags (bitset; v1 all zero)
8       1       kdf_id (1 = Argon2id)
9       1       aead_id (1 = XChaCha20-Poly1305)
10      2       reserved (zero)
12      4       argon_m_kib (u32)
16      4       argon_t (u32)
20      4       argon_p (u32)
24      4       item_count (u32)
28      1       vault_label_len (u8) 0..=64
29      L       vault_label (UTF-8, L = vault_label_len bytes)
29+L    2       salt_len (u16) MUST be 16
31+L    16      salt
47+L    2       env_nonce_len (u16) MUST be 24
49+L    24      env_nonce
73+L    4       env_ct_len (u32) includes AEAD tag
77+L    N       env_ciphertext
77+L+N  2       payload_nonce_len (u16) MUST be 24
79+L+N  24      payload_nonce
103+L+N 8       payload_ct_len (u64) includes AEAD tag
111+L+N M       payload_ciphertext
```

All length fields MUST be validated against file size and sane caps:

- `vault_label_len` MUST be ≤ 64.
- `env_ct_len` MUST be between 48 and 4096 bytes (envelope is small).
- `payload_ct_len` MUST be ≤ 256 MiB in v0.1.0 (configurable build constant).

### H3. Envelope plaintext (CBOR)

Decrypted with `kek`. CBOR map:

- `vault_id`: 16 bytes random
- `vault_key`: 32 bytes random
- `created_at`: unix seconds
- `kdf_hint`: optional string (non-identifying)
- `reserved`: optional bytes

### H4. AAD binding

- Envelope AAD: header bytes from offset 0 through end of `env_ct_len` field (before ciphertext begins), excluding ciphertext.
- Payload AAD: header bytes from offset 0 through end of `payload_ct_len` field, excluding payload ciphertext.

### H5. Payload plaintext (CBOR)

Top-level map:

- `schema`: 1
- `app`: `{ name, version }`
- `updated_at`: unix seconds
- `items`: array of items (see H5a–H5d)
- `tombstones`: array of `{ id, deleted_at }`
- `settings`: vault-local settings (encrypted within payload)
- `search_index`: encrypted search index data (see H8)

#### H5a. Login item schema

All fields are strict (no user-defined custom fields in v0.1.0).

| Field | Type | Required | Constraints |
| ----- | ---- | -------- | ----------- |
| `id` | string (UUIDv4) | MUST | Unique within vault |
| `type` | string | MUST | `"login"` |
| `title` | string | MUST | 1–256 bytes UTF-8 |
| `urls` | array of URL entry | SHOULD | See URL entry below |
| `username` | string | MAY | 0–256 bytes UTF-8 |
| `password` | string | MAY | 0–10,000 bytes UTF-8 |
| `totp` | TOTP object | MAY | See H5c; embedded when TOTP is associated with a login |
| `notes` | string | MAY | 0–100,000 bytes UTF-8 |
| `tags` | array of string | MAY | Each tag: 1–64 bytes UTF-8, trimmed, case-preserved |
| `favorite` | bool | MUST | Default `false` |
| `created_at` | u64 | MUST | Unix seconds |
| `updated_at` | u64 | MUST | Unix seconds |

**URL entry** (within `urls` array):

| Field | Type | Required | Constraints |
| ----- | ---- | -------- | ----------- |
| `url` | string | MUST | Valid URL, 1–2048 bytes |
| `match` | string | MUST | One of: `"exact"`, `"domain"`, `"subdomain"` |

First URL in the array is the **primary** URL (used for display and default search ranking).

#### H5b. Secure note schema

| Field | Type | Required | Constraints |
| ----- | ---- | -------- | ----------- |
| `id` | string (UUIDv4) | MUST | Unique within vault |
| `type` | string | MUST | `"note"` |
| `title` | string | MUST | 1–256 bytes UTF-8 |
| `body` | string | MUST | 0–1,000,000 bytes UTF-8 (plaintext only) |
| `tags` | array of string | MAY | Same constraints as login |
| `favorite` | bool | MUST | Default `false` |
| `created_at` | u64 | MUST | Unix seconds |
| `updated_at` | u64 | MUST | Unix seconds |

#### H5c. TOTP schema

When embedded in a login item (in the `totp` field) or stored standalone:

| Field | Type | Required | Constraints |
| ----- | ---- | -------- | ----------- |
| `seed` | bytes | MUST | Base32-decoded TOTP secret |
| `issuer` | string | SHOULD | 0–256 bytes UTF-8 |
| `algorithm` | string | MUST | One of: `"SHA1"`, `"SHA256"`, `"SHA512"`. Default `"SHA1"` |
| `digits` | u8 | MUST | `6` or `8`. Default `6` |
| `period` | u16 | MUST | `30` or `60`. Default `30` |

#### H5d. Passkey reference schema

| Field | Type | Required | Constraints |
| ----- | ---- | -------- | ----------- |
| `id` | string (UUIDv4) | MUST | Unique within vault |
| `type` | string | MUST | `"passkey_ref"` |
| `title` | string | MUST | 1–256 bytes UTF-8 |
| `rp_id` | string | MUST | Relying party ID (domain), 1–256 bytes |
| `rp_name` | string | MAY | Relying party display name, 0–256 bytes |
| `user_display_name` | string | MAY | User display name, 0–256 bytes |
| `credential_id` | bytes | MUST | Credential ID (opaque bytes, base64url in display) |
| `notes` | string | MAY | Freeform notes (e.g., which device holds the passkey, recovery steps), 0–100,000 bytes UTF-8 |
| `tags` | array of string | MAY | Same constraints as login |
| `favorite` | bool | MUST | Default `false` |
| `created_at` | u64 | MUST | Unix seconds |
| `updated_at` | u64 | MUST | Unix seconds |

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

#### Migration UX: Prompt before upgrade

- On vault open, if the vault schema is older than the app's current schema:
    - GUI: Show dialog: "This vault needs upgrading from schema vN to vM. A backup will be created automatically. Continue?" User must confirm.
    - CLI: Interactive prompt with same message. `--upgrade` flag to skip prompt in scripts.
- A timestamped backup MUST be created **before** any migration writes.
- If migration fails, abort and restore from the pre-migration backup.

#### Downgrade support

- The CLI MUST provide `npw downgrade <vault>` to convert a vault back to a previous schema version.
- Downgrade MUST create a backup before converting.
- If the schema change is inherently one-way (e.g., changed encryption scheme, removed fields that had data), `npw downgrade` MUST refuse with an explanation rather than silently losing data.
- Downgrade strips any fields added by the newer schema (with warnings listing removed fields).

### H8. Search index

The vault file MUST contain an **encrypted search index** as part of the payload.

- Index scope: item titles, URLs (the `url` string only), usernames, and tags.
- Index MUST NOT contain passwords, TOTP seeds, note bodies, or other secret fields.
- Index is stored in the `search_index` field of the CBOR payload, encrypted alongside all other payload data with `payload_key`.
- Index is rebuilt from item data on every vault write.
- On vault unlock, the index is decrypted into memory and used for all search operations.
- If the index is missing or corrupt, the app MUST rebuild it from decrypted items (graceful degradation).

### H9. Atomic writes and backups

Save algorithm MUST:

1. Acquire exclusive file lock.
2. Read current vault to verify decryptable (optional but recommended).
3. Serialize payload + rebuild search index.
4. Write temp file with secure permissions.
5. `fsync` temp file.
6. Copy current vault to backup directory (encrypted backup).
7. Run backup compaction (see D7).
8. Atomic rename temp to vault.
9. Best-effort directory `fsync`.
10. Release lock.

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
+----------------------------+          +----------------------------+
|            CLI             |          |        Electron GUI        |
|  (Rust binary)             |          |                            |
|  +----------------------+  |          |  +----------------------+  |
|  | core (crypto+vault)  |  |          |  | Renderer (Svelte)    |  |
|  | storage+domain       |  |          |  | - no vault IO        |  |
|  +----------+-----------+  |          |  +----------+-----------+  |
|             |              |          |             | IPC allowlist |
|        .npw vault          |          |  +----------v-----------+  |
+-------------+--------------+          |  | Main process         |  |
                                        |  | - session mgr        |  |
                                        |  | - clipboard          |  |
                                        |  +----------+-----------+  |
                                        |             | N-API        |
                                        |  +----------v-----------+  |
                                        |  | Rust addon (core)    |  |
                                        |  +----------------------+  |
                                        +----------------------------+
```

### I1. Module responsibilities

- **core (Rust library)**
    - Vault format read/write, crypto, schema validation, migrations.
    - Import/export transforms (but NOT GUI dialogs).
    - TOTP generation.
    - Password strength estimation (zxcvbn + entropy).
    - Password/passphrase generation.
- **storage (Rust)**
    - File locking, atomic writes, backups, compaction.
- **domain (Rust)**
    - Item validation, search index build/query, tag normalization.
- **CLI (Rust)**
    - Prompts, JSON output, exit codes, config management (TOML).
- **Electron main (TypeScript)**
    - Vault selection, session lifecycle, IPC handlers, clipboard, OS integration.
    - Calls Rust addon for all sensitive operations.
- **Electron renderer (Svelte)**
    - UI only; receives minimal non-secret data by default.

### I2. Electron hardening (MUST)

- `contextIsolation: true`
- `nodeIntegration: false`
- `sandbox: true` for renderer where feasible (platform constraints noted).
- CSP MUST be set to disallow remote content:
    - `default-src 'self'`
    - `script-src 'self'`
    - `img-src 'self' data:`
    - `connect-src 'none'`
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

### I5. IPC failure handling

When the Electron main process (Rust addon) crashes or becomes unresponsive during an IPC call:

- **Hard restart**: Kill the main process, show a "vault locked — reopen" dialog, and force the user to re-authenticate.
- The renderer MUST NOT attempt to retry IPC calls or recover session state.
- This policy prioritizes data integrity and simplicity over convenience.
- Since the Rust addon runs in the main process (see G0), an addon crash is equivalent to a main process crash — recovery is identical regardless of isolation strategy.

---

## J. CLI Specification

### J0. CLI name

- Binary: `npw`

### J1. Session model

The CLI is **stateless**: every command re-derives keys from the master password via Argon2id. There is no daemon, no socket, no session file.

- Each command that requires vault access prompts for the master password (unless `--non-interactive` with stdin piping).
- This means each command incurs the full KDF cost (3–5 seconds with default parameters).
- This is an accepted trade-off for simplicity and security — no session state means no session to attack.

### J2. Global flags

- `--vault <path>`
- `--json`
- `--no-color`
- `--quiet`
- `--config <path>`
- `--non-interactive`

### J3. Exit codes

- `0` success
- `1` general error
- `2` invalid usage
- `3` vault locked / no session
- `4` auth failed
- `5` vault file locked (by another process)
- `6` corrupted/parse error
- `7` network disabled
- `8` permission denied

### J4. Secure prompting

- Password MUST NOT be accepted via CLI arg.
- Password MAY be accepted from stdin only with `--non-interactive` and explicit documentation of risk.
- Prompts MUST disable echo and clear buffers where feasible.

### J5. Commands (summary)

- **Vault**: `vault init|unlock|lock|status|check|change-password|backup`
- **Items**: `item add|get|list|edit|delete|restore|copy`
- **Search**: `search`
- **TOTP**: `totp <item_id>` (alias for `totp show <item_id>`), `totp add|show|copy|export-qr`
- **Passkeys**: `passkey list|show|open-site`
- **Import/Export**: `import csv|bitwarden-json`, `export csv|json|encrypted`
- **Config**: `config get|set|list`
- **Recovery**: `recover [--auto]`
- **Migration**: `migrate`, `downgrade`
- **Password generation**: `generate [--mode charset|diceware] [options]`

### J6. Configuration system

Configuration is stored in **TOML** format at XDG-compliant paths:

- **Linux/macOS**: `$XDG_CONFIG_HOME/npw/config.toml` (defaults to `~/.config/npw/config.toml`)
- **Windows**: `%APPDATA%\npw\config.toml`

#### Config schema (v0.1.0)

```toml
# Default vault path (optional)
default_vault = "~/Vaults/personal.npw"

[security]
clipboard_timeout_seconds = 30    # 10..=90, or 0 to disable (with warning)
auto_lock_minutes = 5             # 1..=60
lock_on_suspend = true
reveal_requires_confirm = true

[generator]
default_mode = "charset"          # "charset" or "diceware"
charset_length = 20               # 8..=128
charset_uppercase = true
charset_lowercase = true
charset_digits = true
charset_symbols = true
charset_avoid_ambiguous = false
diceware_words = 5                # 4..=10
diceware_separator = "-"

[logging]
level = "info"                    # "error", "warn", "info", "debug"

[backup]
max_retained = 10                 # after compaction
```

- `config get <key>` MUST print the current value.
- `config set <key> <value>` MUST validate and persist.
- `config list` MUST print all current settings with defaults annotated.

### J7. JSON output contract

All JSON outputs MUST include:

- `schema_version` (int)
- `ok` (bool)
- `error` object on failure

---

## K. GUI Specification (Electron + Svelte)

### K0. Framework

The GUI renderer uses **Svelte** (SvelteKit). Rationale: smaller compiled bundle, less boilerplate, good Electron integration. State management via Svelte stores.

### K1. Screen list (required for v0.1.0)

1. Vault Picker (recent vaults + open/create)
2. Create Vault
3. Unlock Vault
4. Main List (items + search/filter)
5. Item Detail (login/note/passkey_ref)
6. Add/Edit Item
7. Import/Export
8. Settings (security + preferences)
9. Backup/Recovery screen (restore from backup)

### K2. Vault Picker flow

**Wireframe**

```text
npw
Recent Vaults:
- Personal (~/Secrets/personal.npw)  [Open]
- Work (~/Vaults/work.npw)          [Open]

[Create New Vault]  [Open Existing Vault]
```

Requirements:

- MUST display paths (to avoid confusion).
- MUST allow removing a vault from recent list without deleting file.
- Recent list MUST be stored in config (non-secret).

### K3. Create Vault flow

- MUST prompt for:
    - vault file location,
    - master password (twice),
    - optional vault label (0–64 chars),
    - password strength guidance shown inline (zxcvbn score + feedback).
- Password generator MUST default to diceware mode during vault creation.
- MUST show password minimum requirements (12 chars or 4 words; zxcvbn score ≥ 3).
- MUST create file with secure permissions.

### K4. Unlock flow

- MUST support unlocking by master password.
- MAY support "Quick Unlock" via OS keychain only if enabled for that vault (Section L1).
- MUST show:
    - vault path and label (if set),
    - unlock method,
    - failure message that does not reveal sensitive detail.
- Auto-lock timer MUST start after unlock.

### K5. Main List behavior

**Wireframe**

```text
[Search box..................] [Filter: All v]
Favorites
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

### K6. Item Detail (Login)

Fields:

- Title, URLs (with match type badges), Username
- Password field:
    - default: masked
    - actions: [Copy] [Reveal] [Generate & Replace]
- TOTP (if present):
    - show current code + countdown timer
    - actions: [Copy code] [Export QR]
    - MUST not display TOTP secret by default
- Notes (collapsed by default if long)
- Tags

Security UX:

- Reveal password MUST require explicit user action and SHOULD auto-hide after 30 seconds.
- Copy actions MUST show a toast that clipboard will clear in N seconds.

### K7. Item Detail (Secure Note)

- Body editor with plaintext (no rich text).
- Copy selected text action MAY be supported.

### K8. Passkey Reference Item UI

- Display `rp_id`, `rp_name`, `user_display_name`, `credential_id`.
- Freeform notes field (e.g., "stored on YubiKey #2", recovery steps).
- Actions:
    - Open origin in browser
    - Open OS passkey manager (best effort)
- MUST clearly label: "This app does not store passkeys. This is a reference entry."

### K9. Add/Edit item flows

- MUST validate required fields (title).
- MUST normalize tags (trim, collapse whitespace).
- Save MUST be atomic and show error if vault locked.

### K10. TOTP QR import

- Approach:
    - Use `getUserMedia` camera access in renderer **only** on the QR import screen.
    - QR decoding MUST happen locally (no network).
    - If camera denied/unavailable, MUST provide fallback: paste `otpauth://` URI or base32 secret.
- Security:
    - Camera stream MUST be stopped immediately after scan/cancel.
    - No frames MUST be persisted.

### K11. Settings screen (security critical)

Settings MUST include:

- Auto-lock timeout (default 5 minutes; range 1–60)
- Lock on suspend/lock screen (default on)
- Clipboard clear timeout (default 30 seconds; range 10–90)
- "Reveal secrets requires confirmation" (default on)
- OS keychain "Quick Unlock" per vault (default off)
- Log level (default info)

### K12. Error UX

All vault operation errors (write failures, corrupt backups, lock contention) use a **toast + retry** model:

- Non-blocking toast notification with error summary.
- "Retry" button where the operation is retryable.
- Expandable section with detailed error information.
- Vault stays unlocked — errors do not force a lock.
- Exception: IPC failure (main process crash/hang) triggers hard restart per Section I5.

---

## L. Cross-Platform OS Integration

### L0. OS keychain usage — DECIDED

**Decision: Opt-in Quick Unlock storing `vault_key` in OS keychain; OFF by default.**

Store **`vault_key`** (32 bytes) in OS keychain to allow "Quick Unlock". This preserves offline protection of the vault file when keychain is unavailable (attacker with only file still faces Argon2id).

#### Decision matrix (historical)

| Option                    |          Security | Performance | Cross-platform fit |   DX | Auditability | Ecosystem maturity | Electron/Node integration | Risk |
| ------------------------- | ----------------: | ----------: | -----------------: | ---: | -----------: | -----------------: | ------------------------: | ---: |
| No keychain               |              High |         Med |               High | High |         High |               High |                      High |  Low |
| Store master pw           |           Low–Med |        High |                Med |  Med |          Med |               High |                      High | High |
| Store `vault_key`/derived | Med–High (opt-in) |        High |           Med–High |  Med |          Med |               High |                  Med–High |  Med |
| Non-secret only           |              High |         Low |               High |  Low |         High |               High |                      High |  Low |

**Security warning (MUST)**

- Enabling Quick Unlock means anyone who can access the OS user session/keychain may unlock the vault without the master password. GUI MUST present this warning and require explicit confirmation.

#### Keychain integration requirements (v0.1.0)

- Keychain entries MUST be per-vault, keyed by `vault_id`.
- Stored secret: `vault_key` base64 (or raw bytes if API supports).
- Label/metadata MUST NOT include sensitive user info; use `npw Vault Key (<vault_id_prefix>)`.
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
- Concealed pasteboard flags (see D4) MUST be set on copy.

### L2. Auto-start / tray behavior

- v0.1.0: **No auto-start** and **no tray resident mode** by default.
- GUI MAY support "minimize to tray" later (v0.2+) with careful security review.

### L3. File dialogs and sandboxing

- GUI MUST use OS file dialogs for vault open/create.
- Renderer MUST not receive arbitrary filesystem paths unless needed for display; main retains canonical path.

### L4. Code signing/notarization requirements

- Windows: release installers/binaries MUST be Authenticode-signed.
- macOS: app MUST be code-signed and notarized.
- Linux: AppImage SHOULD be signed (detached signature) and checksums published.

---

## M. Networking (Default: none)

### M0. Networking policy — DECIDED

**Decision: No networking in v0.1.0, enforced by build configuration.**

Networking increases attack surface (MITM, dependency sprawl, privacy concerns). Local-first product launch prioritizes correctness and security fundamentals.

HIBP k-anonymity checks and/or update checks may be implemented as separately opt-in modules behind compile-time feature flags and runtime toggles in v0.2+.

### M1. Enforcement (v0.1.0 MUST)

- Default builds MUST:
    - not include HTTP client dependencies in Rust core/CLI,
    - not call `fetch`, `XMLHttpRequest`, or open remote URLs except when user explicitly clicks "Open site" for a stored URL (which launches external browser).
- Electron renderer CSP MUST set `connect-src 'none'`.
- CI MUST include a test that scans built JS bundles for disallowed network primitives (best-effort) and fails if found outside allowlisted modules.

### M2. If networking is implemented later (spec for future compatibility)

If a networking feature is compiled in, it MUST:

- Be **opt-in** with explicit UX gating.
- Send the minimum data required; MUST NOT send vault contents, emails, or identifiers.
- Use TLS with system trust store; certificate pinning is NOT required but MAY be added with careful operational planning.
- Respect proxy environment variables only if user enables "Use system proxy".

#### HIBP k-anonymity (future)

- Compute SHA-1 of password (per HIBP protocol).
- Send only first 5 hex chars prefix to endpoint.
- Use padding header if supported by endpoint to reduce response-size leakage.
- Compare suffixes locally; do not send full hash or password.

---

## N. Observability, Telemetry, and Logging

### N1. Structured logging

All logging uses **structured JSON format** written to a log file.

- **File location**: `$XDG_STATE_HOME/npw/npw.log` (Linux/macOS; defaults to `~/.local/state/npw/npw.log`), `%LOCALAPPDATA%\npw\npw.log` (Windows).
- **Default log level**: `info` (configurable via `config set logging.level <level>` or env var `NPW_LOG=debug`).
- **Rotation**: Rotate by file size at **10 MB**. Keep current + one rotated file.
- **Format**: One JSON object per line (newline-delimited JSON). Fields:
    - `ts`: ISO 8601 timestamp
    - `level`: `error` | `warn` | `info` | `debug`
    - `msg`: human-readable message
    - `correlation_id`: unique ID per logical operation (e.g., per vault open, per item save)
    - `module`: source module name
    - Additional structured fields as appropriate

### N2. Audit trail (security events)

The following security-relevant operations MUST be logged at `info` level for forensic review:

| Event | Logged fields |
| ----- | ------------- |
| Vault unlock success | vault path, timestamp, method (password/keychain) |
| Vault unlock failure | vault path, timestamp, method (no password or error details) |
| Item created | item ID, item type, timestamp |
| Item updated | item ID, item type, timestamp |
| Item deleted | item ID, timestamp |
| Export invoked | export type (csv/json/encrypted), redacted flag, timestamp |
| Import invoked | import type, item count, duplicate count, timestamp |
| Config changed | key, new value (MUST NOT log secret values), timestamp |
| Backup created | backup path, timestamp |
| Backup restored | backup path, timestamp |
| Quick Unlock enabled/disabled | vault ID prefix, timestamp |

Audit events MUST be included in the standard log file (not a separate file).

### N3. Secret redaction rules

Logs MUST NEVER include:

- master password,
- derived keys (`kdf_key`, `kek`, `vault_key`, `payload_key`),
- passwords, TOTP secrets, decrypted note bodies,
- full item records.

Item IDs MAY be logged. Vault path MAY be logged. These redaction rules MUST be unit-tested.

### N4. Telemetry policy

- v0.1.0 MUST have **no telemetry**.
- Crash reporting MUST be off by default. If implemented later, MUST be opt-in and must scrub secrets.

---

## O. QA, Test Plan, and Security Validation

### O1. Test layers

- **Unit tests (Rust core)**
    - KDF parameter parsing bounds
    - Envelope/payload encryption-decryption roundtrips
    - CBOR schema validation (all item types per H5a–H5d)
    - TOTP vectors (RFC 6238 test cases)
    - Password strength scoring (zxcvbn integration)
    - Password/passphrase generation (character set coverage, word count, entropy)
    - Search index build/query correctness
- **Integration tests**
    - Vault create → write → reopen across processes
    - Backup rotation and compaction correctness
    - File locking behavior (best-effort cross-platform)
    - Import duplicate detection
    - Schema migration and downgrade
- **E2E tests**
    - CLI workflows (all subcommands)
    - GUI smoke tests (Playwright)

### O2. Property tests (MUST)

- Vault roundtrip: random item sets serialize→encrypt→decrypt→parse equals original (modulo timestamps).
- AEAD invariants: tampering any header byte in AAD MUST cause decrypt failure.
- Import/export: export→import roundtrip preserves expected fields.
- Search index: index→query returns all items matching the query term.

### O3. Fuzzing targets (MUST)

- Vault header parser
- CBOR payload parser
- Migration logic
- CSV/JSON import parsers

Fuzzing MUST run **10 million iterations clean** (no crashes, no panics) as a release gate. Fuzzing SHOULD run in CI on nightly schedule and on release branches.

### O4. Test coverage gates (MUST)

| Scope | Coverage requirement |
| ----- | -------------------- |
| Crypto core (KDF, AEAD, HKDF, key hierarchy) | **100% line coverage** |
| Vault read/write (format, atomic writes, locking) | **100% line coverage** |
| CLI commands | **80%+ line coverage** |
| GUI (Svelte renderer) | Smoke tests only (Playwright: vault create/unlock, add item, search, TOTP copy) |

Coverage MUST be measured in CI and enforced as a release gate.

### O5. Cross-platform CI matrix (MUST)

- Windows latest (x64)
- macOS latest (arm64 and/or x64)
- Ubuntu 22.04 (x64)

CI tasks:

- Build CLI
- Build Electron app
- Run unit/integration tests
- Lint/format checks
- Dependency audits (`cargo audit`, `npm audit`)
- SBOM generation (release)
- Coverage measurement and enforcement

### O6. Static analysis and linting

- Rust: `clippy` with deny warnings on CI; `rustfmt`.
- TS/Svelte: ESLint + typecheck; formatting via Prettier.
- Security linters: check for dangerous Electron settings and CSP.

### O7. Security review checklist (pre-release gate)

- Verify KDF params and storage
- Verify AEAD AAD binding
- Verify no secrets in logs (automated redaction tests)
- Verify renderer isolation, CSP, IPC allowlist
- Verify network disabled by default
- Verify file permissions and backup behavior
- Verify dependency audit results acceptable
- Verify mlock/zeroize behavior

### O8. Pre-release security gates for v0.1.0 (MUST)

- At least 1 internal security review sign-off.
- All fuzz targets run with no new crashes on release candidate (10M iterations).
- Coverage gates met (crypto + vault 100%, CLI 80%+).

---

## P. Release Engineering and Supply Chain Security

### P1. Distribution strategy (v0.1.0)

**GitHub releases only.** Signed binaries attached to GitHub releases:

- **macOS**: `.dmg` (code-signed + notarized)
- **Windows**: `.msi` or `.exe` installer (Authenticode-signed)
- **Linux**: `.AppImage` + `.deb` (detached signature + checksums)

No auto-update mechanism in v0.1.0. Users manually download new versions from the GitHub releases page.

### P2. Reproducible builds stance

- v0.1.0 SHOULD be reproducible "where feasible":
    - CLI: reproducible builds SHOULD be achievable with locked Rust toolchain and Cargo.lock.
    - GUI: reproducibility is harder due to Electron packaging; project MUST document exact build environment and dependencies to approximate reproducibility.
- Build instructions MUST include pinned toolchain versions.

### P3. Signing requirements

- All release artifacts MUST be signed:
    - CLI: detached signatures + checksums.
    - GUI: platform-native signing (Windows Authenticode, macOS notarization).
- Release page MUST publish SHA-256 checksums.

### P4. SBOM generation

- Releases MUST include SBOMs:
    - Rust dependencies (SPDX or CycloneDX)
    - npm dependencies (CycloneDX recommended)
- SBOMs MUST be generated in CI and attached to release artifacts.

### P5. Provenance / SLSA stance

- v0.1.0 SHOULD generate build provenance attestation (SLSA level 2 target).
- CI MUST be configured to prevent secret leakage and restrict release signing keys.

### P6. Supply chain security controls

- **Pin all dependency versions**: `Cargo.lock` and npm/pnpm lockfile MUST be committed.
- **Audit in CI**: `cargo audit` and `npm audit` MUST run on every PR and release build.
- **SBOM**: generated and published with every release (see P4).
- **Minimal dependency tree**: prefer well-audited crates; avoid transitive dependency sprawl.
- **Review process**: new dependencies MUST be reviewed for maintenance status, security history, and license compatibility before adoption.

---

## Q. Documentation Deliverables

### Q1. User documentation (MUST)

- Getting started (create/unlock/lock)
- Backups and recovery (including recovery wizard usage)
- Import/export guide with warnings (including duplicate detection behavior)
- TOTP guide (adding seeds, generating codes, QR export)
- Passkey reference explanation (what it is and is not)
- Password generator guide (charset mode vs diceware mode)
- Threat model summary (plain language)
- Security defaults and how to change them

### Q2. Contributor documentation (MUST)

- Dev setup (Rust + Node toolchain + Svelte)
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

- Implement vault format v1 (including new header fields: vault label, item count), crypto, atomic writes, backups with compaction
- Implement core domain model + search index
- Implement all item schemas (login, note, TOTP, passkey_ref)
- Implement CLI commands for vault and items (stateless session model)
- Implement config system (TOML + XDG)
- Implement password generator (both modes) + strength guidance (zxcvbn)
- Unit/property tests + fuzz harness
- Achieve crypto + vault 100% coverage

### Phase 2 — Electron GUI + IPC hardening

- Implement main/renderer split with Svelte renderer, preload API, allowlisted IPC
- Implement vault picker/create/unlock, list/detail/add/edit
- Implement clipboard handling with concealed flags and configurable timeout
- Implement auto-lock
- Implement toast + retry error UX
- Implement hard-restart IPC failure policy

### Phase 3 — Import/export + TOTP + passkey references

- CSV + Bitwarden JSON import with duplicate detection
- Redacted exports + encrypted export
- TOTP full generator + QR scan flow + QR export (otpauth:// + encrypted)
- Passkey reference item UI/actions with notes field

### Phase 4 — Release hardening

- Cross-platform CI green
- Signing pipelines
- SBOM generation
- Security review gates
- Coverage gates enforced
- Fuzz targets: 10M iterations clean
- Documentation completion
- Recovery wizard tested (GUI + CLI)
- Migration/downgrade tested

**Definition of Done (v0.1.0)**

- Meets all acceptance criteria (Section S)
- Signed release artifacts published with checksums on GitHub
- Security review completed
- No critical known vulnerabilities in dependencies (document exceptions)

---

## S. Acceptance Criteria (v0.1.0)

### S1. Given/When/Then scenarios (top 5 complex flows)

#### Scenario 1: Vault creation with weak password rejection

```
Given the user launches npw (CLI or GUI) to create a new vault
When the user enters a master password with zxcvbn score < 3
Then the system MUST reject the password with a message explaining why
  and the zxcvbn feedback (e.g., "this is a common dictionary word")
  and the minimum requirements (12 chars or 4 words, score ≥ 3)
  and no vault file is created
```

#### Scenario 2: Import with duplicate detection

```
Given a vault containing a login item with title="GitHub", username="user@example.com", url="https://github.com"
When the user imports a CSV containing a row with matching title, username, and URL
Then the system MUST flag the row as a suspected duplicate
  and present options: Skip, Overwrite, Keep Both
  and if Skip: the item is not imported, count is logged
  and if Overwrite: the existing item is replaced with imported data
  and if Keep Both: a new item is created alongside the existing one
```

#### Scenario 3: Vault corruption and recovery

```
Given a vault file whose AEAD tag has been tampered with
  and 3 backup files exist (ages: 1h, 1d, 3d)
When the user attempts to open the vault
Then the system MUST refuse to open with a corruption error
  and launch the recovery wizard listing all 3 backups with timestamps and item counts
  and when the user selects the 1h backup
  then the backup is copied to the vault path, the corrupt file is preserved as .corrupt
  and the vault opens successfully
```

#### Scenario 4: TOTP code generation and QR export

```
Given a login item with an embedded TOTP seed (SHA1, 6 digits, 30s period)
When the user requests a TOTP code (GUI: view item; CLI: `npw totp <item>`)
Then the system MUST display the correct 6-digit code per RFC 6238
  and the GUI MUST show a countdown timer for the current period
  and when the user requests QR export with otpauth:// format
  then a QR code is rendered containing the standard otpauth:// URI
  and the QR is scannable by Google Authenticator (verified manually)
```

#### Scenario 5: Concurrent access with exclusive locking

```
Given a vault is open in the GUI (write lock held)
When the user runs `npw item add` via CLI targeting the same vault
Then the CLI MUST fail immediately with exit code 5
  and display "vault file locked by another process"
  and the GUI session is unaffected
  and no data corruption occurs
```

### S2. Testable checklist

#### Vault/crypto

- [ ] Vault create/unlock/lock works offline on Windows/macOS/Linux
- [ ] Wrong password fails with exit code 4 (CLI) and safe UI error (GUI)
- [ ] Tampering with any header byte causes decrypt failure (AAD binding)
- [ ] Change master password works and preserves all items
- [ ] Optional full rotation (`--rotate-vault-key`) re-encrypts payload successfully
- [ ] KDF completes within 3–5s on reference hardware with default params
- [ ] Vault label and item count are readable from header without decryption
- [ ] mlock is attempted for key material; failure logs warning and continues

#### Data integrity/reliability

- [ ] Atomic save verified via crash simulation test (kill during write → original intact)
- [ ] Rolling backups created on every write
- [ ] Backup compaction: keeps all from 24h, one/day for 7d, one/week up to limit
- [ ] Recovery wizard lists backups with timestamps and item counts
- [ ] `npw recover --auto` restores most recent valid backup non-interactively
- [ ] File locking prevents concurrent writes (CLI+GUI, exit code 5 for second writer)

#### Item schemas

- [ ] Login item CRUD with all fields (including URL array with match types)
- [ ] Secure note CRUD with body up to 1MB
- [ ] Passkey reference CRUD with notes field
- [ ] TOTP embedded in login item: add, show code, copy code
- [ ] Standalone TOTP generation with `npw totp` command
- [ ] Item soft delete creates tombstone; item no longer appears in search
- [ ] All item fields validated against schema constraints (max lengths, required fields)

#### Search

- [ ] Encrypted search index built on vault write
- [ ] Search returns matches on title, username, URL, tags
- [ ] Search index rebuilt gracefully if missing/corrupt
- [ ] Search over 10K items completes in ≤200ms

#### Password generation

- [ ] Charset mode: respects length, character set toggles, ambiguous char exclusion
- [ ] Diceware mode: respects word count, separator, optional digit/symbol injection
- [ ] Generated passwords use OS CSPRNG (verified via test with deterministic seed in test mode)
- [ ] Password strength guidance (zxcvbn) rejects score < 3 for master password

#### Clipboard

- [ ] Clipboard auto-clears after configured timeout
- [ ] Clipboard NOT cleared if user changed it after copy
- [ ] Concealed pasteboard flags set on macOS
- [ ] Toast shown after copy with countdown

#### Import/export

- [ ] CSV import with valid data succeeds; unknown columns produce warnings
- [ ] Bitwarden JSON import with valid data succeeds
- [ ] Duplicate detection flags matches on (title + username + URL)
- [ ] Redacted export contains titles/URLs/usernames/timestamps only (no secrets)
- [ ] Encrypted export protected by independent password; re-importable
- [ ] Plaintext export requires explicit flag + warning confirmation

#### TOTP

- [ ] TOTP codes match RFC 6238 test vectors
- [ ] QR import (GUI) works with camera and fallback to URI paste
- [ ] QR export in otpauth:// format produces scannable standard QR
- [ ] QR export in encrypted format produces QR only npw can decode
- [ ] `--at` flag produces deterministic output for given timestamp

#### Security posture

- [ ] Renderer hardened (contextIsolation, no nodeIntegration, CSP, sandbox)
- [ ] IPC allowlist enforced: renderer cannot call unlisted methods
- [ ] No secrets in logs (verified via automated redaction tests)
- [ ] Networking disabled by default and enforced (CSP + no HTTP deps)
- [ ] Audit trail logs: unlock success/fail, item CRUD, export, config changes
- [ ] Zeroize verified: secret buffers cleared on drop (unit test with memory inspection)

#### Supply chain / release

- [ ] Signed artifacts (.dmg, .msi/.exe, .AppImage/.deb) + published SHA-256 checksums
- [ ] SBOMs generated and published (Rust + npm)
- [ ] `cargo audit` and `npm audit` clean (or exceptions documented)
- [ ] Fuzz targets: 10M iterations with no crashes
- [ ] Crypto + vault modules: 100% line coverage
- [ ] CLI commands: 80%+ line coverage
- [ ] Documentation deliverables complete

#### Migration

- [ ] Schema migration prompts user before upgrade (GUI dialog, CLI prompt)
- [ ] Migration creates backup before modifying vault
- [ ] `npw downgrade` converts back for reversible schema changes
- [ ] `npw downgrade` refuses for one-way schema changes with explanation
- [ ] `--upgrade` CLI flag skips interactive prompt

---

## T. Open Questions / Future Work

- Encrypted attachments (external files) design and transactional semantics (v0.2+).
- Sync design (opt-in, privacy-preserving, potentially third-party backends).
- Browser extension/autofill (high risk, separate threat model).
- Biometric unlock that binds keychain item to biometric prompt (macOS/Windows) with careful UX and security review.
- Secret "session lock" with memory-only reauth (PIN) separate from master password.
- Hardware key integration for 2FA code storage (not typical for TOTP but consider).
- Custom fields on items (deferred from v0.1.0 to reduce schema complexity).
- CLI daemon/agent session model for faster scripting (deferred; stateless model accepted for v0.1.0).
- Auto-update mechanism (Electron autoUpdater, requires networking).
- Formal accessibility compliance (explicitly deferred with no current timeline).
- Persistent encrypted search index as separate file for performance at scale (current: inside vault, rebuilt on write).

---

## U. Decision Log (v0.1.0)

1. **Crypto core language**: Rust core + N-API addon for Electron; Rust CLI.
    - Rationale: security, performance, auditability, consistent crypto implementation.
    - See: [G0](#g0-crypto-core-language--decided), [I](#i-application-architecture)

2. **OS keychain usage**: Opt-in Quick Unlock storing `vault_key` in OS keychain; OFF by default.
    - Rationale: convenience without storing master password; preserves file-only offline protection.
    - See: [L0](#l0-os-keychain-usage--decided)

3. **Attachments**: Deferred for v0.1.0; only file references with warnings.
    - Rationale: reduces complexity and data-loss/security risks at launch.
    - See: [H0](#h0-attachments--decided-deferred)

4. **Networking**: None in v0.1.0; enforced by build and CSP; optional future opt-in.
    - Rationale: reduce attack surface and privacy risk; align with local-first launch.
    - See: [M0](#m0-networking-policy--decided)

5. **Passkeys/WebAuthn**: Reference-only with notes field; no private key storage.
    - Rationale: aligns with platform authenticator realities and avoids unsafe export assumptions.
    - See: [D8](#d8-passkeys--webauthn-support-definition-v010), [H5d](#h5d-passkey-reference-schema)

6. **Item schemas**: Strict fixed fields per item type; no custom fields in v0.1.0.
    - Rationale: reduces schema complexity, simplifies validation/fuzzing/migration. Custom fields deferred.
    - See: [H5a](#h5a-login-item-schema)–[H5d](#h5d-passkey-reference-schema)

7. **CLI session model**: Stateless — every command re-derives keys via Argon2id. No daemon, no session file.
    - Rationale: simplicity and security. Accepts 3–5s per-command KDF cost.
    - See: [J1](#j1-session-model)

8. **URL model**: Array of `{url, match}` tuples where match is `exact | domain | subdomain`.
    - Rationale: enables future autofill preparation while remaining simple. First URL is primary.
    - See: [H5a](#h5a-login-item-schema)

9. **GUI framework**: Svelte (SvelteKit) for the Electron renderer.
    - Rationale: smaller compiled bundle, less boilerplate, good Electron integration.
    - See: [K0](#k0-framework)

10. **Config format**: TOML at XDG-compliant paths.
    - Rationale: human-readable, Rust-native serde support, standard paths.
    - See: [J6](#j6-configuration-system)

11. **Password strength**: Combined zxcvbn + entropy calculation + hard minimums (12 chars/4 words, score ≥ 3).
    - Rationale: zxcvbn provides meaningful feedback; entropy adds signal; hard minimums prevent bypass.
    - See: [G3](#g3-master-password-handling)

12. **IPC failure**: Hard restart — kill main process, force re-authentication.
    - Rationale: prioritizes data integrity over convenience. Simple recovery model.
    - See: [I5](#i5-ipc-failure-handling)

13. **Concurrency**: Exclusive write lock, first writer wins, immediate error for second process.
    - Rationale: simplest correct model. No conflict resolution needed.
    - See: [D9](#d9-concurrency-and-file-locking)

14. **Migration UX**: Prompt before upgrade with automatic backup. `npw downgrade` for reversible changes.
    - Rationale: user consent before data transformation; reversibility where possible.
    - See: [H7](#h7-migration-strategy)

15. **Clipboard**: Configurable timeout (10–90s, default 30s), concealed pasteboard flags, disable option with warning.
    - Rationale: balances security with user control. Concealed flags prevent clipboard history capture.
    - See: [D4](#d4-clipboard-handling)

16. **Search**: Encrypted search index inside vault file, rebuilt on every write.
    - Rationale: scales better than decrypt-and-scan for large vaults; single file management.
    - See: [D5](#d5-search-filtering-favorites), [H8](#h8-search-index)

17. **TOTP**: Full generator with countdown + QR export in both otpauth:// and encrypted formats.
    - Rationale: replaces standalone authenticator app. Dual QR formats for interop + secure transfer.
    - See: [D6](#d6-totp-rfc-6238)

18. **Password generator**: Both charset-random and diceware modes. Diceware default for master password.
    - Rationale: charset for site passwords (compatibility), diceware for master passwords (memorability + entropy).
    - See: [D3](#d3-password-generation)

19. **Import duplicates**: Warn on match (title + username + URL). Interactive skip/overwrite/keep-both.
    - Rationale: prevents messy re-imports without false-positive auto-merges.
    - See: [D7](#d7-importexportbackup)

20. **Backups**: Every write + compaction (all from 24h, one/day for 7d, one/week up to limit).
    - Rationale: comprehensive coverage without unbounded growth.
    - See: [D7](#d7-importexportbackup)

21. **Observability**: Structured JSON logs at XDG_STATE_HOME, configurable level (default info), 10MB rotation, correlation IDs.
    - Rationale: enables debugging user-reported issues. Structured format enables tooling.
    - See: [N](#n-observability-telemetry-and-logging)

22. **Error UX (GUI)**: Toast + retry for all vault operation errors. Non-blocking.
    - Rationale: avoids disrupting user workflow for non-critical errors. Vault stays unlocked.
    - See: [K12](#k12-error-ux)

23. **Accessibility**: Not a target for v0.1.0 or foreseeable future.
    - See: [E](#accessibility), [B](#non-goals)

24. **Redacted export**: Titles + metadata only (titles, URLs, usernames, timestamps, item types). All secrets stripped.
    - Rationale: useful for item inventory sharing without exposing secrets.
    - See: [D7](#d7-importexportbackup)

25. **Vault header metadata**: Optional vault label (0–64 bytes) + item count in plaintext header.
    - Rationale: enables multi-vault management UX. Accepts name + cardinality leakage trade-off.
    - See: [G9](#g9-metadata-leakage-stance), [H2](#h2-binary-layout-v1)

26. **Rust addon isolation**: Main process (not utility process).
    - Rationale: hard-restart IPC policy means recovery is identical regardless. Main process is simpler.
    - See: [G0](#g0-crypto-core-language--decided)

27. **Vault corruption recovery**: Recovery wizard listing backups with timestamps + item counts. `npw recover` CLI.
    - Rationale: combined approach gives both guided recovery and automated fallback.
    - See: [D10](#d10-error-handling-and-recovery)

28. **Distribution**: GitHub releases only. Signed binaries. No auto-update in v0.1.0.
    - Rationale: simplest release pipeline. Auto-update requires networking (explicitly excluded).
    - See: [P1](#p1-distribution-strategy-v010)

29. **Test coverage gates**: Crypto + vault 100%, CLI 80%+, GUI smoke only, fuzz 10M iterations.
    - Rationale: highest coverage where stakes are highest (crypto). Pragmatic for CLI/GUI.
    - See: [O4](#o4-test-coverage-gates-must)

30. **KDF target**: 3–5 seconds with m=512MiB, t=4, p=4.
    - Rationale: prioritizes GPU attack resistance over unlock speed. Accepted for stateless CLI model.
    - See: [G2](#g2-kdf-parameters-defaults--bounds)

31. **Audit trail**: Log security events (unlock, CRUD, export, config, backup) at info level.
    - Rationale: enables post-breach forensics for a local app without telemetry.
    - See: [N2](#n2-audit-trail-security-events)

32. **Memory protection**: mlock + zeroize with graceful degradation (log warning if mlock fails).
    - Rationale: defense-in-depth for key material. Only ~1MB needs locking. Graceful failure avoids crashes.
    - See: [G8](#g8-secure-memory-handling)

33. **Rollback**: Previous binary + `npw downgrade` for reversible schema changes.
    - Rationale: completes the prompt-before-upgrade safety net. Refuse one-way downgrades rather than corrupt.
    - See: [H7](#h7-migration-strategy)

34. **Risk focus**: Supply chain is the primary documented risk.
    - See: [W](#w-risk-register)

35. **TOTP QR format**: Both otpauth:// (default, interop) and encrypted QR (npw-to-npw). User picks at export.
    - See: [D6](#d6-totp-rfc-6238)

36. **Acceptance criteria format**: Given/When/Then for top 5 complex flows + testable checklist for everything else.
    - See: [S](#s-acceptance-criteria-v010)

37. **Desktop addon packaging (implementation note)**: During development/CI, build `npw-addon` via Cargo and copy the compiled shared library to `apps/desktop/native/npw-addon.node` for Electron main-process loading.
    - Rationale: keeps Electron↔Rust bridge explicit and reproducible without introducing a separate packaging system in early milestones.
    - See: [I](#i-application-architecture)

---

## V. Security Defaults Summary (One Page)

**Vault/crypto**

- KDF: Argon2id, default m=512 MiB, t=4, p=4 (targeting 3–5s unlock)
- AEAD: XChaCha20-Poly1305
- Header binds via AAD; strict parsing
- Plaintext header contains: crypto params, optional vault label, item count
- Memory protection: mlock + zeroize (graceful degradation if mlock fails)

**App behavior**

- Networking: **disabled** (no HTTP deps; CSP `connect-src 'none'`)
- Telemetry: **none**
- Auto-lock: **5 minutes** inactivity (configurable 1–60)
- Lock on suspend/screen lock: **on** (best effort Linux)
- Clipboard clear: **30 seconds** (configurable 10–90; concealed pasteboard flags)
- Reveal password: requires explicit action; SHOULD auto-hide after 30 seconds
- OS keychain Quick Unlock: **off by default**; explicit warning required to enable
- Exports: redacted by default (titles + metadata); plaintext secrets require explicit flag + warning
- Backups: encrypted rolling backups with compaction; every write triggers backup
- Password strength: zxcvbn score ≥ 3 required for master password; hard minimum 12 chars or 4 words
- CLI session: stateless (re-derive keys every command)
- Audit trail: security events logged at info level

**Error handling**

- GUI errors: toast + retry (non-blocking)
- IPC failure: hard restart, force re-authentication
- Vault corruption: recovery wizard with backup selection
- Concurrency: exclusive write lock, first writer wins, immediate error for second

---

## W. Risk Register

### W1. Supply chain compromise (HIGH)

**Risk:** Rust crate or npm dependencies could be compromised (typosquatting, maintainer account takeover, malicious update).

**Impact:** Attacker gains code execution within the build, potentially exfiltrating secrets or backdooring the vault format.

**Mitigations:**
- Pin all dependency versions (`Cargo.lock` + npm lockfile committed).
- Run `cargo audit` and `npm audit` in CI on every PR and release build.
- Generate and publish SBOMs with every release.
- Target SLSA level 2 build provenance.
- Minimize dependency tree; prefer well-audited crates with active maintenance.
- Review new dependencies before adoption (maintenance status, security history, license).
- Monitor dependency advisories via automated tooling.

**Residual risk:** A zero-day in a pinned dependency could still affect released builds before an advisory is published. Mitigation: rapid response process for dependency advisories.

### W2. Memory safety — secrets in memory (MEDIUM)

**Risk:** Decrypted secrets (vault_key, plaintext items) could be swapped to disk, captured via core dump, or read by a local attacker with sufficient privileges.

**Impact:** Secret material exposed outside the vault file's encryption boundary.

**Mitigations:**
- `mlock`/`VirtualLock` for key material and decrypted buffers (graceful degradation if unavailable).
- `zeroize` all secret buffers on drop.
- Disable core dumps where platform APIs allow.
- Secrets held in memory only while vault is unlocked; cleared on lock.

**Residual risk:** Cannot fully prevent a privileged local attacker or kernel-level malware from reading process memory. Documented as out-of-scope threat.

### W3. User error — forgotten master password (MEDIUM)

**Risk:** User forgets master password with no recovery path. All vault data is permanently inaccessible.

**Impact:** Complete data loss for that vault.

**Mitigations:**
- Clear warning during vault creation: "There is no password recovery. If you forget your master password, your data cannot be recovered."
- Default to diceware passphrase mode during vault creation (more memorable).
- Encourage encrypted backups with a separate known password.
- No backdoor by design — this is a feature, not a bug.

**Residual risk:** Users may still forget passwords despite warnings. This is an inherent property of zero-knowledge encryption.

### W4. Vault file loss or disk failure (MEDIUM)

**Risk:** Single-file vault with no sync means disk failure = data loss.

**Impact:** All vault data lost if no backups exist or backups are on the same disk.

**Mitigations:**
- Automatic encrypted backups on every write with compaction.
- User documentation emphasizing off-device backup importance.
- Encrypted export feature for manual backups to external storage.

**Residual risk:** Users who don't maintain off-device backups risk total loss. Sync is deferred to v0.2+.

### W5. Electron renderer compromise (LOW-MEDIUM)

**Risk:** Despite hardening, a vulnerability in the Svelte app or Electron could allow renderer-side code execution.

**Impact:** Attacker could attempt to escalate via IPC to access vault data.

**Mitigations:**
- `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`.
- Strict CSP (`connect-src 'none'`, `script-src 'self'`).
- IPC allowlist with type/length/value validation.
- Renderer never receives vault_key or raw secret material unless explicitly requested for display.
- Hard restart on IPC anomalies.

**Residual risk:** Zero-day in Chromium/Electron could bypass sandbox. Mitigated by keeping Electron updated.

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
