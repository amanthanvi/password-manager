# Security Defaults

- KDF: Argon2id (`m=512 MiB`, `t=4`, `p=4`)
- AEAD: XChaCha20-Poly1305
- HKDF: SHA-256
- Networking: disabled by default in renderer CSP (`connect-src 'none'`)
- Electron renderer hardening: `contextIsolation=true`, `nodeIntegration=false`, `sandbox=true`
- No telemetry by default
