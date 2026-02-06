# Threat Model Summary

In scope:
- offline attacker with vault-file access
- vault tampering and parser corruption
- local process boundary hardening (Electron IPC + native bridge)

Out of scope:
- fully compromised OS / kernel malware
- hardware compromise

Key controls:
- Argon2id KDF (stored parameter set in header)
- XChaCha20-Poly1305 authenticated encryption
- header AAD binding for envelope and payload
- structured validation and command exit codes
