# Backups and Recovery

`npw` writes encrypted vault files and validates them with authenticated encryption.

Current baseline:
- `vault check` verifies decryptability and basic structure.
- corrupted/tampered vaults fail authentication and are rejected.

Planned in v0.1.0 completion scope:
- automatic encrypted backup rotation
- `npw recover` CLI workflow
- GUI backup recovery flow
