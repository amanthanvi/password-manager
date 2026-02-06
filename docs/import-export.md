# Import and Export

Current baseline:
- import/export command scaffolding is planned but not fully implemented yet.

Target v0.1.0 behavior (SPEC):
- CSV + Bitwarden JSON import
- duplicate detection on `(title + username + primary URL)`
- redacted exports by default
- explicit opt-in for plaintext secret export
- encrypted portable export format (`.npwx`)
