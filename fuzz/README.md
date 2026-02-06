# Fuzzing

This repo uses `cargo-fuzz` for best-effort fuzz targets.

## Setup

- Install: `cargo install cargo-fuzz --locked`
- Run a target (example): `cargo fuzz run vault_header_parser -- -max_total_time=60`

## Targets

- `vault_header_parser`: fuzz `npw_core::parse_vault_header`
- `payload_cbor_parser`: fuzz `npw_core::VaultPayload::from_cbor`
- `import_csv_parser`: fuzz CSV decoding + TOTP URI parsing
- `import_bitwarden_json`: fuzz Bitwarden JSON shape parsing + TOTP parsing paths

