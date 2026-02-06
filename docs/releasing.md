# Releasing `npw` (v0.1.x)

This repo ships via **GitHub Releases** only.

## Workflows

- `CI` (`.github/workflows/ci.yml`): runs on PRs/pushes.
- `Release` (`.github/workflows/release.yml`): builds CLI + desktop artifacts and uploads them to the GitHub Release (also generates `SHA256SUMS.txt`).
- `SBOM` (`.github/workflows/sbom.yml`): generates SBOMs and uploads them to the GitHub Release (`sbom-rust.zip`, `sbom-npm.cdx.json`).

## Versioning

The GitHub release **tag** must match these manifest versions:

- Root `package.json` (`version`)
- Desktop `apps/desktop/package.json` (`version`)
- Rust workspace `Cargo.toml` (`[workspace.package].version`)

Example: tag `v0.1.0` requires manifest versions `0.1.0`.

## Signing (scaffolding)

### Checksums signature (optional)

If these GitHub Actions secrets are set, the `Release` workflow will also upload an ASCII-armored detached signature:

- `NPW_GPG_PRIVATE_KEY` (ASCII-armored private key material)
- `NPW_GPG_PASSPHRASE`

This produces `SHA256SUMS.txt.asc` alongside `SHA256SUMS.txt`.

### Desktop artifact signing (Electron)

Desktop signing/notarization is handled by `electron-builder` when the appropriate signing secrets are configured in CI.
The `Release` workflow is structured so you can add those secrets without changing code.
