# TOTP

Current baseline:
- cryptographic primitives required for TOTP support are present in the Rust core.

Target v0.1.0 behavior (SPEC):
- RFC 6238 TOTP generation
- support for SHA1/SHA256/SHA512
- `otpauth://` import/export
- deterministic CLI output with `--at`
- GUI code countdown and QR import/export
