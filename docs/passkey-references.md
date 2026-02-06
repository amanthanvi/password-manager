# Passkey References

`npw` models passkeys as reference metadata entries.

Security model:
- no passkey private keys are stored or exported
- entries are metadata only (`rp_id`, display names, credential ID bytes, notes)

Target v0.1.0 behavior (SPEC):
- CLI and GUI list/show actions
- open site and OS passkey manager shortcuts
