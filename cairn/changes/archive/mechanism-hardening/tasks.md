---
cairn: tasks
change: mechanism-hardening
---

- [x] Check in the dependency graph that unicode-normalization builds no_std and alloc-only
- [x] Write the regression tests and watch them fail, the preparation ones in a build without the feature
- [x] Drop the `saslprep` feature and prepare in every build
- [x] Escape the OAUTHBEARER authorization identity
- [x] Refuse `%x01` in the OAUTHBEARER and XOAUTH2 credentials
- [x] Print a `WantsWrite` payload as its length in debug output
- [x] Wipe the derived SCRAM keys and the prepared passwords on drop
- [x] Read the server-first-message positionally, refuse `m=`, cut the server-final-message at its first comma
- [x] Follow the new parse in the SCRAM fuzz oracle
- [x] Remove the ten test imports the compiler reports unused
- [x] Update the crate header, CONTRIBUTING, the CHANGELOG and the spec
- [x] Re-run fmt, tests, clippy in every feature shape, the core build and both fuzz targets
- [ ] Drop `io-sasl/saslprep` from the manifests naming it once this crate is released
