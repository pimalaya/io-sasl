---
cairn: tasks
change: gssapi-relay
---

- [x] Rename `SaslArg::Challenge` to `Input`, and the yield's read side to io-imap's `WantsRead`
- [x] Document on both types which one carries the nuance, and why
- [x] Add rfc4752::gssapi, its credentials, its failure type and its example
- [x] Add the GSSAPI tag, its `Sasl` variant and its `From` impl
- [x] Split the stray-input and early-end properties by class in tests/exchange.rs
- [x] Add GSSAPI to the tag sweep and to the exchange fuzz target
- [x] Update the crate header, the README, the CHANGELOG and the spec
- [x] Re-run fmt, clippy, tests, doctests, rustdoc, coverage and both fuzz targets
