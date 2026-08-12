---
cairn: spec
capability: packaging
status: current
---

# Packaging

The crate is published as io-sasl, the I/O-free SASL layer every Pimalaya protocol crate authenticates through.

### Requirement: no_std
`#![no_std]` SHALL be unconditional and `extern crate alloc` SHALL be declared, since the crate allocates. The crate SHALL stay alloc-only: no `extern crate std`, no client layer, no I/O.

### Requirement: Dependencies
The vocabulary and the mechanisms needing no cryptography SHALL depend only on `secrecy`, `log` and `thiserror`. `base64`, `hmac`, `pbkdf2` and `sha2` SHALL be optional and pulled by the `scram` feature, `sha1` by `scram-sha-1`. A random number generator SHALL NOT be a dependency, and neither SHALL a TLS implementation.

### Requirement: Public surface
There SHALL be no re-export at the crate root: consumers reach items through module-qualified paths. Every public item SHALL be documented, enforced by `#![deny(missing_docs)]`.

### Requirement: Licensing
The crate SHALL be dual-licensed MIT OR Apache-2.0, with both license files at the repository root and no per-file header.
