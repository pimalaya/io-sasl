---
cairn: delta
change: client-surface-removal
---

## REMOVED Requirements

### Requirement: Command surface
Removed with the capability. A trait whose one required method is the protocol's own loop does not move the framing boundary, it names it in the wrong crate.

### Requirement: No transport
Removed with the capability.

### Requirement: Caller-owned failure
Removed with the capability. The conclusion survives it and belongs wherever the surface lands: the failure type is whoever drives the exchange's, not this crate's.

### Requirement: Send on the async surface only
Removed with the capability. The conclusion survives it too: an async surface needs `Send` as a supertrait and on the future its methods return, a blocking one needs neither.

### Requirement: Surface coverage
Removed with the capability.

### Requirement: Surface tests
Removed with the capability.

## MODIFIED Requirements

### Requirement: no_std
`#![no_std]` SHALL be unconditional and `extern crate alloc` SHALL be declared, since the crate allocates. The crate SHALL stay alloc-only: no `extern crate std`, no client layer, no I/O.

### Requirement: Dependencies
The vocabulary and the mechanisms needing no cryptography SHALL depend only on `secrecy`, `log` and `thiserror`. `base64`, `hmac`, `pbkdf2` and `sha2` SHALL be optional and pulled by the `scram` feature, `sha1` by `scram-sha-1`, `md-5` by `cram-md5`, and `unicode-normalization` by `saslprep`. A random number generator SHALL NOT be a dependency, and neither SHALL a TLS implementation or a Kerberos one.

Every feature SHALL exist because it pulls a crate in, which is the only justification for one.

### Requirement: Coverage
Every line of the library SHALL be reachable from a test, measured with cargo-tarpaulin over all features. Production code SHALL NOT be shaped to move the number: code no meaningful test can reach is deleted rather than covered, and code a tool misreads is documented rather than rewritten. The fuzz package SHALL be excluded from the measured surface, which tarpaulin.toml does.

The measured figure is 98.22%. The lines it counts short are second lines of multi-line expressions and match-arm patterns, most of them in code the compiler instantiates once per digest while tarpaulin attributes one address per source line; mutating any of them fails several tests. A drop below that figure SHALL be treated as untested code until a mutation shows otherwise.

### Requirement: Documented exchanges
Every mechanism module SHALL open with a runnable example driving its exchange step by step, compiled and run as a doctest. The example SHALL show the mechanism a consumer reaches for, not a fragment of it: what the protocol crate sends first, what it feeds back, and where the exchange ends, since driving that sequence correctly is the whole contract.
