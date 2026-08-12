---
cairn: tasks
change: missing-mechanisms
---

- [x] Add the EXTERNAL mechanism under rfc4422
- [x] Derive the missing test vectors with an implementation outside the crate, checked against the published ones
- [x] Generalise the SCRAM exchange over its digest, in a family module under rfc5802
- [x] Add the SHA-1 profile behind its own cargo feature, pinned by the RFC 5802 exchange
- [x] Add the SHA-512 profile, pinned by a derived exchange
- [x] Add the three channel binding cases, and let the binding pick the reported mechanism name
- [x] Share one credential struct across the profiles, and drop the From impl a shared struct cannot have
- [x] Extend the vocabulary, the contract properties, the tag sweep and both fuzz targets
- [x] Update the crate header, the README, CONTRIBUTING, the CHANGELOG and the spec
- [x] Re-run fmt, clippy, tests, doctests, rustdoc, coverage and both fuzz targets in every feature shape
