---
cairn: tasks
change: kerberos-legacy-and-preparation
---

- [x] Move the channel binding vocabulary to a new rfc5801 module, with the GS2 header assembly
- [x] Point SCRAM at it, so the header is written once
- [x] Add rfc5801::gs2_krb5, its credentials, its failure type, its example and its tags
- [x] Add the RFC 4752 section 3.1 offer and choice as pure functions
- [x] Add rfc4013, SASLprep, against the RFC 3454 tables
- [x] Prepare the PLAIN and SCRAM credentials at their first resume, failing the exchange when they cannot be
- [x] Add rfc2195::cram_md5 behind its feature, pinned by the RFC 2195 exchange
- [x] Split the initial-response property by class for the first server-first mechanism
- [x] Extend the vocabulary, the tag sweep and the exchange fuzz target
- [x] Update the crate header, the README, CONTRIBUTING, the CHANGELOG and the spec
- [x] Re-run fmt, clippy, tests, doctests, rustdoc, coverage and both fuzz targets in every feature shape
