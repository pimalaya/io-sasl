---
cairn: log
change: scram-bounds
landed: 2026-11-13
---

# SCRAM bounds its iteration count and validates its nonce

Three inputs of the exchange were taken as given, found by the family audit of 2026-11-13 (SASL-01, SASL-02, SASL-03) and each reproduced by a test before anything changed.

The iteration count had no ceiling. The server announces it and the derivation runs inside one resume, so `i=4294967295` was minutes of PBKDF2 that no timeout covers and no caller can cancel. `SaslScram::new` now takes a `SaslScramOptions` next to the credentials, and a count above `max_iterations` (five million unless set) completes `IterationCountTooHigh` before a single round runs. The test announces one more than the default and failed on the old code by getting a client-final-message back.

It had no floor either. `i=1` was derived, and `i=0` too, which the PBKDF2 crate runs as one round, so a party holding the transport could ask for a proof one HMAC deep and guess passwords against it offline. A count below `min_iterations` (4096 unless set, the figure RFC 5802 section 5.1 and RFC 7677 section 4 give servers) completes `IterationCountTooLow`. Both failures carry the count and the bound, so the message tells a user with a legacy server which option to lower and to what. `i=` is also parsed as the `posit-number` of the grammar now: `0`, `+4096` and `04096` are syntax errors whatever the options, where Rust's integer parser alone accepted all three.

The nonce was sent as given. An empty one made the "server nonce extends the client nonce" check vacuous and the authentication message constant, so a recorded server-first and server-final pair would verify again. The first resume now completes `InvalidNonce` for a nonce shorter than 18 bytes or holding a comma or a byte outside printable ASCII, the lossy replacement of invalid UTF-8 included. The alphabet is the RFC's; the length is this crate's floor, chosen under the two published exchanges (20 and 24 characters) and at the 24 characters the protocol crates draw. The validation sits at the first resume, next to SASLprep, so the constructor stays infallible and a std client that fills an empty nonce before building the session keeps working.

The options went into an argument rather than into `SaslScramCreds`: bounds are not credentials, the family shape is `new(<mandatory>, opts)`, and a new credentials field would have broken every struct literal in the applications where the argument breaks one call site per protocol crate. Those three crates still have to carry the options to their own callers, which is their change to make once this one is released; until then they compile against 0.1 and are unbounded.

Not done here, and the maintainer's call: having the first step yield for random bytes instead of trusting the caller to have drawn some. It closes the nonce question for good and changes the yield vocabulary shared with io-imap.

The fuzz targets used to skip any challenge announcing more than 1024 iterations, with a comment calling the cost a question for the consumer. They now hand 1024 to the mechanisms as their ceiling and feed everything, so the ceiling is under test and a regression shows as a libFuzzer timeout. They also fold the fuzzed nonce bytes onto the alphabet and pad them, since a raw fuzzed nonce would now end nearly every exchange at its first step; the `exchange` target keeps one SCRAM-SHA-256 driven with the nonce as fuzzed, for the refusal.

Breaking: `SaslScram::new` takes `(creds, opts)`, `SaslScramError` gains three variants, and a nonce that used to be sent is now refused. The next release is 0.2.0.

Capabilities moved: scram, mechanisms, testing.

Verified: `cargo test --all-features` passed (85 unit tests, 5 of them new, 5 contract properties, 1 tag sweep, 12 doctests), as did `--no-default-features` (48 unit tests) and the default shape (79); each new test fails with its check removed; `cargo build --no-default-features` clean; both fuzz targets ran 30 seconds without a finding; tarpaulin reads 99.18%, the four lines it counts short being older ones. `cargo clippy --all-features --all-targets -- -D warnings` stops on ten `unused import: coroutine::*` errors in test modules, the same ten as before this change.
