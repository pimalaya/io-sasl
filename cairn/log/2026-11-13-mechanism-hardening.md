---
cairn: log
change: mechanism-hardening
landed: 2026-11-13
---

# Preparation in every build, guarded separators, hidden payloads, SCRAM read by its grammar

Four findings of the family audit of 2026-11-13 (SASL-04 to SASL-07), each reproduced by a test before anything changed.

SASLprep stopped being a feature. The spec said PLAIN and SCRAM SHALL prepare and two of the three protocol crates built this crate without the feature that did it, so their SCRAM derived its key from the password as typed, where RFC 5802 lets a client either prepare or refuse non-ASCII. The two preparation tests, ungated, failed in a build without the feature: the soft hyphen stayed in the SCRAM username and the no-break space in the PLAIN password. The feature is gone and unicode-normalization is a dependency of every build. Before choosing that over keeping the feature, the claim it rests on was checked in the graph of the core build: unicode-normalization 0.1.26 is `no_std` unless its `std` feature is on, which it is not, and it brings tinyvec with `alloc` and nothing else, so the core build now resolves log, secrecy, thiserror, zeroize, unicode-normalization and tinyvec. No `no_std` target is installed in the dev shell, so this was read in the graph and in the two crates' sources, not proven by a cross build.

One thing is the maintainer's to weigh. PLAIN prepares in every build now, as its default build always did. RFC 4616 is softer than RFC 5802 on this, asking for prepared strings at the server's verification and recommending SASLprep there, so a server that compares raw bytes sees a prepared password differ from the typed one. A password holding a control character is also refused outright. Neither is new for a default build; both are new for the protocol crates that built without the feature.

Separators are guarded. OAUTHBEARER wrote its authorization identity raw, and now escapes it through the helper SCRAM and GS2-KRB5 already shared, so `a=b,c@example.com` goes out as `a=3Db=2Cc@example.com`. A `%x01` in an OAUTHBEARER or XOAUTH2 credential, which added a key/value pair to the message, fails the first resume with a new `InvalidCreds`. A NUL in a PLAIN field, which shifted the three fields wherever the feature was off, needs no variant of its own: preparation refuses it as a control character, in every build.

`SaslYield` no longer derives `Debug`. It printed the `WantsWrite` payload as a byte list, and that payload is the password or the token for PLAIN, LOGIN, OAUTHBEARER and XOAUTH2; this crate's own tests did it in their panic messages. It prints `WantsWrite([13 bytes])` now, and `SaslCoroutineState` follows since it only wraps the yield. The salted password and the client, stored and server keys of SCRAM live in buffers wiped on drop, and so does the prepared copy of the password in PLAIN and SCRAM, through the `zeroize` secrecy re-exports, so no dependency was added. The limit is stated rather than hidden: the HMAC and digest crates keep their own state and return arrays by value, and wiping those takes their `zeroize` feature, which was not turned on. No test covers the wiping, since observing it means reading freed memory.

SCRAM reads its server messages by the grammar. The server-first-message is nonce, salt, iteration count, in that order, and anything after is an extension that is not read; before, attributes were matched by name wherever they stood and the last of a repeated one won. The reserved `m=` fails with a new `MandatoryExtension` in either message, where it was ignored. The server-final-message is read up to its first comma, so `v=...,x=...` verifies instead of failing as bad base64, and an `e=` value no longer swallows what follows it. The fuzz oracle of the SCRAM target reads the salt and the count by position too, and compares the acknowledged challenge up to its first comma.

Ten test modules imported `coroutine::*` next to a glob of their own module that already brings it, which the current compiler reports as unused and `cargo clippy --all-targets -- -D warnings` refused. The ten imports are gone and the check is green in every feature shape.

Breaking, on top of the previous change of the day: the `saslprep` feature no longer exists, so a manifest naming `io-sasl/saslprep` has to drop it; `SaslScramError` gains `MandatoryExtension`, `SaslOauthbearerError` and `SaslXoauth2Error` gain `InvalidCreds`; `SaslYield` prints differently.

Capabilities moved: mechanisms, scram, packaging.

Verified: `cargo test --all-features` passed (94 unit tests, 9 of them new, 5 contract properties, 1 tag sweep, 12 doctests), as did the default shape (88), `--no-default-features` (61) and `--no-default-features --features cram-md5` (65); `cargo clippy --all-targets -- -D warnings` clean in the five feature shapes; `cargo build --no-default-features` clean; both fuzz targets ran 30 seconds without a finding; tarpaulin reads 99.40%, the three lines it counts short being older ones.
