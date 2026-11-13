---
cairn: change
id: mechanism-hardening
status: landed
created: 2026-11-13
---

# Prepare in every build, guard the separators, hide the payloads, read SCRAM by its grammar

## Why

Four defects of unequal weight, found by the family audit of 2026-11-13 (SASL-04 to SASL-07), each in what a mechanism does with the strings it is handed.

SASLprep was a cargo feature. The spec says PLAIN and SCRAM SHALL prepare, CONTRIBUTING called the feature correctness rather than a mechanism, and two of the three protocol crates take this crate without default features and never named it, so their SCRAM derived its key from the password as typed. RFC 5802 leaves a client two choices, prepare or refuse non-ASCII, and that build did neither. A password with a no-break space, a compatibility character or a decomposed accent then fails against a server that stored the prepared form, and fails looking like a wrong password.

Separator bytes went out as given. OAUTHBEARER wrote its authorization identity raw where the GS2 header it borrows escapes `,` and `=`, which SCRAM and GS2-KRB5 already did through the same helper. A `%x01` inside a username, a host or a token added a key/value pair to an OAUTHBEARER or XOAUTH2 message. A NUL inside a PLAIN field shifted the three fields, which SASLprep refuses as a control character, but only where the feature was on.

`SaslYield` derived `Debug`, and for PLAIN, LOGIN, OAUTHBEARER and XOAUTH2 the `WantsWrite` payload is the password or the token, so any `{:?}` on a yield or on a coroutine state printed it as a byte list, this crate's own test panics included. The spec already said secrets never appear in debug output. The keys SCRAM derives were also plain values, left in freed memory.

SCRAM read its server messages by attribute name rather than by position: attributes in any order, the last of a repeated one winning, the reserved `m=` ignored where RFC 5802 section 5.1 says its presence fails the authentication, and a server-final-message with extensions after the signature refused as bad base64 although the grammar allows them.

## What

Drop the `saslprep` feature and make unicode-normalization a dependency of every build. The claim it rests on was checked in the dependency graph of the core build: the crate is `no_std` without its `std` feature, which is off, and pulls tinyvec with `alloc` only. PLAIN keeps preparing, as the spec already asked of it. RFC 4616 is less firm than RFC 5802 here, asking for prepared strings at verification and recommending SASLprep for it, so a server comparing raw bytes would see a prepared password differ from a typed one: that is the behaviour of every default build since 0.1.0 and now of the others too.

Route the OAUTHBEARER authorization identity through the GS2 escape, and refuse a `%x01` in any OAUTHBEARER or XOAUTH2 credential at the first resume with a new `InvalidCreds` variant. PLAIN needs no variant of its own: with preparation unconditional a NUL fails as `Preparation`, in every build.

Write `Debug` for `SaslYield` by hand, printing `WantsWrite([n bytes])`. Hold the salted password and the client, stored and server keys in buffers wiped on drop, and the prepared copy of the password in PLAIN and SCRAM likewise, through the `zeroize` that secrecy re-exports, so no dependency is added. This does not reach the internal state of the digest and HMAC crates nor the arrays they return by value; that takes their own `zeroize` feature and is left out.

Read the server-first-message positionally, nonce then salt then iteration count, everything after being extensions that are not read. Refuse `m=` wherever it appears in either server message with a new `MandatoryExtension` variant. Read the server-final-message up to its first comma.

The server-first parse is stricter than before in one way a server could notice: attributes out of order are refused. The grammar fixes the order, the authentication message is computed over the bytes as received, and both ends have to agree on what they mean.
