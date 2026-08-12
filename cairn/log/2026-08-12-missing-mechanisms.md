---
cairn: log
change: missing-mechanisms
landed: 2026-08-12
---

# Missing mechanisms: EXTERNAL, the other SCRAM profiles, and channel binding

Brought the crate up to the mechanisms a client can run without an external security library, which is the line the specifications draw rather than the one a mail client's usage draws. Six mechanism names became twelve.

EXTERNAL landed under rfc4422, where the SASL framework defines it: one message carrying an optional authorization identity, no secret, no computation. It is how a client says the outer channel already authenticated it, which on the wire is what a TLS client certificate amounts to.

SCRAM went from one profile to three, and from one name per profile to two. The exchange moved into a family module at rfc5802, generic over its digest, so a profile module is now three things: `pub type SaslScramSha256 = SaslScram<Sha256>`, an impl naming the two mechanisms the digest is registered under, and the exchange it is pinned by. SHA-1 is the original of RFC 5802 and sits behind its own `scram-sha-1` feature, off by default so the weakest profile is only ever compiled on request; SHA-256 and SHA-512 share the sha2 crate and are therefore not gated apart, since a feature that changes no dependency buys nothing. The three profiles also share one `SaslScramCreds`, which cost the `From` impl for it: one struct cannot pick among three `Sasl` variants, so the profile is named at the call site.

Channel binding is the part that changes what the crate can defend against. `SaslScramCreds` now carries a `SaslScramChannelBinding` in the three cases RFC 5802 defines, and the case picks both the GS2 header and the mechanism name the coroutine reports, so a bound exchange announces `-PLUS` by construction rather than by the caller remembering to. The middle case is the one implementations skip: a client that supports binding whose server advertised no `-PLUS` name sends `y`, not `n`, which is how a server that does support binding learns its offer was stripped in flight. The binding material comes from the caller with the credentials, as the client nonce already did, since asking a TLS session what it exported is not something an I/O-free crate can do. pimalaya-stream is untouched, and it is what will have to expose the exporter before a consumer can fill any of this in.

Vectors were the other half of the work. RFC 5802 section 5 pins SHA-1 and RFC 7677 section 3 pins SHA-256, but the SHA-512 draft says only `[[TBD: Add an example]]`, and no specification publishes a bound exchange. Those vectors were derived from the RFC 5802 algorithm by an implementation written outside this crate, which reproduces both published exchanges byte for byte before deriving anything; a vector regenerated from this crate's own output would pin nothing. The Rust implementation then reproduced all four independently, which is what the passing tests are.

The tests grew with the set: the contract properties, the tag sweep and both fuzz targets now carry every profile bound and unbound, and the tag sweep walks each profile twice, since the name it reports depends on its credentials rather than on its type alone. 44 unit tests, 5 contract properties, 1 tag sweep and 9 doctests pass in every feature shape.

Coverage now reads 97.81% rather than 100%, and the six lines it counts short are not untested. They sit inside the generic exchange, where the compiler emits instructions once per digest and tarpaulin attributes one address per source line: a two-line `format!`, the tail of the constant-time comparison, and four match-arm patterns whose bodies count as covered. Mutating any of them fails between one and five tests, which is how it was checked rather than argued. Both engines report the same six, the code was left alone, and CONTRIBUTING and the testing spec now name the figure to expect and the check to redo.

Capabilities moved: mechanisms, scram (renamed from scram-sha-256, the capability now being the family), packaging, testing.
