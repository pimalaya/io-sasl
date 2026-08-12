---
cairn: log
change: gssapi-relay
landed: 2026-08-12
---

# GSSAPI as a relay, and the argument named for its role

Added rfc4752::gssapi, renamed the resume argument's payload from `Challenge` to `Input`, and gave the yield's read side io-imap's own word, `WantsRead`.

GSSAPI had been ruled out twice on the same reasoning: a crate that performs no I/O cannot produce Kerberos tokens, since they come from a library that reads a credential cache and talks to a KDC. That part holds. What did not hold was the conclusion, which rested on an unexamined assumption: that the coroutine would have to ask its caller to compute, and that asking needs a yield variant the two-cased `SaslYield` cannot express. It does not have to ask. The caller advances its security context before resuming, exactly as it strips base64 before resuming, and hands the result in. The coroutine is then a relay, and the vocabulary already in the crate is enough.

So the mechanism is thirty lines: the first token rides in `SaslGssapiCreds`, every `Input` is forwarded verbatim as the next response, `Done` completes `Ok`, and being resumed out of sequence completes `OutOfOrder`. What it gives a consumer is the SASL half it would otherwise write again: the name on the wire, the initial response so SASL-IR works, and the sequencing. What it refuses to pretend is everything else, and the module says so in as many words: it does not read the tokens, does not count the rounds, verifies nothing, and does not assemble the security layer negotiation of RFC 4752 section 3.1. That last one fits here later as two pure functions, since its four octets and authorization identity are SASL rather than GSS.

The rename is what makes one vocabulary cover both kinds of mechanism. `Challenge` asserted where the bytes came from, which is the peer for eleven mechanisms and the caller's own context for the twelfth. `Input` asserts only what they are for, and both variant docs now say which is which rather than leaving a reader to infer it.

That also settles a name this crate had argued itself out of once. The read side of the yield was called `WantsChallenge` on the grounds that the caller does more than read, stripping framing and base64 before the bytes become a challenge. True, but it is the wrong place for the nuance: a yield names the caller's action, and the caller does read. So the yield takes io-imap's `WantsRead` and a driver written against both crates now matches on one vocabulary, while what comes back from that read, which is what actually differs between the two crates and between the two kinds of mechanism, is described where it belongs, on `SaslArg::Input`.

Two properties in tests/exchange.rs had to be split rather than weakened, and the split is the interesting part of this change. A relay cannot refuse stray input, since the round count belongs to a context it cannot see, and it cannot refuse an early end, since mutual authentication lives inside tokens it does not read. Both are now exhaustive predicates next to the properties they qualify, so a mechanism added later has to answer both questions before the file compiles, and the universal property that survives is the one that matters most: no mechanism ever answers stray input with a success.

49 unit tests, 5 contract properties, 1 tag sweep and 10 doctests pass in every feature shape, and both fuzz targets drive the relay alongside the rest.

Capabilities moved: coroutines, mechanisms, testing.
