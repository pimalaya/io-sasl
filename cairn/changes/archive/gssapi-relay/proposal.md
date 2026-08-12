---
cairn: change
id: gssapi-relay
status: landed
created: 2026-08-12
---

# Carry GSSAPI as a relay, and name the argument for its role

## Why

GSSAPI was ruled out on the grounds that a crate performing no I/O cannot produce Kerberos tokens. That is true and it is not a reason to leave the mechanism out, because producing the tokens is not the only work: there is also the SASL exchange around them, the name that goes on the wire, the initial response, and the sequencing of who speaks when. A consumer writing GSSAPI today writes all of it, including the part every other mechanism gets from this crate.

The objection that survived was narrower and turned out to be an assumption: that the coroutine would have to ask its caller to compute, which the two-cased yield cannot express. It does not have to ask. The caller can advance its security context before resuming, exactly as it decodes base64 before resuming, and hand the result in. Then the coroutine is a relay and the existing vocabulary is enough.

What that costs is one word. `Challenge` claimed the bytes came from the peer, which is true for every mechanism computing its own payloads and false for a relay, where they come from the caller's own context.

## What

Rename `SaslArg::Challenge` to `Input`, naming the argument for its role rather than for its origin, so one vocabulary covers both kinds of mechanism, and let the yield's read side take io-imap's own word, `WantsRead`, since what a yield names is the caller's action and the caller does read. The nuance the earlier `WantsChallenge` was carrying, that what comes back is not raw bytes off a socket, belongs on the argument and now lives there.

Add `rfc4752::gssapi`: the first token in the credentials, every input forwarded verbatim, `Ok` on `Done`, `OutOfOrder` when resumed out of sequence. Document what it does not do, which is read tokens, count rounds, verify anything, or assemble the security layer negotiation.

State the two properties a relay breaks as per-class predicates in the integration tests rather than weakening them for everyone: a relay cannot refuse stray input, and it cannot refuse an early end. Both matches are exhaustive, so the next mechanism has to answer both questions.
