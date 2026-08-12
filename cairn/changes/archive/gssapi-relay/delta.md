---
cairn: delta
change: gssapi-relay
---

## ADDED Requirements

### Requirement: Computed and relayed mechanisms
A mechanism whose payloads follow from its credentials SHALL compute them here. A mechanism whose payloads come from a security context this crate cannot host SHALL be carried as a relay instead of being left out: the crate holds the exchange, the caller holds the context. A relay SHALL claim nothing it cannot check, and its module SHALL name what it leaves to the caller.

### Requirement: GSSAPI
`SaslGssapi` (RFC 4752) SHALL answer `None` with the first GSS-API token, which the credentials carry, and every `Input` with that input verbatim, then complete `Ok` on `Done`. Resumed out of order it SHALL complete `Err` with `OutOfOrder`.

It SHALL NOT read, verify or count the tokens: the caller feeds it what its own security context produced from each peer message, and only that context knows when the handshake is over. The security layer negotiation of RFC 4752 section 3.1 SHALL stay with the caller until this crate carries it as pure functions.

## MODIFIED Requirements

### Requirement: Coverage
The crate SHALL carry ANONYMOUS, EXTERNAL, GSSAPI, LOGIN, PLAIN, OAUTHBEARER, XOAUTH2 and the three SCRAM profiles, each of the latter under its plain and its `-PLUS` name. Mechanisms the IANA registry lists but a live specification discourages SHALL NOT be added, DIGEST-MD5 being Historic by RFC 6331.

### Requirement: Three-cased resume
`SaslArg` SHALL carry three cases: `None` before anything is exchanged, `Input(&[u8])` for the bytes the mechanism asked for, and `Done` when the peer ended the exchange without speaking again. The first resume of an exchange SHALL take `None`.

`Input` SHALL be named for its role rather than for its origin. For a mechanism computing its own payloads it carries the peer's challenge, base64-decoded by the protocol crate; for a relay it carries what the caller's own security context produced from the peer's message. One name covers both, and no mechanism needs a yield of its own to say which it expects.

### Requirement: Two-cased yield
`SaslYield` SHALL carry `WantsWrite(Vec<u8>)` for raw, not yet base64-encoded bytes to send, and `WantsRead` when the mechanism has nothing to send and needs what the caller reads next. Both variants SHALL be io-imap's, down to the word, so that a driver written against both crates matches on one vocabulary, and both SHALL name the caller's action rather than the mechanism's. What the two crates differ on is not the yield but what comes back from a read, which is why the argument carrying it is named for its role; see the three-cased resume. An empty `WantsWrite` payload is an acknowledgement, which a protocol whose framing already ended the exchange MAY drop instead of writing.

### Requirement: End of exchange
The mechanisms performing no mutual authentication SHALL complete `Ok(())` on `Done`. A mechanism performing mutual authentication of its own SHALL complete `Err` on `Done` whenever its verification has not run, so a protocol cannot end an exchange early by omission. A relay SHALL complete `Ok(())`, having verified nothing and having nothing to refuse for.

### Requirement: Unexpected resume
A mechanism computing its own payloads SHALL complete `Err` when resumed with input it does not expect or out of order. A relay SHALL refuse only what it can recognise, which is being resumed out of order, and SHALL forward input it cannot judge rather than guess that it is stray.

### Requirement: Contract properties
The integration tests SHALL state the coroutine contract as properties over the whole mechanism set rather than as statements about single mechanisms, so a mechanism added later is held to the same edges: every mechanism answers `None` with a response, every mechanism completes on `Done`, and no mechanism answers stray input with a success. Where a class of mechanism genuinely differs, the property SHALL be split by an exhaustive predicate rather than weakened for everyone: a mechanism performing mutual authentication of its own completes `Err` on `Done` at every point before its verification ran, and a mechanism computing its own payloads refuses stray input with its unexpected-challenge failure, neither of which a relay can do.
