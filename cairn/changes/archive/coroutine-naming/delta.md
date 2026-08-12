---
cairn: delta
change: coroutine-naming
---

## ADDED Requirements

### Requirement: State naming
A mechanism's private state enum SHALL name each variant after what the next resume is about to do, never after what the previous one did: `SendUsername`, `SendPassword`, `Done` rather than `Start`, `SentUsername`, `SentPassword`. The convention is io-imap's, so a reader moving between the two crates reads the same state machine.

## MODIFIED Requirements

### Requirement: Two-cased yield
`SaslYield` SHALL carry `WantsWrite(Vec<u8>)` for raw, not yet base64-encoded bytes to send, and `WantsChallenge` when the mechanism has nothing to send and needs the peer's next challenge. Both variants SHALL name what the caller is being asked to do, as io-imap's yield does; the read side is named after the challenge rather than after the read, since the caller strips its framing and its base64 before the bytes become one. An empty `WantsWrite` payload is an acknowledgement, which a protocol whose framing already ended the exchange MAY drop instead of writing.
