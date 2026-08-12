---
cairn: spec
capability: coroutines
status: current
---

# Coroutines

Every SASL mechanism is exposed as an I/O-free coroutine: a resumable state machine computing the payloads the mechanism sends and checking the ones it receives. The protocol crate driving it owns the socket, the framing and the transport encoding. The contract is shared by every mechanism and lives in the crate-root `coroutine` module.

### Requirement: Coroutine contract
Each mechanism SHALL implement `SaslCoroutine`, declaring an `Error` associated type, a `mechanism()` method returning its `SaslMechanism` tag, and a `resume(&mut self, arg: SaslResume<'_>)` method returning `SaslCoroutineState<SaslYield, Result<(), Error>>` (`Yielded` or `Complete`).

### Requirement: Three-cased resume
`SaslResume` SHALL carry three cases: `Start` before anything is exchanged, `Challenge(&[u8])` for an already base64-decoded peer challenge, and `PeerFinished` when the peer ended the exchange without a further challenge. The first resume of an exchange SHALL take `Start`.

### Requirement: Two-cased yield
`SaslYield` SHALL carry `WantsWrite(Vec<u8>)` for raw, not yet base64-encoded bytes to send, and `WantsChallenge` when the mechanism has nothing to send and needs the peer's next challenge. Both variants SHALL name what the caller is being asked to do, as io-imap's yield does; the read side is named after the challenge rather than after the read, since the caller strips its framing and its base64 before the bytes become one. An empty `WantsWrite` payload is an acknowledgement, which a protocol whose framing already ended the exchange MAY drop instead of writing.

### Requirement: State naming
A mechanism's private state enum SHALL name each variant after what the next resume is about to do, never after what the previous one did: `SendUsername`, `SendPassword`, `Done` rather than `Start`, `SentUsername`, `SentPassword`. The convention is io-imap's, so a reader moving between the two crates reads the same state machine.

### Requirement: Initial response
A mechanism answering `Start` with `WantsWrite` has an initial response (RFC 4422); one answering `WantsChallenge` is server-first. Whether the protocol carries the initial response inline, and whether it should against a given server, SHALL NOT be decided here.

### Requirement: End of exchange
The mechanisms performing no mutual authentication SHALL complete `Ok(())` on `PeerFinished`. A mechanism performing mutual authentication SHALL complete `Err` on `PeerFinished` whenever its verification has not run, so a protocol cannot end an exchange early by omission.

### Requirement: Unexpected resume
A mechanism resumed with a challenge it does not expect, or resumed out of order, SHALL complete `Err` with its own unexpected-challenge failure.
