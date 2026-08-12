---
cairn: spec
capability: coroutines
status: current
---

# Coroutines

Every SASL mechanism is exposed as an I/O-free coroutine: a resumable state machine computing the payloads the mechanism sends and checking the ones it receives. The protocol crate driving it owns the socket, the framing and the transport encoding. The contract is shared by every mechanism and lives in the crate-root `coroutine` module.

### Requirement: Coroutine contract
Each mechanism SHALL implement `SaslCoroutine`, declaring an `Error` associated type, a `mechanism()` method returning its `SaslMechanism` tag, and a `resume(&mut self, arg: SaslArg<'_>)` method returning `SaslCoroutineState<SaslYield, Result<(), Error>>` (`Yielded` or `Complete`).

### Requirement: Three-cased resume
`SaslArg` SHALL carry three cases: `None` before anything is exchanged, `Input(&[u8])` for the bytes the mechanism asked for, and `Done` when the peer ended the exchange without speaking again. The first resume of an exchange SHALL take `None`.

`Input` SHALL be named for its role rather than for its origin. For a mechanism computing its own payloads it carries the peer's challenge, base64-decoded by the protocol crate; for a relay it carries what the caller's own security context produced from the peer's message. One name covers both, and no mechanism needs a yield of its own to say which it expects.

### Requirement: Two-cased yield
`SaslYield` SHALL carry `WantsWrite(Vec<u8>)` for raw, not yet base64-encoded bytes to send, and `WantsRead` when the mechanism has nothing to send and needs what the caller reads next. Both variants SHALL be io-imap's, down to the word, so that a driver written against both crates matches on one vocabulary, and both SHALL name the caller's action rather than the mechanism's. What the two crates differ on is not the yield but what comes back from a read, which is why the argument carrying it is named for its role; see the three-cased resume. An empty `WantsWrite` payload is an acknowledgement, which a protocol whose framing already ended the exchange MAY drop instead of writing.

### Requirement: State naming
A mechanism's private state enum SHALL name each variant after what the next resume is about to do, never after what the previous one did: `SendUsername`, `SendPassword`, `Done` rather than `Start`, `SentUsername`, `SentPassword`, a vocabulary of its own unrelated to the argument enum. The convention is io-imap's, so a reader moving between the two crates reads the same state machine.

### Requirement: Initial response
A mechanism answering `None` with `WantsWrite` has an initial response (RFC 4422); one answering `WantsRead` is server-first. Whether the protocol carries the initial response inline, and whether it should against a given server, SHALL NOT be decided here.

### Requirement: End of exchange
The mechanisms performing no mutual authentication SHALL complete `Ok(())` on `Done`. A mechanism performing mutual authentication of its own SHALL complete `Err` on `Done` whenever its verification has not run, so a protocol cannot end an exchange early by omission. A relay SHALL complete `Ok(())`, having verified nothing and having nothing to refuse for.

### Requirement: Unexpected resume
A mechanism computing its own payloads SHALL complete `Err` when resumed with input it does not expect or out of order. A relay SHALL refuse only what it can recognise, which is being resumed out of order, and SHALL forward input it cannot judge rather than guess that it is stray.

