---
cairn: change
id: scram-bounds
status: landed
created: 2026-11-13
---

# Bound the SCRAM iteration count and validate the client nonce

## Why

Three inputs of the SCRAM exchange were taken as given (family audit of 2026-11-13, SASL-01, SASL-02 and SASL-03).

The iteration count comes from the server and the key derivation runs inside one resume, so whoever speaks the server side of the exchange decided how long the caller computes: `i=4294967295` is minutes of PBKDF2 during which no read timeout applies, since no I/O is pending, and which no caller can cancel. The protocol crates hand the challenge over as is, so none of them could refuse it either.

The same count had no floor. `i=1` was derived, and so was `i=0`, which the PBKDF2 crate runs as one round. A party holding the transport could ask for a proof one HMAC deep and test password guesses against it offline at that price, where the salted, iterated proof exists to make each guess cost the full count.

The client nonce was sent as given, an empty one included. The check that the server nonce extends the client nonce is always true for an empty prefix, and with a constant nonce the authentication message repeats, so a recorded server-first and server-final pair verifies again. The three protocol crates draw a nonce when their std `connect` finds the field empty, which made "empty means draw one" a convention this crate never knew about and that only one of their entry points honours. A nonce holding a comma or bytes that are not UTF-8 was also sent, as a broken message or silently altered.

## What

Give `SaslScram::new` a second argument, `SaslScramOptions`, with `min_iterations` and `max_iterations`, both optional. The floor defaults to 4096, the count RFC 5802 section 5.1 and RFC 7677 section 4 ask servers to announce at least, and the ceiling to five million, several times the few hundred thousand the most demanding deployments announce, so no real server trips either. A count outside the bounds fails before anything is derived, with `IterationCountTooLow` or `IterationCountTooHigh`, both carrying the count and the bound so the message says which option to move. The defaults are public constants, for the protocol crates and applications that will document them.

Parse `i=` as the `posit-number` the RFC 5802 grammar asks for, so `0`, `+1` and `01` fail with `InvalidIterationCount` whatever the options say.

Validate the nonce at the first resume, where SASLprep already reports what it refuses, so the constructor stays infallible: at least 18 bytes, printable ASCII, no comma, else `InvalidNonce`. The alphabet is the grammar's. The length is this crate's own floor, not the RFC's, which asks only that the value differ at every authentication: it is short enough for both published exchanges (20 and 24 characters) and long enough that a forgotten or token nonce cannot pass.

The options are an argument rather than fields of `SaslScramCreds` for two reasons. Bounds are not credentials, and the family shape for a coroutine is `new(<mandatory>, opts)` with an all-optional, defaulted options struct. And a field added to the credentials would break every struct literal in the six applications, where a second argument breaks three call sites, one per protocol crate, which have to pass the options through anyway to let a user lower the floor for a legacy server.

Rejected for this change: making the first step yield for random bytes, so that no caller can forget the nonce. It is the stronger fix and it changes the yield vocabulary this crate shares with io-imap down to the word, which is the maintainer's decision and touches three dependants. The validation stands on its own either way.

Rejected: a nonce newtype with a fallible constructor. It would make an invalid nonce unrepresentable, and it would break every credentials literal as well as the empty-then-drawn convention the std clients rely on, for a check the first resume makes just as surely.
