---
cairn: spec
capability: server
status: current
---

# Server

The `server` module, behind the `server` feature, is the server side of PLAIN and LOGIN: an I/O-free state machine parsing what a client sends and yielding the credentials for the caller to verify. It checks no password itself.

### Requirement: Contract
`SaslServer::new(mechanism, initial_response)` SHALL build the exchange and `resume(SaslServerArg)` SHALL return a `SaslServerState`: `Challenge(Vec<u8>)` with raw bytes the protocol base64-encodes, `Verify(SaslServerCredentials)` answered with `Verdict(bool)`, `Success { authzid, authcid }` or `Failure(SaslServerError)`. The first resume SHALL take `None`. Responses SHALL arrive base64-decoded; a client cancel SHALL be `Cancel`, and an empty initial response `Some(vec![])`.

### Requirement: PLAIN
PLAIN SHALL read one UTF-8 message `authzid NUL authcid NUL passwd` with exactly two NULs and a non-empty authcid and password, an empty authzid meaning none; anything else SHALL fail `Malformed`. Without an initial response the first state SHALL be `Challenge` with an empty payload.

### Requirement: LOGIN
LOGIN SHALL challenge `Username:` then `Password:`, an initial response standing for the username. Both answers SHALL be non-empty UTF-8, or the exchange fails `Malformed`. The authzid of LOGIN SHALL always be none.

### Requirement: Failures
`Cancel` before the end SHALL fail `Cancelled`, a `false` verdict SHALL fail `Rejected`, and any argument out of order, any resume after a terminal state included, SHALL fail `UnexpectedArg`. `Success` SHALL only follow a `true` verdict on the credentials yielded just before.

### Requirement: Secrecy
The password SHALL travel as a `SecretString`, and neither the `Debug` output of an argument, a state or the exchange nor the logs SHALL carry a response payload or a password.
