---
cairn: spec
capability: scram-sha-256
status: current
---

# SCRAM-SHA-256

The salted challenge/response mechanism of RFC 5802, in its SHA-256 profile (RFC 7677). It is the only mechanism needing cryptography, the only one performing mutual authentication, and the reason the crate exists: it used to be implemented twice, once in io-imap and once in io-smtp, with two independent bug surfaces.

### Requirement: Feature gate
The mechanism SHALL live behind the `scram` cargo feature, which pulls in the HMAC, PBKDF2, SHA-256 and base64 crates. The feature is enabled by default, and the rest of the crate SHALL build without it.

### Requirement: Caller-provided nonce
`SaslScramSha256::new` SHALL take the client nonce as an explicit argument. The crate SHALL NOT depend on a random number generator, since an I/O-free mechanism cannot produce entropy and the caller owns that decision.

### Requirement: Exchange
The mechanism SHALL answer `Start` with the client-first-message, the server-first challenge with the client-final-message, and the server-final challenge with an empty acknowledgement, then complete `Ok` on `PeerFinished`.

### Requirement: Message computation
The client-first-message SHALL carry the GS2 header `n,,` for a client without channel binding, and the client-final-message SHALL carry `c=biws`, its base64. The username SHALL be escaped as a `saslname`, `=` as `=3D` and `,` as `=2C`. The salted password, client proof and expected server signature SHALL follow RFC 5802 section 3.

### Requirement: Server verification
The server nonce SHALL extend the client nonce, failing with `NonceMismatch` otherwise. The server-final-message SHALL carry `v=` matching the expected signature, failing with `ServerSignatureMismatch` otherwise, `ServerError` when it carries `e=`, and `InvalidServerFinal` when it carries neither.

### Requirement: No silent skip
`PeerFinished` arriving before the server signature was verified SHALL complete `Err` with `ServerSignatureNotVerified`, never `Ok`. A protocol accepting its own success reply without feeding the server-final-message back therefore fails instead of silently skipping mutual authentication.

### Requirement: Test vector
The exchange published in RFC 7677 section 3, for the user `user` with the password `pencil`, SHALL be covered by a test asserting the client-first-message, the client-final-message and the acceptance of the server-final-message.
