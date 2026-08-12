---
cairn: spec
capability: scram
status: current
---

# SCRAM

The salted challenge/response family of RFC 5802, in three digest profiles and six registered names. It is the only family needing cryptography, the only one performing mutual authentication, and the reason the crate exists: it used to be implemented twice, once in io-imap and once in io-smtp, with two independent bug surfaces.

### Requirement: Feature gates
The family SHALL live behind the `scram` cargo feature, which pulls in the HMAC, PBKDF2, SHA-2 and base64 crates and carries the SHA-256 and SHA-512 profiles. The SHA-1 profile SHALL live behind `scram-sha-1`, which adds its digest crate. The SHA-256 and SHA-512 profiles SHALL NOT be gated apart, sharing one digest crate; the rest of the crate SHALL build with neither feature.

### Requirement: One exchange, three profiles
The exchange SHALL be written once, generic over the digest. A profile SHALL add exactly three things: the digest, the two mechanism names it is registered under, and the exchange it is pinned by. A profile SHALL NOT restate the message assembly, since a family implemented once per digest is the duplication this crate was extracted to remove.

### Requirement: Caller-provided nonce
The client nonce SHALL be a field of the credentials. The crate SHALL NOT depend on a random number generator, since an I/O-free mechanism cannot produce entropy and the caller owns that decision.

### Requirement: Exchange
The mechanism SHALL answer `None` with the client-first-message, the server-first challenge with the client-final-message, and the server-final challenge with an empty acknowledgement, then complete `Ok` on `Done`.

### Requirement: Message computation
The client-first-message SHALL carry the GS2 header its channel binding calls for, and the client-final-message SHALL carry `c=`, the base64 of that header followed by the binding material. The username SHALL be escaped as a `saslname`, `=` as `=3D` and `,` as `=2C`. The salted password, client proof and expected server signature SHALL follow RFC 5802 section 3, in the digest of the profile.

### Requirement: Channel binding
The channel binding vocabulary SHALL live in the `rfc5801` module, the GS2 bridge being what defines the header and its flags, and SCRAM SHALL share it rather than restate it. The credentials SHALL carry one of three channel binding cases, and the case SHALL pick both the GS2 header and the mechanism name the coroutine reports. A client that does not support binding SHALL send `n` and report the plain name. A client that supports binding whose server advertised no `-PLUS` name SHALL send `y` and report the plain name, as RFC 5802 section 6 requires, so that a server supporting binding detects the stripped offer. A client binding the exchange SHALL send `p=<kind>` and report the `-PLUS` name.

The binding material SHALL be supplied by the caller with the credentials, along with which of `tls-exporter`, `tls-unique` and `tls-server-end-point` it came from. The crate SHALL NOT extract it, having no TLS session to ask.

### Requirement: Server verification
The server nonce SHALL extend the client nonce, failing with `NonceMismatch` otherwise. The server-final-message SHALL carry `v=` matching the expected signature, failing with `ServerSignatureMismatch` otherwise, `ServerError` when it carries `e=`, and `InvalidServerFinal` when it carries neither.

### Requirement: No silent skip
`Done` arriving before the server signature was verified SHALL complete `Err` with `ServerSignatureNotVerified`, never `Ok`. A protocol accepting its own success reply without feeding the server-final-message back therefore fails instead of silently skipping mutual authentication.

### Requirement: Test vectors
Every profile SHALL be pinned by a full exchange. SHA-1 SHALL be pinned by the exchange published in RFC 5802 section 5 and SHA-256 by the one published in RFC 7677 section 3, both for the user `user` with the password `pencil`. Where no specification publishes an exchange, as for SHA-512 and for every bound exchange, the vector SHALL be derived by an implementation outside this crate that reproduces both published exchanges byte for byte, and SHALL NOT be regenerated from this crate's own output.
