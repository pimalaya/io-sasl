---
cairn: delta
change: missing-mechanisms
---

## ADDED Requirements

### Requirement: Coverage
The crate SHALL carry every SASL mechanism a client can run without an external security library: ANONYMOUS, EXTERNAL, LOGIN, PLAIN, OAUTHBEARER, XOAUTH2 and the three SCRAM profiles, each of those under its plain and its `-PLUS` name. Mechanisms the IANA registry lists but a live specification discourages SHALL NOT be added, DIGEST-MD5 being Historic by RFC 6331. The GSSAPI family SHALL stay out, its tokens coming from a Kerberos implementation that performs I/O of its own.

### Requirement: EXTERNAL
`SaslExternal` (RFC 4422 appendix A) SHALL answer `Start` with the optional authorization identity, or an empty payload when there is none, and complete `Ok` on `PeerFinished`. It SHALL carry no secret of its own, the outer channel being what authenticates.

### Requirement: One exchange, three profiles
The SCRAM exchange SHALL be written once, generic over the digest. A profile SHALL add exactly three things: the digest, the two mechanism names it is registered under, and the exchange it is pinned by. A profile SHALL NOT restate the message assembly, since a family implemented once per digest is the duplication this crate was extracted to remove.

### Requirement: Channel binding
The credentials SHALL carry one of three channel binding cases, and the case SHALL pick both the GS2 header and the mechanism name the coroutine reports. A client that does not support binding SHALL send `n` and report the plain name. A client that supports binding whose server advertised no `-PLUS` name SHALL send `y` and report the plain name, as RFC 5802 section 6 requires, so that a server supporting binding detects the stripped offer. A client binding the exchange SHALL send `p=<kind>` and report the `-PLUS` name.

The binding material SHALL be supplied by the caller with the credentials, along with which of `tls-exporter`, `tls-unique` and `tls-server-end-point` it came from. The crate SHALL NOT extract it, having no TLS session to ask.

## MODIFIED Requirements

### Requirement: Feature gates
The SCRAM family SHALL live behind the `scram` cargo feature, which pulls in the HMAC, PBKDF2, SHA-2 and base64 crates and carries the SHA-256 and SHA-512 profiles. The SHA-1 profile SHALL live behind `scram-sha-1`, which adds its digest crate and is off by default. The SHA-256 and SHA-512 profiles SHALL NOT be gated apart, sharing one digest crate; the rest of the crate SHALL build with neither feature.

### Requirement: Vocabulary
The `mechanism` module SHALL hold `SaslMechanism` (the tag, knowing its registered wire name) and `Sasl` (a tag paired with the credentials of one mechanism). `SaslMechanism` SHALL carry a variant per registered name whatever the build enables, `-PLUS` names included, since a consumer matching a server capability list has to name a mechanism it cannot run. `Sasl` SHALL carry one variant per profile rather than per name, the `-PLUS` names following from the credentials.

### Requirement: Credential locality
Each credential struct SHALL live in the module of the mechanism that transmits it, next to that mechanism's coroutine and failure type, or in the family module when several mechanisms share it. A struct serving one mechanism SHALL be convertible into `Sasl`; one shared by several SHALL NOT, an impl having no way to guess which variant was meant. A mechanism excluded by a cargo feature SHALL take its `Sasl` variant with it, an exchange this build cannot run having no shape to describe.

### Requirement: Constructors
Each mechanism SHALL be built from the credential struct it shares with its `Sasl` variant, so a consumer matching on that enum reaches the mechanism it needs without restating the fields.

### Requirement: Message computation
The client-first-message SHALL carry the GS2 header its channel binding calls for, and the client-final-message SHALL carry `c=`, the base64 of that header followed by the binding material. The username SHALL be escaped as a `saslname`, `=` as `=3D` and `,` as `=2C`. The salted password, client proof and expected server signature SHALL follow RFC 5802 section 3, in the digest of the profile.

### Requirement: Test vectors
Every profile SHALL be pinned by a full exchange. SHA-1 SHALL be pinned by the exchange published in RFC 5802 section 5 and SHA-256 by the one published in RFC 7677 section 3, both for the user `user` with the password `pencil`. Where no specification publishes an exchange, as for SHA-512 and for every bound exchange, the vector SHALL be derived by an implementation outside this crate that reproduces both published exchanges byte for byte, and SHALL NOT be regenerated from this crate's own output.

### Requirement: Specification vectors
Each mechanism SHALL be pinned by unit tests asserting the exact payloads its specification defines. Where a specification publishes an exchange, that exchange SHALL be the vector; when the test fails, the code is wrong, never the vector. Where none is published, the vector SHALL come from an implementation outside this crate that reproduces the published ones byte for byte, and SHALL NOT be regenerated from this crate's own output, which would pin nothing.

### Requirement: Dependencies
The vocabulary and the mechanisms needing no cryptography SHALL depend only on `secrecy`, `log` and `thiserror`. `base64`, `hmac`, `pbkdf2` and `sha2` SHALL be optional and pulled by the `scram` feature, `sha1` by `scram-sha-1`. A random number generator SHALL NOT be a dependency, and neither SHALL a TLS implementation.
