---
cairn: delta
change: kerberos-legacy-and-preparation
---

## ADDED Requirements

### Requirement: CRAM-MD5
`SaslCramMd5` (RFC 2195) SHALL answer `None` with `WantsRead`, being server-first, then answer the challenge with the username, a space, and the HMAC-MD5 of that challenge keyed by the shared secret in lowercase hexadecimal, and complete `Ok` on `Done`. It SHALL live behind the `cram-md5` cargo feature, being a legacy mechanism whose server stores a plaintext-equivalent secret.

### Requirement: GS2-KRB5
`SaslGs2Krb5` (RFC 5801) SHALL answer `None` with the GS2 header followed by the first token its credentials carry, relay every later `Input` verbatim, and complete `Ok` on `Done`. The header SHALL carry the channel binding flag and the escaped authorization identity, and the binding SHALL pick between `GS2-KRB5` and `GS2-KRB5-PLUS`. What it relays it SHALL NOT read, verify or count, as for GSSAPI.

### Requirement: Credential preparation
PLAIN and SCRAM SHALL prepare their username and password with SASLprep (RFC 4013) before sending or deriving anything, as RFC 4616 and RFC 5802 ask, and SHALL complete `Err` when a credential carries a code point the profile prohibits. The preparation SHALL apply every rule that changes the bytes going out: the non-ASCII space mapping, the removals, NFKC normalization and the prohibited output tables. The bidirectional rule and the unassigned code points of RFC 3454 MAY be left out, both rejecting strings rather than changing them.

## MODIFIED Requirements

### Requirement: Coverage
The crate SHALL carry ANONYMOUS, CRAM-MD5, EXTERNAL, GSSAPI, GS2-KRB5, LOGIN, PLAIN, OAUTHBEARER, XOAUTH2 and the three SCRAM profiles, the Kerberos and SCRAM ones under their plain and their `-PLUS` names where they have both. Mechanisms the IANA registry lists but a live specification discourages SHALL NOT be added, DIGEST-MD5 being Historic by RFC 6331. Proprietary schemes SHALL NOT be added either, NTLM being the one servers still offer.

### Requirement: GSSAPI
`SaslGssapi` (RFC 4752) SHALL answer `None` with the first GSS-API token, which the credentials carry, and every `Input` with that input verbatim, then complete `Ok` on `Done`. Resumed out of order it SHALL complete `Err` with `OutOfOrder`.

It SHALL NOT read, verify or count the tokens: the caller feeds it what its own security context produced from each peer message, and only that context knows when the handshake is over.

The security layer negotiation of RFC 4752 section 3.1 SHALL be carried as pure functions rather than as coroutine steps, since its four octets travel wrapped and only the caller can move them through its context. `SaslGssapiSecurityLayerOffer::parse` SHALL read the layer bitmask and the maximum message size, failing on a truncated offer or one carrying no defined layer, and `SaslGssapiSecurityLayerChoice::to_bytes` SHALL assemble the answer, truncating a size larger than the three octets the format gives it.

### Requirement: Channel binding
The channel binding vocabulary SHALL live in the `rfc5801` module, the GS2 bridge being what defines the header and its flags, and SCRAM SHALL share it rather than restate it. The credentials SHALL carry one of three channel binding cases, and the case SHALL pick both the GS2 header and the mechanism name the coroutine reports. A client that does not support binding SHALL send `n` and report the plain name. A client that supports binding whose server advertised no `-PLUS` name SHALL send `y` and report the plain name, as RFC 5802 section 6 requires, so that a server supporting binding detects the stripped offer. A client binding the exchange SHALL send `p=<kind>` and report the `-PLUS` name.

The binding material SHALL be supplied by the caller with the credentials, along with which of `tls-exporter`, `tls-unique` and `tls-server-end-point` it came from. The crate SHALL NOT extract it, having no TLS session to ask.

### Requirement: Contract properties
The integration tests SHALL state the coroutine contract as properties over the whole mechanism set rather than as statements about single mechanisms, so a mechanism added later is held to the same edges: every mechanism answers `None` the way its specification speaks, every mechanism completes on `Done`, and no mechanism answers stray input with a success. Where a class of mechanism genuinely differs, the property SHALL be split by an exhaustive predicate rather than weakened for everyone: a server-first mechanism answers `None` with `WantsRead` and has no initial response to inline, a mechanism performing mutual authentication of its own completes `Err` on `Done` at every point before its verification ran, and a mechanism computing its own payloads refuses stray input with its unexpected-challenge failure.

### Requirement: Coverage
Every line of the library SHALL be reachable from a test, measured with cargo-tarpaulin over all features. Production code SHALL NOT be shaped to move the number: code no meaningful test can reach is deleted rather than covered, and code a tool misreads is documented rather than rewritten. The fuzz package SHALL be excluded from the measured surface, which tarpaulin.toml does.

The measured figure is 98.22%. The lines it counts short are second lines of multi-line expressions and match-arm patterns, most of them in code the compiler instantiates once per digest while tarpaulin attributes one address per source line; mutating any of them fails several tests. A drop below that figure SHALL be treated as untested code until a mutation shows otherwise.

### Requirement: Dependencies
The vocabulary and the mechanisms needing no cryptography SHALL depend only on `secrecy`, `log` and `thiserror`. `base64`, `hmac`, `pbkdf2` and `sha2` SHALL be optional and pulled by the `scram` feature, `sha1` by `scram-sha-1`, `md-5` by `cram-md5`, and `unicode-normalization` by `saslprep`. A random number generator SHALL NOT be a dependency, and neither SHALL a TLS implementation or a Kerberos one.
