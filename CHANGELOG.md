# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added the `SaslCoroutine` trait, the I/O-free contract every mechanism implements.

  A `mechanism()` method naming the mechanism on the wire, and a `resume(SaslResume)` method returning `SaslCoroutineState<SaslYield, Result<(), Error>>`. `SaslResume` is three-cased (`Start`, `Challenge`, `PeerFinished`) so that the end of an exchange stays distinguishable from a challenge, and `SaslYield` is either `WantsWrite(Vec<u8>)` or `WantsChallenge` for a server-first mechanism.

- Added the SASL vocabulary, moved from `pimalaya-stream`.

  `SaslMechanism` tags a mechanism and knows its wire name, listing every mechanism whatever the build enables, since a consumer reading a server capability list has to name the ones it cannot run. `Sasl` pairs a tag with the credentials of one, and each credential struct lives in the module of the mechanism that transmits it, next to its coroutine. The three SCRAM profiles share `SaslScramCreds`, differing only in their digest.

- Added the ANONYMOUS mechanism following RFC 4505, sending an optional trace token.

- Added the PLAIN mechanism following RFC 4616, sending the NUL-separated authorization identity, authentication identity and password.

- Added the LOGIN mechanism following draft-murchison-sasl-login, sending the username then the password.

  The mechanism sees only the password prompt: the username prompt is the implicit empty challenge whose answer is the initial response, as RFC 4959 defines it.

- Added the OAUTHBEARER mechanism following RFC 7628, sending the GS2 header with the host, port and bearer token.

  A rejected token is acknowledged with the single `%x01` response of RFC 7628 section 3.2.3, then reported as a failure carrying the JSON the server sent.

- Added the XOAUTH2 mechanism following the Google specification, sending the username and bearer token.

  A rejected token is acknowledged with the empty response Google documents, then reported as a failure carrying the JSON the server sent.

- Added the EXTERNAL mechanism following RFC 4422 appendix A, sending the optional authorization identity and letting the outer channel authenticate.

- Added the SCRAM family following RFC 5802, behind the `scram` cargo feature, in three profiles: SHA-256 (RFC 7677) and SHA-512 (draft-melnikov-scram-sha-512) by default, SHA-1 (RFC 5802) behind `scram-sha-1`.

  The exchange is written once and each profile is its digest and the two names it is registered under. It is verified against the exchanges published in RFC 5802 section 5 and RFC 7677 section 3; the SHA-512 and channel-bound vectors, which no specification publishes, were derived by an implementation outside this crate that reproduces both published ones.

  The client nonce is a field of `SaslScramCreds` rather than something the mechanism generates, since an I/O-free mechanism cannot produce entropy; carrying it with the credentials means a protocol crate holding a `Sasl` always has everything the exchange needs. An exchange ending before the server signature was verified fails with `ServerSignatureNotVerified` instead of succeeding, so mutual authentication cannot be skipped by omission.

- Added channel binding, so every SCRAM profile also speaks its `-PLUS` name.

  `SaslScramCreds` carries a `SaslScramChannelBinding`, which the caller extracts from its TLS session: this crate opens no connection and cannot ask a session what it exported. The binding also picks the mechanism name the coroutine reports, so a bound exchange announces `-PLUS` by construction. A client that supports binding without using it sends the `y` flag of RFC 5802 section 6 rather than `n`, so a server supporting it sees that its `-PLUS` offer was stripped in flight.

[unreleased]: https://github.com/pimalaya/io-sasl
