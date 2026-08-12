# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added the `SaslCoroutine` trait, the I/O-free contract every mechanism implements.

  A `mechanism()` method naming the mechanism on the wire, and a `resume(SaslResume)` method returning `SaslCoroutineState<SaslYield, Result<(), Error>>`. `SaslResume` is three-cased (`Start`, `Challenge`, `PeerFinished`) so that the end of an exchange stays distinguishable from a challenge, and `SaslYield` is either `Respond(Vec<u8>)` or `AwaitChallenge` for a server-first mechanism.

- Added the SASL vocabulary, moved from `pimalaya-stream`.

  `SaslMechanism` tags a mechanism and knows its wire name, `Sasl` carries the credentials of one, and `SaslAnonymous`, `SaslLogin`, `SaslPlain`, `SaslOauthbearer`, `SaslXoauth2` and `SaslScramSha256` describe what each mechanism needs.

- Added the ANONYMOUS mechanism following RFC 4505, sending an optional trace token.

- Added the PLAIN mechanism following RFC 4616, sending the NUL-separated authorization identity, authentication identity and password.

- Added the LOGIN mechanism following draft-murchison-sasl-login, sending the username then the password.

  The mechanism sees only the password prompt: the username prompt is the implicit empty challenge whose answer is the initial response, as RFC 4959 defines it.

- Added the OAUTHBEARER mechanism following RFC 7628, sending the GS2 header with the host, port and bearer token.

  A rejected token is acknowledged with the single `%x01` response of RFC 7628 section 3.2.3, then reported as a failure carrying the JSON the server sent.

- Added the XOAUTH2 mechanism following the Google specification, sending the username and bearer token.

  A rejected token is acknowledged with the empty response Google documents, then reported as a failure carrying the JSON the server sent.

- Added the SCRAM-SHA-256 mechanism following RFC 5802 and RFC 7677, behind the `scram` cargo feature.

  Verified against the exchange published in RFC 7677 section 3. The client nonce is a field of `SaslScramSha256` rather than something the mechanism generates, since an I/O-free mechanism cannot produce entropy; carrying it with the credentials means a protocol crate holding a `Sasl` always has everything the exchange needs. An exchange ending before the server signature was verified fails with `ServerSignatureNotVerified` instead of succeeding, so mutual authentication cannot be skipped by omission.

[unreleased]: https://github.com/pimalaya/io-sasl
