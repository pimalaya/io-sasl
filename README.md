# 🔐 I/O SASL [![Documentation](https://img.shields.io/docsrs/io-sasl?style=flat&logo=docs.rs&logoColor=white)](https://docs.rs/io-sasl/latest/io_sasl) [![Coverage](https://img.shields.io/codecov/c/github/pimalaya/io-sasl/master?style=flat&logo=codecov&logoColor=white)](https://codecov.io/gh/pimalaya/io-sasl) [![Matrix](https://img.shields.io/badge/chat-%23pimalaya-blue?style=flat&logo=matrix&logoColor=white)](https://matrix.to/#/#pimalaya:matrix.org) [![Mastodon](https://img.shields.io/badge/news-%40pimalaya-blue?style=flat&logo=mastodon&logoColor=white)](https://fosstodon.org/@pimalaya)

Simple Authentication and Security Layer (SASL) client library for Rust

This library is composed of a single layer:

- Low-level **I/O-free** coroutines: no_std-compatible state machines containing the whole SASL mechanism logic, usable anywhere

There is no client layer, because the crate performs no I/O of any kind: it computes what a mechanism sends and checks what it receives, while the protocol library driving it (I/O IMAP, I/O SMTP, ...) owns the socket, the framing and the transport-level base64.

## Table of contents

- [Features](#features)
- [RFC coverage](#rfc-coverage)
- [Usage](#usage)
- [Examples](#examples)
- [AI policy](https://github.com/pimalaya/.github/blob/master/AI_POLICY.md)
- [License](#license)
- [Social](#social)
- [Contributing](./CONTRIBUTING.md)
- [Sponsoring](#sponsoring)

## Features

- **I/O-free mechanisms**: no_std state machines with no sockets and no async runtime, resumable from any blocking, async or in-memory test harness.
- **Every registered mechanism a mail client meets**: ANONYMOUS, CRAM-MD5, EXTERNAL, GSSAPI, GS2-KRB5, LOGIN, PLAIN, OAUTHBEARER, XOAUTH2 and the three SCRAM profiles, each computing exactly the payloads its specification defines.
- **Kerberos as a building block**: both Kerberos mechanisms are carried as relays, since their tokens come from an implementation that talks to a KDC. The library holds the exchange, the caller holds the security context, and GS2-KRB5 adds the channel binding the older one cannot have.
- **Credentials prepared the way the specifications ask**: PLAIN and SCRAM run their username and password through SASLprep, so a password with a non-breaking space or a decomposed accent matches what the server stored instead of failing as a wrong password.
- **Channel binding**: every SCRAM profile also speaks its `-PLUS` name, which ties the exchange to the TLS connection it runs on and is what stops a machine in the middle from replaying it.
- **Downgrade detection**: a client that supports channel binding says so even when the server offered no `-PLUS` name, so a server that does support it sees the stripped offer and stops.
- **Shared vocabulary**: one set of credential types describing what each mechanism needs, shared by every protocol library and by the account wizards that prompt for them.
- **Mutual authentication that cannot be skipped**: an exchange ending before SCRAM verified the server signature fails instead of quietly succeeding.
- **Caller-owned randomness**: the SCRAM client nonce and channel binding are supplied with the credentials, so entropy and TLS stay decisions of the application and the exchange is reproducible in tests.
- **Credential redaction**: passwords and tokens stay inside secret wrappers and never reach the logs.

> [!TIP]
> I/O SASL is written in [Rust](https://www.rust-lang.org/) and uses [cargo features](https://doc.rust-lang.org/cargo/reference/features.html) for everything that pulls in an extra crate: `scram` for the SHA-2 profiles and `saslprep` for the credential preparation, both enabled by default, `scram-sha-1` for the legacy SCRAM profile and `cram-md5` for the legacy digest mechanism, both off unless a server asks for them. The default feature set is declared in [Cargo.toml](./Cargo.toml) or on [docs.rs](https://docs.rs/crate/io-sasl/latest/features).

## RFC coverage

| RFC    | What is covered                                                                                                       |
|--------|-----------------------------------------------------------------------------------------------------------------------|
| [2195] | The CRAM-MD5 mechanism: the keyed digest answering a server challenge, and the only server-first exchange here                |
| [4013] | SASLprep: the mapping, normalization and prohibitions a client applies to a username and a password before sending either |
| [4422] | The SASL framework: the notion of an authentication exchange, of an initial client response, and the EXTERNAL mechanism that defers to the outer channel |
| [4505] | The ANONYMOUS mechanism: an optional trace token identifying an unauthenticated user                                  |
| [4616] | The PLAIN mechanism: the authorization identity, authentication identity and password triple                          |
| [4752] | The GSSAPI mechanism: the exchange around the Kerberos tokens, which the caller's own security context produces        |
| [5801] | The GS2 bridge: the header a Kerberos mechanism opens with, the three channel binding flags every `-PLUS` name rests on, and GS2-KRB5 itself |
| [5802] | The SCRAM family: salted password derivation, the client proof, verification of the server signature, the SHA-1 profile, and the channel binding flags including the one that reports a stripped offer |
| [5929] | The TLS channel bindings a `-PLUS` exchange can be bound to below TLS 1.3, `tls-unique` and `tls-server-end-point`     |
| [7628] | The OAUTHBEARER mechanism: the bearer token message, and the acknowledgement the server needs to report a failure     |
| [7677] | The SHA-256 profile of SCRAM, verified against the exchange published in the specification                            |
| [9266] | The `tls-exporter` channel binding, the only one defined for TLS 1.3                                                  |

The channel binding material itself is extracted from the TLS session by the caller and handed over with the credentials, since a library that opens no connection cannot ask a session what it exported. Kerberos tokens arrive the same way, from a security context the caller holds.

SASLprep leaves out two of the checks RFC 3454 lists, the bidirectional rule and the unassigned code points, both of which reject strings rather than change them; everything that decides what bytes go on the wire is applied.

Three mechanisms were never standardised: LOGIN follows [draft-murchison-sasl-login](https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login-00), SCRAM-SHA-512 follows [draft-melnikov-scram-sha-512](https://datatracker.ietf.org/doc/html/draft-melnikov-scram-sha-512) and is registered with IANA under that name, and XOAUTH2 follows the [Google specification](https://developers.google.com/gmail/imap/xoauth2-protocol) that Google and Microsoft implement.

[2195]: https://www.rfc-editor.org/rfc/rfc2195
[4013]: https://www.rfc-editor.org/rfc/rfc4013
[4422]: https://www.rfc-editor.org/rfc/rfc4422
[4505]: https://www.rfc-editor.org/rfc/rfc4505
[4616]: https://www.rfc-editor.org/rfc/rfc4616
[4752]: https://www.rfc-editor.org/rfc/rfc4752
[5801]: https://www.rfc-editor.org/rfc/rfc5801
[5802]: https://www.rfc-editor.org/rfc/rfc5802
[5929]: https://www.rfc-editor.org/rfc/rfc5929
[7628]: https://www.rfc-editor.org/rfc/rfc7628
[7677]: https://www.rfc-editor.org/rfc/rfc7677
[9266]: https://www.rfc-editor.org/rfc/rfc9266

## Usage

The whole API is documented on [docs.rs](https://docs.rs/io-sasl/latest/io_sasl), including a runnable snippet for every mechanism, and starting with the crate header describing how a mechanism is driven and where the boundary with the protocol library sits.

## Examples

The crate ships no examples folder, since a mechanism only comes alive inside a protocol exchange: every mechanism module opens with a runnable snippet driving its own exchange, the integration tests under [tests](./tests) drive whole exchanges the way a protocol library drives them, and the protocol libraries built on it show the real wiring.

## License

This project is licensed under either of:

- [MIT license](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

## Social

- Chat on [Matrix](https://matrix.to/#/#pimalaya:matrix.org)
- News on [Mastodon](https://fosstodon.org/@pimalaya) or [RSS](https://fosstodon.org/@pimalaya.rss)
- Mail at [pimalaya.org@posteo.net](mailto:pimalaya.org@posteo.net)

## Sponsoring

[![nlnet](https://nlnet.nl/logo/banner-160x60.png)](https://nlnet.nl/)

Special thanks to the [NLnet foundation](https://nlnet.nl/) and the [European Commission](https://www.ngi.eu/) that have been financially supporting the project for years:

- 2022 → 2023: [NGI Assure](https://nlnet.nl/project/Himalaya/)
- 2023 → 2024: [NGI Zero Entrust](https://nlnet.nl/project/Pimalaya/)
- 2024 → 2026: [NGI Zero Core](https://nlnet.nl/project/Pimalaya-PIM/)
- 2026 → 2027: [NGI Zero Commons Fund](https://nlnet.nl/project/Pimalaya-pimdir/)

If you appreciate the project, feel free to donate using one of the following providers:

[![GitHub](https://img.shields.io/badge/-GitHub%20Sponsors-fafbfc?logo=GitHub%20Sponsors)](https://github.com/sponsors/soywod)
[![Ko-fi](https://img.shields.io/badge/-Ko--fi-ff5e5a?logo=Ko-fi&logoColor=ffffff)](https://ko-fi.com/soywod)
[![Buy Me a Coffee](https://img.shields.io/badge/-Buy%20Me%20a%20Coffee-ffdd00?logo=Buy%20Me%20A%20Coffee&logoColor=000000)](https://www.buymeacoffee.com/soywod)
[![Liberapay](https://img.shields.io/badge/-Liberapay-f6c915?logo=Liberapay&logoColor=222222)](https://liberapay.com/soywod)
[![thanks.dev](https://img.shields.io/badge/-thanks.dev-000000?logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQuMDk3IiBoZWlnaHQ9IjE3LjU5NyIgY2xhc3M9InctMzYgbWwtMiBsZzpteC0wIHByaW50Om14LTAgcHJpbnQ6aW52ZXJ0IiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxwYXRoIGQ9Ik05Ljc4MyAxNy41OTdINy4zOThjLTEuMTY4IDAtMi4wOTItLjI5Ny0yLjc3My0uODktLjY4LS41OTMtMS4wMi0xLjQ2Mi0xLjAyLTIuNjA2di0xLjM0NmMwLTEuMDE4LS4yMjctMS43NS0uNjc4LTIuMTk1LS40NTItLjQ0Ni0xLjIzMi0uNjY5LTIuMzQtLjY2OUgwVjcuNzA1aC41ODdjMS4xMDggMCAxLjg4OC0uMjIyIDIuMzQtLjY2OC40NTEtLjQ0Ni42NzctMS4xNzcuNjc3LTIuMTk1VjMuNDk2YzAtMS4xNDQuMzQtMi4wMTMgMS4wMjEtMi42MDZDNS4zMDUuMjk3IDYuMjMgMCA3LjM5OCAwaDIuMzg1djEuOTg3aC0uOTg1Yy0uMzYxIDAtLjY4OC4wMjctLjk4LjA4MmExLjcxOSAxLjcxOSAwIDAgMC0uNzM2LjMwN2MtLjIwNS4xNTYtLjM1OC4zODQtLjQ2LjY4Mi0uMTAzLjI5OC0uMTU0LjY4Mi0uMTU0IDEuMTUxVjUuMjNjMCAuODY3LS4yNDkgMS41ODYtLjc0NSAyLjE1NS0uNDk3LjU2OS0xLjE1OCAxLjAwNC0xLjk4MyAxLjMwNXYuMjE3Yy44MjUuMyAxLjQ4Ni43MzYgMS45ODMgMS4zMDUuNDk2LjU3Ljc0NSAxLjI4Ny43NDUgMi4xNTR2MS4wMjFjMCAuNDcuMDUxLjg1NC4xNTMgMS4xNTIuMTAzLjI5OC4yNTYuNTI1LjQ2MS42ODIuMTkzLjE1Ny40MzcuMjYuNzMyLjMxMi4yOTUuMDUuNjIzLjA3Ni45ODQuMDc2aC45ODVabTE0LjMxNC03LjcwNmgtLjU4OGMtMS4xMDggMC0xLjg4OC4yMjMtMi4zNC42NjktLjQ1LjQ0Ni0uNjc3IDEuMTc3LS42NzcgMi4xOTVWMTQuMWMwIDEuMTQ0LS4zNCAyLjAxMy0xLjAyIDIuNjA2LS42OC41OTMtMS42MDUuODktMi43NzQuODloLTIuMzg0di0xLjk4OGguOTg0Yy4zNjIgMCAuNjg4LS4wMjcuOTgtLjA4LjI5Mi0uMDU1LjUzOC0uMTU3LjczNy0uMzA4LjIwNC0uMTU3LjM1OC0uMzg0LjQ2LS42ODIuMTAzLS4yOTguMTU0LS42ODIuMTU0LTEuMTUydi0xLjAyYzAtLjg2OC4yNDgtMS41ODYuNzQ1LTIuMTU1LjQ5Ny0uNTcgMS4xNTgtMS4wMDQgMS45ODMtMS4zMDV2LS4yMTdjLS44MjUtLjMwMS0xLjQ4Ni0uNzM2LTEuOTgzLTEuMzA1LS40OTctLjU3LS43NDUtMS4yODgtLjc0NS0yLjE1NXYtMS4wMmMwLS40Ny0uMDUxLS44NTQtLjE1NC0xLjE1Mi0uMTAyLS4yOTgtLjI1Ni0uNTI2LS40Ni0uNjgyYTEuNzE5IDEuNzE5IDAgMCAwLS43MzctLjMwNyA1LjM5NSA1LjM5NSAwIDAgMC0uOTgtLjA4MmgtLjk4NFYwaDIuMzg0YzEuMTY5IDAgMi4wOTMuMjk3IDIuNzc0Ljg5LjY4LjU5MyAxLjAyIDEuNDYyIDEuMDIgMi42MDZ2MS4zNDZjMCAxLjAxOC4yMjYgMS43NS42NzggMi4xOTUuNDUxLjQ0NiAxLjIzMS42NjggMi4zNC42NjhoLjU4N3oiIGZpbGw9IiNmZmYiLz48L3N2Zz4=)](https://thanks.dev/soywod)
[![PayPal](https://img.shields.io/badge/-PayPal-0079c1?logo=PayPal&logoColor=ffffff)](https://www.paypal.com/paypalme/soywod)
