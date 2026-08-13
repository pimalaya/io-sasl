---
cairn: delta
change: concrete-clients
---

## ADDED Requirements

### Requirement: Framing vocabulary
The `client::framing` module SHALL carry `SaslFraming`, the four protocol facts a driver cannot derive from a socket: the command opening the exchange, the encoding of a response, and the classification of an incoming line as `SaslReply::Challenge`, `SaslReply::Success` or `SaslReply::Failure`. `SaslFraming::command` SHALL take the initial response as an `Option`, `Some` only when the protocol may inline one and the caller chose to, so the SASL-IR policy stays with the protocol crate. `SaslFraming::reply` SHALL own the transport base64, the prefix it strips and the encoding it undoes being one decision.

A concrete client SHALL NOT infer any of the four, and SHALL NOT treat the end of the connection as the end of the exchange, a session continuing after authentication in every protocol carrying SASL.

### Requirement: Concrete clients
`client::std::SaslClientStd<S, F>` SHALL implement `SaslClient` over `S: Read + Write`, and `client::tokio::SaslClientTokio<S, F>` SHALL implement `SaslClientAsync` over `S: AsyncRead + AsyncWrite + Unpin + Send`, both holding the stream and one `SaslFraming`, reading CRLF-terminated lines through a buffer of their own, and handling a line that arrives across several reads. The two SHALL share one `SaslFraming` implementation, so that a consumer moving between flavours rewrites nothing but the client type.

Their failure type SHALL be owned by this crate, carrying the framing's error, the transport's, the mechanism's and the `Failure` reply, this being the one place where this crate is the driver and can name the framing errors itself.

### Requirement: Runtime dependency
The `tokio` cargo feature SHALL gate `SaslClientTokio` and SHALL be off by default. It, and it alone, SHALL pull tokio and `extern crate std`, which no coroutine and neither trait SHALL reach, so that every build not asking for a socket stays alloc-only.

### Requirement: Concrete client tests
Both clients SHALL be driven through recorded transcripts over an in-memory duplex, with an IMAP-shaped `SaslFraming`, covering a mechanism that ends on the peer's success reply and a SCRAM profile that must verify the server signature before it may complete. A line arriving across several reads SHALL be part of the transcript, being what a real socket does.

## MODIFIED Requirements

### Requirement: No transport
Neither trait SHALL name a stream, a socket or a runtime: an implementation brings its own transport and borrows it for the exchange, so the surface itself adds no I/O. The clients this crate ships SHALL sit beside the traits rather than inside them, each owning a stream the caller handed it and a `SaslFraming` describing the protocol, and SHALL open no connection of their own.

### Requirement: no_std
`#![no_std]` SHALL be unconditional and `extern crate alloc` SHALL be declared, since the crate allocates. `extern crate std` SHALL be gated on the features carrying a concrete client, and nothing outside those clients SHALL reach it. The command surface itself stays alloc-only, naming no stream and leaving the transport to whoever implements it.
