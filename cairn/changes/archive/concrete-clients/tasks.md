---
cairn: tasks
change: concrete-clients
---

- [ ] Add `client::framing`: `SaslFraming`, `SaslReply`, and the doc stating which four facts a protocol owns
- [ ] Add `SaslClientStd<S, F>` over `Read + Write`, with its own line buffer and the crate-owned failure type
- [ ] Add the `tokio` cargo feature, and `extern crate std` behind it
- [ ] Add `SaslClientTokio<S, F>` over `AsyncRead + AsyncWrite + Unpin + Send`, sharing the one `SaslFraming`
- [ ] Write the IMAP-shaped `SaslFraming` in the tests, and drive both clients through a recorded LOGIN and SCRAM-SHA-256 transcript over an in-memory duplex
- [ ] Pin the failure the design exists for: a success reply the framing recognises ends the exchange with `Done`, and SCRAM refuses when it arrives unverified
- [ ] Pin the reads that arrive in pieces, a line split across two reads being what a real socket does
- [ ] Give each client a runnable example, and the crate header a paragraph on when to reach for one
- [ ] Update the README, CONTRIBUTING, the CHANGELOG and the spec (client, packaging, testing)
- [ ] Re-run fmt, clippy, tests, doctests and coverage over every feature shape
