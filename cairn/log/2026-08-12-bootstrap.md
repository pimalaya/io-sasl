---
cairn: log
change: bootstrap
landed: 2026-08-12
---

# Bootstrap: the SASL layer extracted from stream, io-imap and io-smtp

Created the crate holding the SASL vocabulary and the per-mechanism computation, task 3b of the io-imap client layer plan. The vocabulary moved out of pimalaya-stream, which is not no_std and had no business holding protocol types; the mechanisms were consolidated from the io-imap and io-smtp coroutines, which implemented the same payloads twice and SCRAM-SHA-256 twice over, in 950 and 553 lines with two independent bug surfaces.

The cut is payload and challenge/response computation here, wire framing in the protocol crates. `SaslCoroutine` is the shared contract: `resume` takes a three-cased `SaslArg` (`Start`, `Challenge`, `PeerFinished`) and returns a `SaslYield` (`Respond`, `AwaitChallenge`) or the terminal result. The third resume case is what the extraction is for: PLAIN and SCRAM look identical from outside once the protocol decides for itself when an exchange ends, and SCRAM's mutual authentication is then skipped by omission. Here PLAIN completes `Ok` on `PeerFinished` while SCRAM completes `ServerSignatureNotVerified` unless it verified the server, a new failure with no counterpart in either protocol crate.

Two divergences between the io-imap and io-smtp implementations were resolved against the specifications rather than split the difference. The SCRAM client nonce is now always an argument, as io-smtp had it, since io-imap generated it internally with `rand`, which an I/O-free crate cannot do; that is breaking for io-imap and drops `rand` from both. The OAUTHBEARER payload keeps the host and port key/value pairs of RFC 7628 section 3.1, which io-imap sent and io-smtp omitted. The XOAUTH2 error acknowledgement is the empty response Google documents, which io-imap sent and io-smtp answered with `%x01`, the OAUTHBEARER form.

SCRAM-SHA-256 sits behind the `scram` feature and is pinned by the exchange published in RFC 7677 section 3, so the crypto both protocol crates will share is verified against the specification rather than against itself. The repository ships the standard Pimalaya skeleton: README, CHANGELOG, CONTRIBUTING documenting the mechanism boundary, dual licenses, deny.toml, SECURITY.md, the Nix flake and shell, and this Cairn folder with its AGENTS.md activation stanza.

Capabilities recorded for the first time: coroutines, mechanisms, scram-sha-256, packaging.
