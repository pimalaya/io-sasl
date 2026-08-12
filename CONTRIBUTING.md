# Contributing guide

Thank you for investing your time in contributing to I/O SASL.

Whether you are a human or an AI agent, read these in order before touching the code:

1. the [Pimalaya README](https://github.com/pimalaya) for what the project is and how its repositories stack;
2. the [Pimalaya CONTRIBUTING](https://github.com/pimalaya/.github/blob/master/CONTRIBUTING.md) guide, which chains to the shared architecture and guidelines;
3. the inline header documentation, starting with src/lib.rs: it is the architecture document of this crate;
4. the cairn/ folder for the development history and living plans (the Cairn convention: spec/, changes/, log/).

Everything below documents only what differs from the Pimalaya standards.

## Feature matrix

The crate ships I/O-free mechanisms and nothing else: there is no client layer to gate, because it opens no connection. The only cargo feature is `scram`, which is enabled by default and pulls in the HMAC, PBKDF2, SHA-256 and base64 crates that SCRAM-SHA-256 needs. Build both shapes, since the reduced one is what a consumer picks when it only speaks the cleartext and OAuth mechanisms.

```sh
cargo build --no-default-features  # the five mechanisms needing no cryptography
cargo build --all-features         # everything, SCRAM-SHA-256 included
```

## Where a mechanism ends

A mechanism computes payloads and verifies what it receives. It never frames anything, never encodes for the transport, and never generates randomness. Three rules follow, and a change breaking one of them belongs in the protocol crate instead:

Transport base64 stays with the protocol crate, which decodes a challenge before handing it over and encodes a response before writing it. Only the intra-message base64 of RFC 5802, the `s=` salt and the `p=` proof, lives here.

Framing errors stay with the protocol crate, including a missing continuation request or a success reply arriving mid-exchange. Only mechanism failures live here: a mismatched signature or nonce, a malformed server message, a rejected token.

Entropy stays with the caller. SCRAM-SHA-256 takes its client nonce as an argument, which is also what makes the published test vectors reproducible.

## Cryptography changes

The SCRAM-SHA-256 exchange is pinned by the test vector published in RFC 7677 section 3, for the user `user` with the password `pencil`. Any change to the message assembly or to the key derivation has to keep that test passing untouched; when it fails, the code is wrong, never the vector.
