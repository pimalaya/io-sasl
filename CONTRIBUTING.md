# Contributing guide

Thank you for investing your time in contributing to I/O SASL.

Whether you are a human or an AI agent, read these in order before touching the code:

1. the [Pimalaya README](https://github.com/pimalaya) for what the project is and how its repositories stack;
2. the [Pimalaya CONTRIBUTING](https://github.com/pimalaya/.github/blob/master/CONTRIBUTING.md) guide, which chains to the shared architecture and guidelines;
3. the inline header documentation, starting with src/lib.rs: it is the architecture document of this crate;
4. the cairn/ folder for the development history and living plans (the Cairn convention: spec/, changes/, log/).

Everything below documents only what differs from the Pimalaya standards.

## Type naming

A mechanism names its coroutine, its failure type and its credential struct after itself and nothing else: `SaslPlain`, `SaslPlainError`, `SaslPlainCreds`. The naming canon would put an `Auth` verb on the coroutine, as io-imap does with `ImapAuthPlain`, and this crate drops it: io-imap needs the verb because it also carries coroutines that authenticate nothing, while here every item is an authentication exchange, so a verb none of them can be told apart by is noise. `Creds` carries the distinction instead, and it reads the right way round, since the credentials are the data and the coroutine is the machine.

This is a local exception, not a rule change. A new mechanism follows it; anything outside this crate follows the canon.

Everything else follows io-imap, since the two crates are read together. A yield names what the caller is asked to do (`WantsWrite`, `WantsChallenge`), and a mechanism's private state enum names what its next resume is about to do (`SendUsername`, `SendPassword`, `Done`), never what the previous one did.

## Feature matrix

The crate ships I/O-free mechanisms and nothing else: there is no client layer to gate, because it opens no connection. The only cargo feature is `scram`, which is enabled by default and pulls in the HMAC, PBKDF2, SHA-256 and base64 crates that SCRAM-SHA-256 needs. Build both shapes, since the reduced one is what a consumer picks when it only speaks the cleartext and OAuth mechanisms.

```sh
cargo build --no-default-features  # the five mechanisms needing no cryptography
cargo build --all-features         # everything, SCRAM-SHA-256 included
```

## Tests

Three layers, each answering a different question. The unit tests next to each mechanism pin its payloads against its own specification, and the ones in the vocabulary module walk the routing between its two closed sets, every tag against the name it is registered under and every credential struct against the variant it converts into, as one table rather than six cases, since what six near-identical arms get wrong is two of them landing on the same place. tests/exchange.rs drives whole exchanges through the public API and states its assertions as properties over all six mechanisms at once, so a seventh one getting an edge of the contract wrong fails there rather than inside a protocol crate. tests/coverage.rs holds the one claim no single module can make: that each coroutine answers with the tag of the module it lives in, which is the name that ends up on the wire.

The example opening each mechanism module is a fourth layer, thin but load-bearing: it is the exchange a consumer copies, and it runs as a doctest, so an API change that would leave a protocol crate driving the mechanism wrong breaks the documentation that taught it.

Run both feature shapes, since the reduced one compiles a different set of mechanisms:

```sh
cargo test --no-default-features
cargo test --all-features
```

## Coverage

The crate is small enough to keep fully covered, and it stays that way:

```sh
cargo tarpaulin --all-features --skip-clean --out Stdout
```

tarpaulin.toml keeps the fuzz targets out of the measured surface: they are a separate cargo package that the coverage run never builds. Never twist the code to move the number. Code no test can reach is either dead, and goes, or is worth a test that means something on its own.

## Fuzzing

Two coverage-guided targets under [fuzz/](./fuzz), described in [fuzz/README.md](./fuzz/README.md): one driving all six mechanisms with arbitrary peer messages, one driving SCRAM-SHA-256 against a server signature the harness derives itself, so that accepting an exchange is checked against arithmetic done outside the state machine doing the accepting. Any change to the SCRAM message assembly or key derivation is worth a fuzz run.

They need the nightly toolchain cargo-fuzz builds against, which the `fuzz` devShell of the flake carries, unlike the default one:

```sh
nix develop .#fuzz --command cargo fuzz run exchange
nix develop .#fuzz --command cargo fuzz run scram
```

## Where a mechanism ends

A mechanism computes payloads and verifies what it receives. It never frames anything, never encodes for the transport, and never generates randomness. Three rules follow, and a change breaking one of them belongs in the protocol crate instead:

Transport base64 stays with the protocol crate, which decodes a challenge before handing it over and encodes a response before writing it. Only the intra-message base64 of RFC 5802, the `s=` salt and the `p=` proof, lives here.

Framing errors stay with the protocol crate, including a missing continuation request or a success reply arriving mid-exchange. Only mechanism failures live here: a mismatched signature or nonce, a malformed server message, a rejected token.

Entropy stays with the caller. SCRAM-SHA-256 takes its client nonce as an argument, which is also what makes the published test vectors reproducible.

## Cryptography changes

The SCRAM-SHA-256 exchange is pinned by the test vector published in RFC 7677 section 3, for the user `user` with the password `pencil`. Any change to the message assembly or to the key derivation has to keep that test passing untouched; when it fails, the code is wrong, never the vector.
