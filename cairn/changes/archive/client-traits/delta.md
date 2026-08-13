---
cairn: delta
change: client-traits
---

## ADDED Requirements

### Requirement: Command surface
The `client` module SHALL carry one submodule per flavour, `std` for the blocking `SaslClient` and `r#async` for `SaslClientAsync`, each trait requiring one method, `run`, taking a mechanism bound by `SaslCoroutine` and returning `Result<(), Self::Error>` or a future of one. Every mechanism SHALL reach both traits as a default body calling `run`. The two traits SHALL be written out rather than generated from one list of delegations, each body being a single call and the surface being read far more often than edited, and the two SHALL stay twins, carrying the same method names, arguments and documentation, so that a mechanism given to one and not to the other is visible in the diff that adds it.

`run` SHALL be the loop a protocol crate writes around a mechanism: open the exchange with the name the mechanism reports, resume first with `None` and then always with the answer to the previous yield, write what `WantsWrite` carries and read what `WantsRead` asks for, resume with `Input` for a decoded challenge and with `Done` once the peer's own success reply ended the exchange, and return on completion.

### Requirement: No transport
Neither trait SHALL name a stream, a socket or a runtime. The implementation brings its own transport and borrows it for the exchange, so the surface adds no I/O and the crate keeps opening nothing. It follows that this crate ships no implementation of either trait: there is no transport here to write one over.

### Requirement: Caller-owned failure
The failure type SHALL be an associated type of each trait rather than an enum this crate owns, since the implementation is what holds both kinds of failure, its framing errors and the mechanism's. Each default body SHALL ask for the one conversion it needs, `Self::Error: From<<Mechanism as SaslCoroutine>::Error>`, so an implementation pays only for the mechanisms it calls, and a crate-owned error SHALL NOT be introduced to carry a boxed variant for errors that are not this crate's.

### Requirement: Send on the async surface only
`SaslClientAsync` SHALL declare `Send` as a supertrait and SHALL declare the future `run` returns as `impl Future<..> + Send`, since a plain `async fn` in a trait cannot promise a `Send` future and every default body would then fail to compile under a spawning runtime. `SaslClient` SHALL carry no `Send` bound, a blocking call returning a value rather than a future, and the bound would exclude a thread-affine transport.

### Requirement: Surface coverage
The surface SHALL carry every mechanism the build enables, one default body per mechanism on each trait, taking the credential struct its `Sasl` variant carries and building its coroutine. A mechanism SHALL be added to both traits in the same change, named identically in each, and the methods SHALL sit in `Sasl` variant order, so the dispatcher matching on that enum reads arm by arm against them. A method SHALL carry the cargo feature of the mechanism it runs.

### Requirement: Surface tests
Each trait SHALL be implemented in an integration test the way a protocol crate implements it, over a transport the driver borrows rather than owns, pinning that a default body runs the whole exchange and that both a mechanism failure and the driver's own reach the caller through the one error type the driver already had. Each file SHALL additionally sweep every method the build enables, asserting that each reaches the mechanism it is named after. The async file SHALL additionally assert what only the compiler can, that the futures the default bodies return are `Send`, by passing one to a function bounded the way a spawning runtime bounds it.

## MODIFIED Requirements

### Requirement: no_std
`#![no_std]` SHALL be unconditional and `extern crate alloc` SHALL be declared, since the crate allocates. The crate SHALL stay alloc-only: no `extern crate std` and no I/O. The command surface is no exception, naming no stream and leaving the transport to whoever implements it, so the `client` cargo feature gating it names a surface rather than a client this crate could connect with.

### Requirement: Dependencies
The vocabulary and the mechanisms needing no cryptography SHALL depend only on `secrecy`, `log` and `thiserror`. `base64`, `hmac`, `pbkdf2` and `sha2` SHALL be optional and pulled by the `scram` feature, `sha1` by `scram-sha-1`, `md-5` by `cram-md5`, and `unicode-normalization` by `saslprep`. A random number generator SHALL NOT be a dependency, and neither SHALL a TLS implementation or a Kerberos one.

The `client` feature SHALL pull nothing, gating a surface rather than a dependency, and SHALL cover both flavours of it at once, splitting them saving nothing but a trait definition. It SHALL be enabled by default, a consumer driving the coroutines itself being the rarer case.

### Requirement: Coverage
Every line of the library SHALL be reachable from a test, measured with cargo-tarpaulin over all features. Production code SHALL NOT be shaped to move the number: code no meaningful test can reach is deleted rather than covered, and code a tool misreads is documented rather than rewritten. The fuzz package SHALL be excluded from the measured surface, which tarpaulin.toml does.

The measured figure is 98.39%. The lines it counts short are second lines of multi-line expressions and match-arm patterns, most of them in code the compiler instantiates once per digest while tarpaulin attributes one address per source line; mutating any of them fails several tests. A drop below that figure SHALL be treated as untested code until a mutation shows otherwise.

### Requirement: Documented exchanges
Every mechanism module SHALL open with a runnable example driving its exchange step by step, compiled and run as a doctest. The example SHALL show the mechanism a consumer reaches for, not a fragment of it: what the protocol crate sends first, what it feeds back, and where the exchange ends, since driving that sequence correctly is the whole contract. Each command surface trait SHALL open with one too, implementing the trait end to end over a borrowed transport, since what a consumer copies there is the loop rather than the exchange.
