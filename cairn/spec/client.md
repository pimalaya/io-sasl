---
cairn: spec
capability: client
status: current
---

# Command surface

The layer above the coroutines: the loop every protocol crate writes around a mechanism, written once as a trait method, so that each mechanism arrives as a method rather than as a loop of its own. It is a surface, not a client: nothing in it opens a connection.

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
