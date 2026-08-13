---
cairn: log
change: client-traits
landed: 2026-08-13
---

# The command surface, shaped on one mechanism and then filled

`SaslClient` and `SaslClientAsync` land with all twelve mechanisms on each, one module per flavour: src/client/std.rs and src/client/async.rs, with src/client/mod.rs holding what is true of both. LOGIN went in first and alone, so the shape was reviewed before eleven more bodies rested on it, and the eleven cost one line each once it held.

The shape is io-imap's, one required `run` and a default body per command, and three things came out different. Two of them follow from the same fact, that this crate has no transport, which is exactly why the pattern was worth trying here first.

The first is the error. io-imap fixes its client error to the crate's own, having ruled an associated type unusable: forty coroutine errors would need forty `From` bounds on the trait. That reasoning holds for a bound on the trait and not for one on each method, and this crate cannot afford the fixed type anyway. A `SaslClientError` would need a boxed variant for the framing errors of whoever drives it, and io-imap would then box its own errors on the way in and unbox them on the way out, to reach an enum that told it nothing it did not already know. So the error is `Self::Error`, each default body carries `Self::Error: From<<Mechanism as SaslCoroutine>::Error>`, and an implementation pays for the mechanisms it calls and no others. The test driver reports its own `Disconnected` and the mechanism's `UnexpectedChallenge` through one type, which is the whole argument in three lines.

The second is that nothing here names a stream. The traits take a mechanism and give back a result: the transport is the implementation's, borrowed for the exchange, and both examples borrow rather than own to say so. That also settles what this crate ships, which is no implementation of either trait, there being nothing here to write one over.

The third is that there is no macro. io-imap emits its two traits from one `imap_client_commands!` list, and with thirty-seven commands on each side that is the right trade. Twelve mechanisms whose bodies are one call each is not the same trade: the surface is read far more often than it is edited, and reading it as it was written is worth more than the drift a macro rules out. What replaces the guarantee is twinship, the two files carrying the same method names, arguments and documentation in the same order, so a mechanism given to one and not to the other appears in the diff that adds it, and CONTRIBUTING says to add them together.

The features collapsed in the same pass. `std` and `async` started as one gate each, which put a `std` feature on a crate that stays `#![no_std]` with it enabled, and made a name for a flavour look like a name for a dependency. One `client` feature gates both traits now, on by default, which also leaves the module with a single gate at its declaration and no `#[cfg]` inside it.

The `Send` decision was taken as io-imap took it and for the same reason: `Send` as a supertrait of the async twin and on the future `run` returns, since an `async fn` in a trait cannot promise a `Send` future and every default body would then fail under a spawning runtime. tests/client_async.rs pins it by passing a default body's future to a function bounded the way a runtime bounds it, so dropping either declaration stops the file compiling. The blocking trait stays unbounded, a thread-affine transport being a perfectly good one.

A cargo feature arrived that pulls nothing, which the feature matrix had until now said was the one thing a feature never does. It stays, and the rule is now stated with its exception: `client` gates a surface a consumer driving the coroutines itself can leave out, rather than a dependency it avoids. The crate is still `#![no_std]` with it enabled, and still opens nothing.

What is deliberately not here is the `Sasl` dispatcher, the match from the credential enum onto the twelve methods, which is the duplication io-imap and io-smtp actually carry today. The methods sit in `Sasl` variant order so it can be read arm by arm against them when it lands.

The tests gained one claim that is worth naming on its own. Twenty-four one-line bodies are twenty-four chances to call the wrong constructor, and no compiler catches it, since each typechecks against its own credentials. So each surface file sweeps every method the build enables and asserts it reaches the mechanism it is named after, which is the vocabulary sweep's argument one layer up: what a dozen near-identical arms get wrong is two of them landing on the same place. Writing the sweep first showed the cost of the twelve bodies honestly, coverage having fallen to 93.68% the moment they landed untested.

78 unit tests, 5 contract properties, 1 tag sweep, 7 surface tests and 14 doctests pass with every feature enabled. Coverage reads 98.39%, up from 98.22%, both client files fully covered.

Capabilities moved: client (new), packaging, testing.
