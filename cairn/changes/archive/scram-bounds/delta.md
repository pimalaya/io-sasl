---
cairn: delta
change: scram-bounds
---

## ADDED Requirements

### Requirement: Iteration bounds
The mechanism SHALL refuse a server-first-message whose `i=` iteration count is outside the bounds of its options, before deriving anything: below `min_iterations` with `IterationCountTooLow`, above `max_iterations` with `IterationCountTooHigh`, both ends inclusive and both failures carrying the count and the bound. The floor SHALL default to 4096, the count RFC 5802 and RFC 7677 ask a server to announce at least, and the ceiling to five million, and both defaults SHALL be public constants. A count that is not the `posit-number` of RFC 5802 section 7, which excludes `0`, a sign and a leading zero, SHALL fail with `InvalidIterationCount` whatever the options.

### Requirement: Options
`SaslScram::new` SHALL take the credentials and a `SaslScramOptions`, every field of which is optional and defaults to the crate's own value, so that a protocol crate can carry the struct inside its own options and hand it over untouched. Bounds SHALL NOT be fields of the credentials.

## MODIFIED Requirements

### Requirement: Caller-provided nonce
The client nonce SHALL be a field of the credentials. The crate SHALL NOT depend on a random number generator, since an I/O-free mechanism cannot produce entropy and the caller owns that decision.

The first resume SHALL fail with `InvalidNonce` when the nonce is shorter than 18 bytes or holds a comma or a byte outside printable ASCII, so that an empty or malformed nonce never reaches the wire. An empty nonce SHALL NOT stand for "draw one": a caller that owns entropy draws it before building the mechanism.

### Requirement: Constructors
Each mechanism SHALL be built from the credential struct it shares with its `Sasl` variant, so a consumer matching on that enum reaches the mechanism it needs without restating the fields. A mechanism with behaviour to bound SHALL take it as a second, defaulted options argument.

### Requirement: Fuzz targets
The repository SHALL carry a cargo-fuzz package, unpublished and detached from the library's cargo workspace, holding at least two coverage-guided targets: one driving every mechanism with arbitrary credentials and arbitrary peer messages, in order and out of order, bound and unbound, and one driving SCRAM-SHA-256 with arbitrary server messages. The nightly toolchain and cargo-fuzz they need SHALL be exposed as the `fuzz` devShell of the repository flake, so a run inherits the nixpkgs and fenix pinned by flake.lock and needs no nixpkgs channel of its own.

Both targets SHALL keep SCRAM affordable by handing the mechanisms a low iteration ceiling rather than by filtering the challenges they feed, so that the ceiling itself is under test, and SHALL fold the fuzzed nonce onto a valid one so that an exchange gets past its first step.
