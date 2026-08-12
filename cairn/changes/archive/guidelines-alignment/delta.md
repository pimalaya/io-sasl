---
cairn: delta
change: guidelines-alignment
---

## ADDED Requirements

### Requirement: Credential locality
Each credential struct SHALL live in the module of the mechanism that transmits it, next to that mechanism's coroutine and failure type, and SHALL be convertible into `Sasl`. A mechanism excluded by a cargo feature SHALL take its credential struct and its `Sasl` variant with it, an exchange this build cannot run having no shape to describe.

### Requirement: Documented exchanges
Every mechanism module SHALL open with a runnable example driving its exchange step by step, compiled and run as a doctest. The example SHALL show the mechanism a consumer reaches for, not a fragment of it: what the protocol crate sends first, what it feeds back, and where the exchange ends, since driving that sequence correctly is the whole contract.

## MODIFIED Requirements

### Requirement: Vocabulary
The `mechanism` module SHALL hold `SaslMechanism` (the tag, knowing its registered wire name) and `Sasl` (a tag paired with the credentials of one mechanism). `SaslMechanism` SHALL carry a variant per mechanism whatever the build enables, since a consumer matching a server capability list has to name a mechanism it cannot run.

### Requirement: Fuzz targets
The repository SHALL carry a cargo-fuzz package, unpublished and detached from the library's cargo workspace, holding at least two coverage-guided targets: one driving all six mechanisms with arbitrary credentials and arbitrary peer messages, in order and out of order, and one driving SCRAM-SHA-256 with arbitrary server messages. The nightly toolchain and cargo-fuzz they need SHALL be exposed as the `fuzz` devShell of the repository flake, so a run inherits the nixpkgs and fenix pinned by flake.lock and needs no nixpkgs channel of its own.
