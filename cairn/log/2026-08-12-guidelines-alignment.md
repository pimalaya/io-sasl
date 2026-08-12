---
cairn: log
change: guidelines-alignment
landed: 2026-08-12
---

# Guidelines alignment: credentials moved to their mechanisms, a flake devShell for the fuzz targets, an example per mechanism

Walked the whole Pimalaya rule set against the repository, scope by scope. The manifest, the crate attributes, the import blocks, the type naming, the markdown files, the licensing and the repository skeleton were already conformant, and are recorded here as checked rather than changed. Four gaps closed.

The six credential structs sat together in the mechanism module, a catalogue naming-005 rules out: a type attached to one coroutine belongs in that coroutine's file, and what a mechanism transmits is attached to nothing else. Each struct moved next to the coroutine that sends it, taking the position io-imap gives an Options companion, between the failure type and the coroutine. The mechanism module keeps what genuinely spans them, `SaslMechanism` and the `Sasl` enum, and now imports the structs it gathers instead of declaring them. `SaslScramSha256` followed its mechanism behind the `scram` feature, so `Sasl::ScramSha256` and its `From` impl are gated too: a build without the mechanism can no longer describe an exchange it cannot run, and a consumer mapping a configuration onto the enum reports the missing feature where the user can act on it. `SaslMechanism` stays complete in every build, since recognising the name of a mechanism in a server capability list is exactly how a consumer reports it as unsupported.

The fuzz job entered its shell with nix-shell fuzz/shell.nix, which resolves nixpkgs through NIX_PATH. A flake-only runner has no channel, so both fuzz steps failed at every push while the library they guard kept reporting green, and the fetchTarball pinning fenix in the same file let the toolchain drift away from flake.lock besides. The shell is now the `fuzz` devShell of the repository flake, taking nixpkgs and fenix as arguments and defaulting to the channel only when called on its own, and the flake merges it into the devShells mkFlakeOutputs generates. The CI job and fuzz/README.md run `nix develop .#fuzz`, with the libFuzzer flags behind a bash -c so nix does not read them as its own. Verified end to end: the shell builds, cargo-fuzz 0.13.1 on nightly rustc, and the exchange target completes 694554 runs without a finding.

No module carried a runnable example, so docs.rs documented every item without ever showing an exchange being driven, which is the part a consumer gets wrong. Each of the six mechanism modules now opens with one, driving its own exchange step by step: the payload PLAIN and ANONYMOUS send, the two prompts of LOGIN, the error acknowledgement OAUTHBEARER owes a refused token, the happy path of XOAUTH2, and the four steps of SCRAM-SHA-256 ending on the server signature. They compile and run as doctests, so an API change that would leave a protocol crate driving a mechanism wrong breaks the documentation that taught it. The crate header, the README and CONTRIBUTING now say they are there.

The cairn/ folder shipped spec/ and log/ but no changes/, which the Cairn conformance rules require; this pass is the first change recorded in it. The fuzz package dependencies were sorted alphabetically.

No mechanism behaviour changed: the thirty-four tests the crate shipped with pass unmodified in both feature shapes, only their import blocks moved, joined by the six doctests. clippy is clean with warnings denied on all targets, cargo deny reports advisories, bans, licenses and sources ok, both fuzz targets rebuild against the moved types and run clean, and coverage stays at 100% of the library, 232 lines of 232.

Capabilities moved: mechanisms, testing.
