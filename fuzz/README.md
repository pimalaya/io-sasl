# Fuzzing

Coverage-guided fuzzing of the SASL mechanisms with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer). Two targets, each with its own oracle.

The `exchange` target drives all six mechanisms with fuzzed credentials and a fuzzed sequence of challenges, both from the start of an exchange and out of order, against a mechanism that has said nothing yet. Its oracle is that whatever a peer says, and whenever it says it, a mechanism answers or fails, never panics.

The `scram` target is the security oracle, and the reason this crate exists. It drives SCRAM-SHA-256 with fuzzed server messages and checks two things: the mechanism never panics, and it never reports success unless it was fed a server-final-message whose signature is the one RFC 5802 computes. The target derives the salted password, the server key and the server signature itself, from the primitives the RFC names and from the bytes it watched the mechanism send, so acceptance is checked against an answer computed outside the state machine being checked. That is exactly the invariant the two implementations io-sasl replaces both got wrong, one verifying only when the reply happened to parse, the other taking a tagged OK carrying the server-final-message as success on its own.

cargo-fuzz needs a nightly toolchain (for the `-Z` sanitizer flags). The `fuzz` devShell of the repository flake carries both, nightly via fenix plus cargo-fuzz, so no rustup and no nix-ld shim are needed:

```sh
nix develop .#fuzz --command cargo fuzz run exchange
nix develop .#fuzz --command cargo fuzz run scram
```

Bound a run with the libFuzzer flags, which come after the `--` separator, and which nix would otherwise read as its own:

```sh
nix develop .#fuzz --command bash -c "cargo fuzz run scram -- -max_total_time=60"
```

libFuzzer saves every interesting new input into `fuzz/corpus/<target>/` (gitignored), and any crash into `fuzz/artifacts/<target>/`, from where it is replayed with `cargo fuzz run <target> fuzz/artifacts/<target>/<file>`.

Both targets cap the SCRAM-SHA-256 iteration count they are willing to derive at 1024 and skip the challenges asking for more. The count comes from the server and RFC 5802 puts no ceiling on it, so a fuzzed `i=4000000000` is a legitimate message that simply takes minutes of PBKDF2: a cost question for the consumer, not a memory-safety one, and libFuzzer would report it as a timeout.

Off NixOS, `cargo install cargo-fuzz` and a nightly toolchain give the same `cargo fuzz run <target>`.
