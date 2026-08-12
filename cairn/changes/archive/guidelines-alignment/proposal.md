---
cairn: change
id: guidelines-alignment
status: landed
created: 2026-08-12
---

# Apply the Pimalaya guidelines to the whole repository

## Why

The crate was bootstrapped and then given its test harness on the same day, both times writing to the guidelines from memory rather than walking them rule by rule. A conformance pass over every scope found the code, the manifest, the markdown files and the licensing already conformant, and three gaps outside them.

The fuzz job entered its shell with nix-shell fuzz/shell.nix, which resolves nixpkgs through NIX_PATH. A flake-only CI runner has no channel, so both fuzz steps failed at every push while the library they guard kept reporting green. The same file also pinned fenix through a fetchTarball, so the toolchain drifted away from flake.lock on every run.

No module carried a runnable example. The API is documented item by item, but nothing on docs.rs showed an exchange being driven, and driving it correctly is the whole contract: a consumer that stops at the success reply skips the SCRAM server verification, which is the failure this crate exists to prevent.

The cairn/ folder shipped spec/ and log/ but no changes/, which the Cairn conformance rules require.

## What

Walk the whole rule set, apply every fix, and record the result.

Expose the fuzz shell as the `fuzz` devShell of the repository flake, so it inherits the pinned nixpkgs and fenix, and point the CI job and fuzz/README.md at it. Keep fuzz/shell.nix callable on its own for a machine that does have a channel.

Give every mechanism module a runnable example driving its exchange step by step, compiled as a doctest, and say so in the crate header and the README.

Create cairn/changes, sort the fuzz package manifest, and re-run the whole check chain in both feature shapes.
