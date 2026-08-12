---
cairn: tasks
change: guidelines-alignment
---

- [x] Check every scope of the guidelines against the repository, rule by rule
- [x] Expose fuzz/shell.nix as the `fuzz` devShell of the flake, on the pinned nixpkgs and fenix
- [x] Point the CI fuzz job and fuzz/README.md at nix develop .#fuzz
- [x] Move each credential struct into the module of the mechanism that transmits it
- [x] Gate the `Sasl` SCRAM variant on the feature that now carries its credentials
- [x] Add a runnable example to each of the six mechanism modules
- [x] Announce the examples in the crate header and the README
- [x] Create cairn/changes and record this pass in it
- [x] Sort the fuzz package dependencies alphabetically
- [x] Re-run fmt, clippy, tests, doctests, deny and coverage in both feature shapes
- [x] Replay both fuzz targets through the new devShell
