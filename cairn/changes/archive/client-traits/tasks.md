---
cairn: tasks
change: client-traits
---

- [x] Add the `client` cargo feature, gating nothing but the surface
- [x] Add the `client` module: one submodule per flavour, one required `run` each
- [x] Give LOGIN its default body in both, with a runnable example per trait
- [x] Prove a blocking implementation over a borrowed transport in tests/client.rs
- [x] Prove the async futures stay `Send` in tests/client_async.rs
- [x] Give the eleven remaining mechanisms their default bodies, in `Sasl` variant order
- [x] Sweep every method in both surface tests, against the mechanism it names
- [x] Update the crate header, the README, CONTRIBUTING, the CHANGELOG and the spec
- [x] Re-run fmt, clippy, tests, doctests and coverage
