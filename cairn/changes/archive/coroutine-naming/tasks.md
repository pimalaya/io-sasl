---
cairn: tasks
change: coroutine-naming
---

- [x] Rename `SaslYield::Respond` to `WantsWrite` and `AwaitChallenge` to `WantsChallenge`
- [x] Rewrite the yield docs from the caller's side, and say why the read side keeps the SASL word
- [x] Rename the six state enums to what their next resume does
- [x] Update the doctests, the tests, the fuzz targets and the CHANGELOG
- [x] Record both conventions in CONTRIBUTING and the coroutines spec
- [x] Re-run fmt, clippy, tests, doctests, rustdoc, coverage and both fuzz targets
