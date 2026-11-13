---
cairn: tasks
change: scram-bounds
---

- [x] Write the regression tests and watch them fail against the unbounded code
- [x] Add `SaslScramOptions`, its two default constants and the minimum nonce length
- [x] Take the options as the second argument of `SaslScram::new`
- [x] Refuse an iteration count outside the bounds before deriving, with the count and the bound in the error
- [x] Parse `i=` as a posit-number, refusing zero whatever the options
- [x] Refuse a nonce that is too short or outside the alphabet at the first resume
- [x] Hand the bounds to the mechanisms in both fuzz targets instead of filtering challenges, and fold the fuzzed nonce onto a valid one
- [x] Update the module and crate headers, the three profile examples, the fuzz README, the CHANGELOG and the spec
- [x] Re-run fmt, tests, clippy, the core build and both fuzz targets
- [ ] Expose the options in io-imap, io-smtp and io-managesieve once this crate is released
