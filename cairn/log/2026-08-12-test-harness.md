---
cairn: log
change: test-harness
landed: 2026-08-12
---

# Test harness: contract properties, a vocabulary sweep and two fuzz targets

Brought the crate up to the testing standard of the mature Pimalaya libraries. No behaviour changed: the bootstrap code is untouched, and the twenty-six unit tests it shipped with still pass unmodified.

Added tests/exchange.rs, which drives whole exchanges through the public API the way a protocol crate does, with every assertion phrased as a property over all six mechanisms at once: each has an initial response, so none is server-first and a protocol may inline it; each completes on `PeerFinished`, and only SCRAM-SHA-256 refuses it, at each of the three points before its verification could have run; and a challenge arriving after a mechanism has said its last word fails with its unexpected-challenge error rather than being answered twice or mistaken for success. The table erases the six unrelated error types behind their rendered messages, which is the only way one driver can carry all six.

Gave the vocabulary module the unit tests it was the only module without, walking its routing as one table rather than six cases: every tag against the name it is registered under with IANA, every credential struct against the variant it converts into, and no two mechanisms sharing either. Six one-line tests would each check their own arm in isolation, which is not where six copy-pasted arms go wrong.

Added tests/coverage.rs for the one claim no module can make about itself: that each coroutine answers with the tag of the module it lives in. It had nothing testing it, and it is the tag a protocol crate writes on the wire, so a crossed arm would send AUTHENTICATE PLAIN and then run a SCRAM exchange inside it.

Added the fuzz package, a separate unpublished crate detached from the library's workspace, with the shell.nix providing the nightly toolchain cargo-fuzz needs. The exchange target drives all six mechanisms with fuzzed credentials and fuzzed challenges, in order and out of order, against the oracle that no peer message ever panics a mechanism. The scram target is the security oracle: it derives the salted password, the server key and the server signature itself, from the RFC 5802 primitives and from the bytes it watched the mechanism send, and asserts that the mechanism accepts no other server-final-message and never completes `Ok` without one. That is the invariant the two implementations this crate replaces both got wrong, and it is not observable from inside the state machine that holds it.

Coverage went from 87.93% to 100% of the library, the closed gap being the vocabulary and the mechanism accessors that no test had ever called. tarpaulin.toml keeps the fuzz package out of the measured surface, since tarpaulin finds those files by name without ever building them.

Capability recorded for the first time: testing.
