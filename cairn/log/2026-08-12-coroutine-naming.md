---
cairn: log
change: coroutine-naming
landed: 2026-08-12
---

# Coroutine naming: the yield and the states named the io-imap way

Renamed `SaslYield::Respond` to `WantsWrite` and `AwaitChallenge` to `WantsChallenge`, and renamed the private state enum of every mechanism to what its next resume does.

Both vocabularies had drifted from io-imap, which is the crate that reads this one. A yield says what the caller must do before resuming, which is what `WantsRead` and `WantsWrite` say there and what `Respond` and `AwaitChallenge` did not say here. The read side keeps the SASL word rather than becoming `WantsRead`, and that is a decision rather than an oversight: io-imap's caller reads bytes off a socket and hands them straight over, while this crate's caller strips its framing and its transport base64 first, so what arrives is a challenge and not a read. RFC 4422 calls every server-to-client message a challenge whatever the mechanism, so the name holds for all six, and it pairs by name with the `SaslResume::Challenge` the mechanism is asking for.

The states now name the step ahead instead of the step behind: `SendUsername`, `SendPassword`, `Done` for LOGIN, `SendTraceToken` and `SendCreds` for the one-shot mechanisms, `SendToken`, `Done` and `Fail` for the two OAuth ones, and `SendClientFirst`, `SendClientFinal`, `Acknowledge`, `Done` for SCRAM-SHA-256, which is io-imap's own list for the same exchange. A state is read while deciding what the next resume does, so naming it after the previous step made the reader translate every time, and the old first variant, `Start`, said nothing at all.

Both conventions are now written down where a seventh mechanism will meet them: the yield docs carry the caller's-side wording and the reason the read side differs, CONTRIBUTING states them next to the local type-naming exception, and the coroutines spec gained a State naming requirement and a rewritten yield requirement.

No behaviour changed. The thirty-four tests and six doctests pass in both feature shapes, clippy is clean with warnings denied, rustdoc is clean with warnings denied, coverage holds at 100% of the library, and both fuzz targets rebuild and run clean.

Capability moved: coroutines.
