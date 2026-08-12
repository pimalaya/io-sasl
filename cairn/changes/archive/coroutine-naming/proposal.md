---
cairn: change
id: coroutine-naming
status: landed
created: 2026-08-12
---

# Name the yield and the states the way io-imap does

## Why

Two vocabularies drifted from the crate that reads this one.

The yield variants named the mechanism's act rather than the caller's: `Respond` and `AwaitChallenge` describe what the mechanism is doing, where io-imap's `WantsRead` and `WantsWrite` describe what the caller has to do before resuming. A driver written against both crates matched on two different conventions in the same file.

The private state enums named the step behind them: `Start`, `SentUsername`, `SentPassword`. A state is read when deciding what a resume does next, so naming it after the previous step forces the reader to translate every time, and the first variant carried no information at all. io-imap names the step ahead (`SendClientFirst`, `SendClientFinal`, `Acknowledge`).

## What

Rename the yield to `WantsWrite` and `WantsChallenge`, and the states of all six mechanisms to what their next resume does.

The read side keeps the SASL word rather than io-imap's `WantsRead`, deliberately. `WantsRead` is right in io-imap, where the caller reads bytes off a socket and hands them over. Here the caller strips its framing and its transport base64 first, so what it hands over is a challenge, not a read; RFC 4422 calls every server-to-client message a challenge whatever the mechanism, and the name then pairs with the `SaslArg::Challenge` it asks for.

Record both conventions where a new mechanism will meet them: the yield docs, CONTRIBUTING and the coroutines spec.
