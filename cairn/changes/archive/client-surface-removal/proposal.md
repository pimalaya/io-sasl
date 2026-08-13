---
cairn: change
id: client-surface-removal
status: landed
created: 2026-08-13
---

# Take the command surface back out

## Why

The surface landed with twelve mechanisms on two traits and no way to use either without writing the loop, which is what `run` is. That was the point of the design and it is also the flaw: the loop is framing, and framing is the protocol's. A trait whose one required method is "do the protocol's part" does not move the boundary, it just names it here.

Trying to ship a concrete client made that unavoidable rather than debatable. `SaslClientStd` over a socket cannot tell a challenge from the success reply, so the design needed a `SaslFraming` describing the opening command, the challenge prefix and the terminal replies: IMAP and SMTP grammar, described in this crate's vocabulary, in a crate whose whole claim is that it holds no protocol. That is the rip-starttls shape, a library growing a model of the protocols above it, and it ends the same way, with the model always one quirk behind the real thing.

The traits without the client are no better, only smaller. They give a protocol crate twelve one-line methods in exchange for a `run` it already writes today, and io-imap and io-smtp both already have the client the methods would hang off. So the surface's value was always going to be realised one layer up, where the framing already lives.

## What

Remove the `client` module, both traits, the `client` cargo feature and the two surface test files, and restore the crate to mechanisms and vocabulary only. The capability spec goes with them, and packaging and testing return to what they said before.

The idea is not dropped, it moves: io-imap is where a `run`-plus-defaults surface belongs, because that is where the framing, the command grammar and the continuation vocabulary already are, and where a `Sasl` dispatcher can be written against a real transport. The concrete-clients proposal is kept, marked rejected rather than deleted, since the four-facts argument in it is what should be reread when the same idea is proposed again for this crate.

What the exercise settled, and what should survive it: the failure type belongs to whoever drives the exchange, the async twin needs `Send` on the trait and on the future, and a mechanism reached through a surface has to be swept against the name it reports. Those hold wherever the surface ends up.
