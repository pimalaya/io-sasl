---
cairn: log
change: client-surface-removal
landed: 2026-08-13
---

# The command surface, removed the same day it landed

`SaslClient`, `SaslClientAsync`, the `client` feature and the two surface test files are gone, and the crate is mechanisms and vocabulary again, at the same 98.22% it was at before they arrived.

What removed them was trying to make them useful. The traits require `run`, and `run` is the loop: write what the mechanism yields, read what the peer says, tell a challenge from the reply that ends the exchange. Every one of those steps is framing, and framing is the protocol's, so the surface handed a protocol crate twelve one-line methods in exchange for writing the only part that was ever hard. Attempting the concrete client made the boundary explicit: `SaslClientStd` over a socket needs the opening command, the challenge prefix and the terminal replies, which is IMAP and SMTP grammar described in this crate's vocabulary. That is a library growing a model of the protocols above it, the rip-starttls shape, and the model is always one quirk behind the servers.

So the surface goes up a layer rather than away. io-imap already holds the framing, the command grammar, the continuation vocabulary and a client to hang the methods off, and it is where a `Sasl` dispatcher can be written against a real transport. The concrete-clients proposal is kept in the archive marked rejected rather than deleted, since the four facts it enumerates are the argument to reread when this is proposed here again.

Three conclusions outlived the code and should be carried wherever the surface lands. The failure type belongs to whoever drives the exchange, not to the crate supplying the mechanism, because the driver is what holds framing errors and mechanism failures at once; a fixed error would have had it boxing its own errors in and unboxing them out. An async surface needs `Send` as a supertrait and on the future its methods return, since an `async fn` in a trait cannot promise it and every default body would then fail under a spawning runtime; a blocking one needs neither, and requiring it would exclude a thread-affine transport. And a surface of near-identical one-line bodies has to be swept against the mechanism each one names, since every body typechecks against its own credentials and no compiler catches two of them landing on the same coroutine.

The client-traits log entry above stays as it was written. It records what landed, which is what a log is for; this one records that it did not stay.

Capabilities moved: client (removed), packaging, testing.
