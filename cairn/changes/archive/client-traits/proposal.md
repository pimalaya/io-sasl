---
cairn: change
id: client-traits
status: landed
created: 2026-08-13
---

# A command surface a protocol crate implements once

## Why

Every protocol crate driving this library writes the same loop: name the mechanism on the wire, resume it, write what it asks for, read what the peer says, hand it back, stop when it completes. The loop is twenty lines and it is the same twenty lines in io-imap, in io-smtp and in anything else that authenticates. What differs is the framing on either side of it, which is exactly the part the loop delegates.

io-imap is solving the same problem one layer up with `ImapClient` and `ImapClientAsync`: one required `run` method, and every command arrives as a default body. The plan behind it (IO_IMAP_CLIENT_PLAN.md, task 2) wants the shape validated somewhere small before it is called canon, and this crate is the smallest place it fits: twelve mechanisms, no transport of its own, no runtime.

The difference is what makes it a validation rather than a copy. io-imap owns the socket, so its client owns the stream and its error type can be the crate's own. This crate owns nothing: the implementation brings its transport, borrows it for the exchange, and already has a failure type carrying its framing errors. So the surface here is a trait and only a trait, and the error is the implementation's.

## What

Add `client::SaslClient` and `client::SaslClientAsync`, behind one `client` cargo feature covering both, each requiring one method:

```rust
fn run<C>(&mut self, mechanism: C) -> Result<(), Self::Error>
where
    C: SaslCoroutine,
    Self::Error: From<C::Error>;
```

and giving one default body per mechanism in return. LOGIN lands first, alone, so the shape is reviewed before eleven more bodies rest on it.

The error is an associated type rather than a crate-owned enum, which is where this diverges from io-imap deliberately. A fixed `SaslClientError` would force io-imap to box its own framing errors into it and unbox them again, since the driving crate is the one holding both kinds of failure. The `From` bounds that would be unusable on the trait are usable on each method: an implementation pays only for the mechanisms it calls.

Both traits are written out, which is where this parts from io-imap's macro over one list. Each body is a single call, the surface is read far more often than it is edited, and keeping the two adjacent puts a mechanism given to one and not to the other in the diff that adds it.

`SaslClientAsync` carries `Send`, as a supertrait and on the future `run` returns. A plain `async fn` in a trait cannot promise a `Send` future, so every default body would fail under `tokio::spawn`, which is the first thing a worker-spawning consumer reaches for. `SaslClient` carries no such bound: a blocking call returns a value, and requiring `Send` would exclude a thread-affine transport such as a JNI bridge.

Out of scope here, and worth doing next: a `Sasl` dispatcher default, matching the credential enum onto the twelve mechanism methods. That is the match io-imap and io-smtp each write by hand today, and it is what the trait exists to delete, but it cannot be written before the twelve bodies are.
