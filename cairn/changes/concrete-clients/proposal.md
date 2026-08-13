---
cairn: change
id: concrete-clients
status: active
created: 2026-08-13
---

# Two concrete clients, over a framing the caller brings

## Why

The command surface gives a driver twelve methods for one `run`, and every consumer still writes that `run`. Written out, it is the same twenty lines everywhere: pump the mechanism, base64-encode a response, write a line, read a line, base64-decode it, hand it back, stop on completion. Only four facts inside those twenty lines differ between protocols, and a crate that ships the loop but not the client leaves each consumer to rediscover which four.

They are the four an implementation cannot guess from a socket, which is why the loop cannot simply be given a `Read + Write` and left to it:

- the command that opens the exchange, `a1 AUTHENTICATE LOGIN` against `AUTH LOGIN`, tag included where the protocol has one;
- the prefix a challenge arrives under, `+ ` against `334 `, which decides how much to strip before base64-decoding;
- the line that ends the exchange, `a1 OK ...` against `235 ...`. This is the load-bearing one: a client that cannot recognise it never resumes with `Done`, so LOGIN and PLAIN report `UnexpectedChallenge` on an authentication that in fact succeeded, and SCRAM never reaches the step that verifies the server signature. Mutual authentication skipped by omission is the failure this crate's three-cased resume exists to prevent, and a client guessing here would reintroduce it under the crate's own name;
- the line that reports a failure, `a1 NO ...` against `535 ...`.

The end of an exchange is a line rather than a closed connection, in every protocol carrying SASL, since the session continues afterwards. So there is no fallback: either the caller states these four facts, or the client speaks a wire format no server implements.

Given them, everything else really is shared, and shipping it is worth doing: the socket, the line reading, the transport base64, the loop, and the ordering rules the mechanisms depend on.

## What

Add `client::framing`, a small vocabulary the caller implements once per protocol:

```rust
pub trait SaslFraming {
    type Error;

    fn command(&mut self, mechanism: SaslMechanism, initial: Option<&[u8]>) -> Vec<u8>;
    fn response(&mut self, payload: &[u8]) -> Vec<u8>;
    fn reply(&mut self, line: &[u8]) -> Result<SaslReply, Self::Error>;
}

pub enum SaslReply {
    Challenge(Vec<u8>),
    Success,
    Failure,
}
```

`command` gets `initial` as `Some` only when the protocol may inline an initial response and the caller decided to, which keeps the SASL-IR policy where it already lives, in the protocol crate. `reply` owns the transport base64, since the prefix it strips and the encoding it undoes are one decision.

Then `client::std::SaslClientStd<S, F>` over `S: Read + Write`, implementing `SaslClient`, and `client::tokio::SaslClientTokio<S, F>` over `S: AsyncRead + AsyncWrite + Unpin + Send`, implementing `SaslClientAsync`, behind a new `tokio` cargo feature. Both hold the stream and the framing, read CRLF-terminated lines through a buffer of their own, and share one `SaslFraming`, so a consumer moving from blocking to async rewrites nothing but the client type.

Their failure type is a `SaslClientStdError<F>` carrying the framing's error, the transport's `io::Error`, a boxed mechanism failure and the `Failure` reply, which is the one place a crate-owned error is right: here this crate is the driver, so the framing errors are ones it can name.

## What this costs, and what it does not

The `tokio` feature pulls tokio, which is the first runtime dependency this crate has, gated off by default and never reachable from the coroutines. `std` arrives with it, gated the same way, so the no_std claim holds for every build that does not ask for a socket.

What it does not cost is the boundary: framing stays the protocol crate's, exactly as the spec says. What changes is that the protocol crate now states it in three methods rather than implementing a loop, and the loop it no longer writes is the one place the ordering rules of the mechanisms can be got wrong.

## What it is for

io-imap and io-smtp will not use these clients, and that is not an argument against them: both drive their own parsers over their own streams, and both will implement `SaslClient` on the client they already have. The value is for the third case, a consumer with a socket and a protocol that carries SASL and no Pimalaya crate for it yet, which is io-pop3, sirup's proxy handshake, and any test harness that wants a real exchange over a pipe rather than a scripted one. That is also the shape of the integration test proving it: an IMAP-shaped `SaslFraming` of about fifteen lines, driven against a recorded transcript.
