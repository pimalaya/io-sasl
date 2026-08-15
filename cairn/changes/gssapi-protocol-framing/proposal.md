---
cairn: change
id: gssapi-protocol-framing
status: draft
created: 2026-08-14
---

# Frame the GSSAPI relay from a protocol crate

## Why

The relay landed with no consumer. `rfc4752::gssapi` holds the SASL half of the mechanism, the name on the wire, the initial response and the sequencing, and every one of its properties is exercised by this crate's own tests, but no protocol crate frames it, so the question the relay was built to answer, what a caller actually has to write, has never been answered in code. Writing it down before someone needs it costs nothing and keeps the design from being rediscovered under deadline.

The reason it cannot simply appear as one more mechanism in io-imap's SASL folder is the contract inversion. Every other mechanism there is fed the server's bytes: the coroutine reads a continuation request and resumes the mechanism with `SaslArg::Input(&challenge)`. GSSAPI's `Input` carries the opposite, the output of the caller's own security context, and the relay proves it by echoing whatever it is given straight back as `WantsWrite`. So the protocol coroutine has to hand the server's continuation out to its caller and take a token back, and the standard yield vocabulary, which is `WantsRead` and `WantsWrite` and nothing else, cannot say that.

By the invariant-versus-opinionated rule that decides io-imap's client surface, a coroutine needing its own yield enum is one implementations are expected to wire differently, so it falls outside the defaulted commands, next to watch, idle and the streamed fetches. That is the whole finding: GSSAPI is not a missing mechanism, it is a missing shape.

## What

Add `ImapAuthGssapi` to io-imap with a yield enum of its own: the usual `WantsRead` and `WantsWrite`, plus `WantsToken(Vec<u8>)` carrying the peer token the caller feeds to its context, plus `WantsUnwrap(Vec<u8>)` and `WantsWrap(Vec<u8>)` for the security layer negotiation. The last two exist because the four octets of RFC 4752 section 3.1 travel wrapped and this crate deliberately stops at plaintext, `SaslGssapiSecurityLayerOffer::parse` and `SaslGssapiSecurityLayerChoice::to_bytes` being plain functions rather than steps of the coroutine. Ship it with one example per runtime, as the other custom-yield coroutines are shipped, because the code belongs to the consumer.

Host it in `ImapSessionOpen` rather than only in the auth folder. That coroutine already yields work it cannot do itself, `WantsTcpConnect` and `WantsTlsUpgrade`, so a caller answering a token request is answering the same kind of question, and the precedent is already set. `ImapClientStd::connect` keeps refusing `Sasl::Gssapi` with `UnsupportedMechanism`, since a std client has no security context to answer with; a consumer that wants Kerberos pumps the session itself, which is what the tokio session example already demonstrates for every other yield.

Support the `None` security layer only, and fail on the rest. This is the real boundary, and it is not an authentication question: picking integrity or confidentiality leaves every later message on that connection wrapped, which io-imap's fragmentizer and all forty command coroutines assume never happens. A wrapping transport belongs at the `ImapStream` boundary, as consumer code, the same place a JNI bridge or a proxy socket already lives. Under TLS, `None` is what everyone picks anyway.

Default this mechanism to the non-IR flow. A Kerberos AP-REQ commonly runs one to two kilobytes, and its base64 inline on the command line can exceed what a server accepts, which is a property of the token rather than of the server's RFC 4959 support. No upstream change is needed for the name: imap-types has no `Gssapi` variant, and `AuthMechanism::Other` carries it.

Rejected, and worth recording because it is what most libraries do: taking the security context as a callback, `ImapAuthGssapi::new(ctx: impl GssContext)`, which would keep the standard yield vocabulary and stay inside the client trait's defaults. It would also put a credential cache read and a KDC round trip inside `resume`, which is the one property this family exists to protect, and would block an executor on a single-threaded runtime.

If the goal is Kerberos rather than GSSAPI specifically, `rfc5801::gs2_krb5` is the cheaper target and should land first: the GS2 bridge drops the wrapped negotiation entirely, so the yield enum loses `WantsWrap` and `WantsUnwrap`, nothing is wrapped after authentication, and the channel binding this crate already models composes with it.
