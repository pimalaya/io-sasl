---
cairn: tasks
change: gssapi-protocol-framing
---

- [ ] Add `ImapAuthGssapi` and its yield enum to io-imap, outside the client trait's defaulted commands
- [ ] Relay the peer token through `WantsToken`, and the negotiation plaintext through `WantsUnwrap` and `WantsWrap`
- [ ] Refuse a negotiated security layer other than `None`, naming the wrapping transport as the caller's
- [ ] Default the mechanism to the non-IR flow, an AP-REQ being too large to inline reliably
- [ ] Yield the same requests from `ImapSessionOpen`, and keep `ImapClientStd::connect` refusing `Sasl::Gssapi`
- [ ] Add one example per runtime, as the other custom-yield coroutines have
- [ ] Consider landing `rfc5801::gs2_krb5` first, its three yields covering the same need
- [ ] Update the io-imap README, CHANGELOG and docs, then re-run fmt, clippy, tests, doctests and rustdoc
