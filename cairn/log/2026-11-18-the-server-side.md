---
cairn: log
change: the-server-side
landed: 2026-11-18
---

# The server side

Pimalaya Server needs SASL on the server side for SMTP submission, LMTP and IMAP, so the crate grew a `server` feature and module: `SaslServer` runs PLAIN and LOGIN, parses what the client sends (already base64-decoded by the protocol crate) and yields `Verify` with the credentials, the caller resuming with its verdict. It never checks a password itself.

The client mechanisms moved behind a new `client` feature, on by default, so a server build compiles no client code. `SaslMechanism` and SASLprep stay in every build; `scram` and `cram-md5` imply `client`, their mechanisms being client-side. This is breaking for `default-features = false` consumers, who add `features = ["client"]`.

Unit tests pin PLAIN (valid, rejected, malformed, empty authzid, cancel, out of order) and LOGIN (with and without initial response). A third fuzz target, `server`, drives arbitrary responses, cancels and verdicts and asserts no success without a positive verdict; a 60 s smoke run found nothing.

Capabilities moved: packaging (sides), server (new).
