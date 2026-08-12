---
cairn: change
id: kerberos-legacy-and-preparation
status: landed
created: 2026-08-13
---

# Add GS2-KRB5, the security layer helpers, SASLprep and CRAM-MD5

## Why

Four gaps were left after the relay landed, and they are not the same kind of gap.

GS2-KRB5 is the mechanism RFC 5801 wrote to replace the RFC 4752 one, and it is a better fit here than its predecessor: the GS2 header is this crate's to write, so the relay stops being a pure pipe, and the header is what gives Kerberos a `-PLUS` name and the downgrade detection SCRAM already had. The channel binding vocabulary was sitting in the SCRAM module, which is where SCRAM found it rather than where it is defined.

The security layer negotiation was the one message of the GSSAPI exchange this crate could compute and did not, so a consumer wanting full GSSAPI had to write four octets by hand from a table in an RFC.

SASLprep is the only gap that makes a supported mechanism wrong rather than absent. PLAIN and SCRAM both say the client prepares its credentials, and the crate sent what it was given, so a password with a non-breaking space or a decomposed accent fails against a server that stored the prepared form, and the failure looks exactly like a wrong password.

CRAM-MD5 is legacy compatibility and nothing more, but it became cheap once the contract tests learned to split properties by class: it is the first server-first mechanism, and that is now a predicate rather than a rewrite.

## What

Move the channel binding types into a new `rfc5801` module holding the GS2 bridge, with the header assembly they need, and have SCRAM use it. Add `rfc5801::gs2_krb5` on top, a relay like GSSAPI but writing its own header.

Add the RFC 4752 section 3.1 offer and choice as pure functions on the GSSAPI module, since their bytes travel wrapped and only the caller can move them through its context.

Add `rfc4013`, SASLprep implemented against RFC 3454's tables rather than pulled from a crate, since the two published implementations are std. Apply it in PLAIN and SCRAM at their first resume, so a credential that cannot be prepared fails the exchange instead of going out unprepared.

Add `rfc2195::cram_md5` behind its own feature, pinned by the exchange RFC 2195 publishes, and split the initial-response property by class so the server-first case is stated rather than assumed.
