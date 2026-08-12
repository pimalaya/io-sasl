---
cairn: log
change: kerberos-legacy-and-preparation
landed: 2026-08-13
---

# GS2-KRB5, the security layer helpers, SASLprep and CRAM-MD5

Four additions, three of which were waiting on decisions the relay pass had already made.

GS2-KRB5 arrived with a move. The channel binding vocabulary had been living in the SCRAM module, which is where SCRAM found it rather than where RFC 5801 defines it, so it moved into a new rfc5801 module along with the header assembly it implies, and SCRAM now calls that instead of formatting `n,,` itself. rfc5801::gs2_krb5 sits on top: the same relay as GSSAPI, except the header is this crate's to write, so the mechanism computes something after all, and the header is what gives Kerberos a `-PLUS` name and the same downgrade detection SCRAM has. The move paid for itself immediately, since the `y` flag, the escaping and the base64 of the binding are now written once for both families.

The security layer negotiation of RFC 4752 section 3.1, which the relay pass deliberately left out, is now two pure functions rather than coroutine steps: its four octets travel wrapped, so only the caller can move them through its context, and a step that cannot see its own bytes would be a step in name only. `SaslGssapiSecurityLayerOffer::parse` reads the bitmask and the maximum size, refusing a truncated offer or one naming no layer the RFC defines, and `SaslGssapiSecurityLayerChoice::to_bytes` writes the answer, truncating a size the three-octet field cannot hold rather than sending its low bits and announcing something smaller than it means.

SASLprep is the one that fixes a mechanism rather than adding one. PLAIN and SCRAM both say the client prepares its credentials, and the crate sent them as typed, so a password with a non-breaking space or a decomposed accent failed against any server that stored the prepared form, and failed looking exactly like a wrong password. The two published Rust implementations are std, which this crate cannot take, so rfc4013 implements the profile against the RFC 3454 tables: the non-ASCII space mapping, the removals, NFKC, and the prohibited output tables, which are all small ranges. The bidirectional rule and the unassigned code points are left out and said to be left out; both reject strings rather than change them, so neither can alter what goes on the wire. Preparation happens at the first resume rather than at construction, which keeps every constructor infallible and reports a prohibited character through the failure channel the mechanism already had. The SCRAM test that pins it is the RFC 7677 vector with a soft hyphen inside the password: preparation removes it and the published proof comes out, which is the shortest way to say the derivation ran on prepared bytes.

CRAM-MD5 cost almost nothing because the properties had already learned to split by class. It is the first server-first mechanism here, answering the first resume with `WantsRead`, so the universal "every mechanism has an initial response" became a predicate next to the two the relay pass introduced. Three exhaustive matches now stand between a new mechanism and a green test run, which is the intent.

One test was wrong and the code was right, which is worth recording: U+0340 is prohibited by RFC 3454 appendix C.8 and cannot survive NFKC, which folds it onto U+0300, so checking prohibitions after normalization is what the profile means and the test asserting a refusal was asserting the wrong order.

The SCRAM fuzz target then found its own assumption. It asserted that the mechanism answers the first resume with a response, which stopped being true the moment preparation could refuse a fuzzed credential before the exchange starts. The oracle now accepts a refusal there and only a refusal: answering that first resume with a success, or with a read, is still a finding.

78 unit tests, 5 contract properties, 1 tag sweep and 12 doctests pass with every feature enabled, 47 and 4 and 1 and 7 with none. Coverage reads 98.22%, the eight lines it counts short being the multi-line-expression artifact already documented.

Capabilities moved: mechanisms, scram, packaging, testing.
