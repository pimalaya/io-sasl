---
cairn: delta
change: mechanism-hardening
---

## ADDED Requirements

### Requirement: Separators
A credential SHALL NOT be able to add or shift a field of the message carrying it. The OAUTHBEARER authorization identity SHALL be escaped as the GS2 header asks, `=` as `=3D` and `,` as `=2C`. OAUTHBEARER and XOAUTH2 SHALL complete `Err` with `InvalidCreds` at the first resume when the username, the host or the token holds `%x01`. PLAIN SHALL complete `Err` when a field holds a NUL, which preparation refuses as a control character.

### Requirement: Server message syntax
The server-first-message SHALL be read in the order RFC 5802 section 7 gives it, the `r=` nonce, the `s=` salt and the `i=` iteration count, failing with `MissingNonce`, `MissingSalt` or `MissingIterations` when one is not at its place, and what follows the iteration count SHALL be taken as extensions and not read. The server-final-message SHALL be read up to its first comma, extensions after it being allowed and not read. Either message carrying the reserved `m=` attribute SHALL fail with `MandatoryExtension`, as RFC 5802 section 5.1 requires.

## MODIFIED Requirements

### Requirement: Credential preparation
PLAIN and SCRAM SHALL prepare their username and password with SASLprep (RFC 4013) before sending or deriving anything, in every build, and SHALL complete `Err` when a credential carries a code point the profile prohibits. Preparation SHALL NOT sit behind a cargo feature, so that a protocol crate cannot run either mechanism unprepared by leaving one out. The preparation SHALL apply every rule that changes the bytes going out: the non-ASCII space mapping, the removals, NFKC normalization and the prohibited output tables. The bidirectional rule and the unassigned code points of RFC 3454 MAY be left out, both rejecting strings rather than changing them.

### Requirement: Credential handling
Passwords and tokens SHALL stay inside secret wrappers and SHALL NOT appear in logs or in debug output. `SaslYield` SHALL debug-print a payload as its length, never its bytes, the payload being the password or the token for several mechanisms. The keys SCRAM derives and the prepared copy of a password SHALL be held in buffers wiped when dropped.

### Requirement: Dependencies
The vocabulary and the mechanisms needing no cryptography SHALL depend only on `secrecy`, `log`, `thiserror` and `unicode-normalization`, the last without its `std` feature. `base64-codec`, `hmac`, `pbkdf2` and `sha2` SHALL be optional and pulled by the `scram` feature, `sha1` by `scram-sha-1`, and `md-5` by `cram-md5`. A random number generator SHALL NOT be a dependency, and neither SHALL a TLS implementation or a Kerberos one.
