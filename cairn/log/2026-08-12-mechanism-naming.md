---
cairn: log
change: mechanism-naming
landed: 2026-08-12
---

# Mechanism naming: the verb dropped, the credentials extended

Renamed the six coroutines and their failure types by dropping the `Auth` verb, and gave the six credential structs the `Creds` extension: `SaslAuthPlain` and `SaslPlain` became `SaslPlain` and `SaslPlainCreds`, and the same for ANONYMOUS, LOGIN, OAUTHBEARER, XOAUTH2 and SCRAM-SHA-256, errors included.

The pass that moved the credentials next to their coroutines is what exposed the question. Once the two types sit in one module, `SaslLogin` the credentials and `SaslAuthLogin` the coroutine read as unrelated, where the canon has a companion mirror its parent. Restoring the mirror the other way, `SaslAuthLoginCreds`, keeps the verb but brands a struct that configuration and account wizards build as the companion of a coroutine they never run, and yields `SaslAuthScramSha256Creds`. Dropping the verb instead is the degenerate case the canon already handles for a target, omitted when the action applies to the whole exchange: every item here is an authentication exchange, so `Auth` never told two of them apart. What it costs is that the verb-less name now belongs to the machine rather than to the data, which is the signal the canon usually gives; `Creds` carries the distinction instead, and carries it where a reader wants it.

The exception is recorded in the three places a future reader meets it: the crate header, which is this crate's architecture document, a CONTRIBUTING section stating that it is local and that anything outside the crate follows the canon, and a Naming requirement in the mechanisms spec. io-imap keeps `ImapAuthPlain`, needing the verb because it also carries coroutines that authenticate nothing, and the org guidelines are untouched.

Mechanical everywhere else: the doctests, the unit tests, the integration tests, the fuzz targets and the CHANGELOG vocabulary entry. No behaviour changed, and the mechanism module keeps holding `SaslMechanism` and `Sasl` under their own names.

Capability moved: mechanisms.
