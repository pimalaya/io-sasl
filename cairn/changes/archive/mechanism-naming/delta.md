---
cairn: delta
change: mechanism-naming
---

## ADDED Requirements

### Requirement: Naming
A mechanism SHALL name its coroutine, its failure type and its credential struct after the mechanism alone: `SaslPlain`, `SaslPlainError`, `SaslPlainCreds`. The `Auth` verb the Pimalaya naming canon would put on the coroutine SHALL be dropped, a verb every item of the crate shares telling none of them apart, and the credentials SHALL carry the `Creds` extension instead. This is a local exception to the canon, not a change to it.
