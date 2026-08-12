---
cairn: change
id: mechanism-naming
status: landed
created: 2026-08-12
---

# Name a mechanism's types after the mechanism alone

## Why

Moving the credential structs next to their coroutines left two types in each module whose names no longer said how they relate: `SaslLogin` the credentials and `SaslAuthLogin` the coroutine read as unrelated types, where the naming canon has a companion mirror its parent (`SaslAuthLoginCreds` would).

Two ways out, and the verb is what decides between them. The canon puts the verb on the action and leaves pure data without one, which is why the coroutine carried `Auth`. But every item in this crate is an authentication exchange, so `Auth` never told two of them apart: it is the degenerate case the canon already handles for a target, dropped when the action applies to the whole exchange. Dropping it gives `SaslLogin` for the coroutine and pairs it with `SaslLoginCreds`, which mirrors it exactly, is shorter, and stops branding a struct that configuration and account wizards also build as the companion of a coroutine they never run.

The cost is that the verb-less name now belongs to the machine rather than to the data. `Creds` carries that distinction instead, and carries it on the type where a reader wants it.

## What

Rename the six coroutines and their failure types, dropping `Auth`, and give the six credential structs the `Creds` extension. Record the exception where a future reader meets it: the crate header, CONTRIBUTING and the mechanisms spec, so nobody restores the verb as a conformance fix.

The exception stays local. io-imap keeps `ImapAuthPlain`, since it also carries coroutines that authenticate nothing, and the org guidelines are not touched.
