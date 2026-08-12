---
cairn: change
id: missing-mechanisms
status: landed
created: 2026-08-12
---

# Add EXTERNAL, the other SCRAM profiles and channel binding

## Why

The crate carried six mechanisms picked by what a mail client needs today, which leaves it defined by usage rather than by the specifications it is organised around. Completeness is the better line, filtered to what a client can run without an external security library: three names were missing on that line, and one capability was missing from a family already implemented.

EXTERNAL is defined by the SASL framework itself and costs nothing to implement, one message and no computation. It is how a client says the outer channel already authenticated it, which is the shape a TLS client certificate takes on the wire.

SCRAM was implemented in one profile out of three. SHA-1 is the original of RFC 5802 and the only one some servers ever enabled; SHA-512 is registered with IANA through a draft. Neither is more than a digest away from the profile already here.

Channel binding is the larger gap. Every SCRAM profile is registered twice, and the `-PLUS` name is the one that ties the exchange to its TLS connection: without it, a machine in the middle can proxy an authentication it cannot read. Worse, a client that never sends the `y` flag makes a stripped `-PLUS` offer invisible to a server that does support binding, so the downgrade goes unnoticed by both ends.

## What

Implement EXTERNAL, generalise SCRAM over its digest, add the SHA-1 and SHA-512 profiles, and give the family channel binding in all three RFC 5802 cases.

Write the exchange once. A profile then adds its digest, the two names it is registered under, and the exchange it is pinned by, which is what stops three profiles from becoming three copies of the same cryptography, the duplication this crate exists to remove.

Take the binding material with the credentials, as the client nonce already is, since extracting it means asking a TLS session what it exported. Let the binding pick the mechanism name the coroutine reports, so a bound exchange announces `-PLUS` by construction rather than by the caller remembering to.

Leave pimalaya-stream alone for now: it is what will have to expose the TLS exporter before a consumer can fill the binding in, and that is a separate decision.
