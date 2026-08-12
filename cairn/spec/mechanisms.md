---
cairn: spec
capability: mechanisms
status: current
---

# Mechanisms

Six client-side mechanisms, each computing exactly what its specification puts on the wire, plus the vocabulary describing their credentials. The source tree follows the specifications: one module per RFC where one exists, and a root module for the two mechanisms that never got one.

### Requirement: Vocabulary
The `mechanism` module SHALL hold `SaslMechanism` (the tag, knowing its registered wire name) and `Sasl` (a tag paired with the credentials of one mechanism). `SaslMechanism` SHALL carry a variant per mechanism whatever the build enables, since a consumer matching a server capability list has to name a mechanism it cannot run.

### Requirement: Credential locality
Each credential struct SHALL live in the module of the mechanism that transmits it, next to that mechanism's coroutine and failure type, and SHALL be convertible into `Sasl`. A mechanism excluded by a cargo feature SHALL take its credential struct and its `Sasl` variant with it, an exchange this build cannot run having no shape to describe.

### Requirement: Naming
A mechanism SHALL name its coroutine, its failure type and its credential struct after the mechanism alone: `SaslPlain`, `SaslPlainError`, `SaslPlainCreds`. The `Auth` verb the Pimalaya naming canon would put on the coroutine SHALL be dropped, a verb every item of the crate shares telling none of them apart, and the credentials SHALL carry the `Creds` extension instead. This is a local exception to the canon, not a change to it.

### Requirement: Constructors
Each mechanism SHALL be built from its own credential struct, so a consumer matching on `Sasl` reaches the mechanism it needs without restating the fields.

### Requirement: ANONYMOUS
`SaslAnonymous` (RFC 4505) SHALL answer `Start` with the optional trace token, or an empty payload when there is none, and complete `Ok` on `PeerFinished`.

### Requirement: PLAIN
`SaslPlain` (RFC 4616) SHALL answer `Start` with `authzid NUL authcid NUL passwd`, leaving the authorization identity empty when absent, and complete `Ok` on `PeerFinished`.

### Requirement: LOGIN
`SaslLogin` (draft-murchison-sasl-login) SHALL answer `Start` with the username and the following challenge with the password, and complete `Ok` on `PeerFinished`. The mechanism SHALL see only the password prompt: the username prompt is the implicit empty challenge whose answer is the initial response, as RFC 4959 defines it.

### Requirement: OAUTHBEARER
`SaslOauthbearer` (RFC 7628) SHALL answer `Start` with the GS2 header, the host, the port and the bearer token, separated and terminated by `%x01`. A JSON error challenge SHALL be answered with the single `%x01` of RFC 7628 section 3.2.3, after which the mechanism SHALL complete `Err` on `PeerFinished`, carrying the JSON the server sent.

### Requirement: XOAUTH2
`SaslXoauth2` (Google) SHALL answer `Start` with the username and the bearer token, separated and terminated by `%x01`. A JSON error challenge SHALL be answered with the empty response Google documents, after which the mechanism SHALL complete `Err` on `PeerFinished`, carrying the JSON the server sent.

### Requirement: Credential handling
Passwords and tokens SHALL stay inside secret wrappers and SHALL NOT appear in logs or in debug output.
