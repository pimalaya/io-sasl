---
cairn: spec
capability: mechanisms
status: current
---

# Mechanisms

Six client-side mechanisms, each computing exactly what its specification puts on the wire, plus the vocabulary describing their credentials. The source tree follows the specifications: one module per RFC where one exists, and a root module for the two mechanisms that never got one.

### Requirement: Vocabulary
The `mechanism` module SHALL hold `SaslMechanism` (the tag, knowing its registered wire name), `Sasl` (the tag plus its credentials), and the six credential structs `SaslAnonymous`, `SaslLogin`, `SaslPlain`, `SaslOauthbearer`, `SaslXoauth2` and `SaslScramSha256`, each convertible into `Sasl`. The tag and the credentials SHALL stay in one module, being two views of one closed set.

### Requirement: Constructors
Each mechanism SHALL be built from its own credential struct, so a consumer matching on `Sasl` reaches the mechanism it needs without restating the fields.

### Requirement: ANONYMOUS
`SaslAuthAnonymous` (RFC 4505) SHALL answer `Start` with the optional trace token, or an empty payload when there is none, and complete `Ok` on `PeerFinished`.

### Requirement: PLAIN
`SaslAuthPlain` (RFC 4616) SHALL answer `Start` with `authzid NUL authcid NUL passwd`, leaving the authorization identity empty when absent, and complete `Ok` on `PeerFinished`.

### Requirement: LOGIN
`SaslAuthLogin` (draft-murchison-sasl-login) SHALL answer `Start` with the username and the following challenge with the password, and complete `Ok` on `PeerFinished`. The mechanism SHALL see only the password prompt: the username prompt is the implicit empty challenge whose answer is the initial response, as RFC 4959 defines it.

### Requirement: OAUTHBEARER
`SaslAuthOauthbearer` (RFC 7628) SHALL answer `Start` with the GS2 header, the host, the port and the bearer token, separated and terminated by `%x01`. A JSON error challenge SHALL be answered with the single `%x01` of RFC 7628 section 3.2.3, after which the mechanism SHALL complete `Err` on `PeerFinished`, carrying the JSON the server sent.

### Requirement: XOAUTH2
`SaslAuthXoauth2` (Google) SHALL answer `Start` with the username and the bearer token, separated and terminated by `%x01`. A JSON error challenge SHALL be answered with the empty response Google documents, after which the mechanism SHALL complete `Err` on `PeerFinished`, carrying the JSON the server sent.

### Requirement: Credential handling
Passwords and tokens SHALL stay inside secret wrappers and SHALL NOT appear in logs or in debug output.
