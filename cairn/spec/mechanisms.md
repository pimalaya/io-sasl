---
cairn: spec
capability: mechanisms
status: current
---

# Mechanisms

Client-side mechanisms, each computing exactly what its specification puts on the wire, plus the vocabulary describing their credentials. The source tree follows the specifications: one module per RFC where one exists, and a root module for the mechanisms that never got one.

### Requirement: Coverage
The crate SHALL carry ANONYMOUS, EXTERNAL, GSSAPI, LOGIN, PLAIN, OAUTHBEARER, XOAUTH2 and the three SCRAM profiles, each of the latter under its plain and its `-PLUS` name. Mechanisms the IANA registry lists but a live specification discourages SHALL NOT be added, DIGEST-MD5 being Historic by RFC 6331.

### Requirement: Computed and relayed mechanisms
A mechanism whose payloads follow from its credentials SHALL compute them here. A mechanism whose payloads come from a security context this crate cannot host SHALL be carried as a relay instead of being left out: the crate holds the exchange, the caller holds the context. A relay SHALL claim nothing it cannot check, and its module SHALL name what it leaves to the caller.

### Requirement: Vocabulary
The `mechanism` module SHALL hold `SaslMechanism` (the tag, knowing its registered wire name) and `Sasl` (a tag paired with the credentials of one mechanism). `SaslMechanism` SHALL carry a variant per registered name whatever the build enables, `-PLUS` names included, since a consumer matching a server capability list has to name a mechanism it cannot run. `Sasl` SHALL carry one variant per profile rather than per name, the `-PLUS` names following from the credentials.

### Requirement: Credential locality
Each credential struct SHALL live in the module of the mechanism that transmits it, next to that mechanism's coroutine and failure type, or in the family module when several mechanisms share it. A struct serving one mechanism SHALL be convertible into `Sasl`; one shared by several SHALL NOT, an impl having no way to guess which variant was meant. A mechanism excluded by a cargo feature SHALL take its `Sasl` variant with it, an exchange this build cannot run having no shape to describe.

### Requirement: Naming
A mechanism SHALL name its coroutine, its failure type and its credential struct after the mechanism alone: `SaslPlain`, `SaslPlainError`, `SaslPlainCreds`. The `Auth` verb the Pimalaya naming canon would put on the coroutine SHALL be dropped, a verb every item of the crate shares telling none of them apart, and the credentials SHALL carry the `Creds` extension instead. This is a local exception to the canon, not a change to it.

### Requirement: Constructors
Each mechanism SHALL be built from the credential struct it shares with its `Sasl` variant, so a consumer matching on that enum reaches the mechanism it needs without restating the fields.

### Requirement: ANONYMOUS
`SaslAnonymous` (RFC 4505) SHALL answer `None` with the optional trace token, or an empty payload when there is none, and complete `Ok` on `Done`.

### Requirement: EXTERNAL
`SaslExternal` (RFC 4422 appendix A) SHALL answer `None` with the optional authorization identity, or an empty payload when there is none, and complete `Ok` on `Done`. It SHALL carry no secret of its own, the outer channel being what authenticates.

### Requirement: GSSAPI
`SaslGssapi` (RFC 4752) SHALL answer `None` with the first GSS-API token, which the credentials carry, and every `Input` with that input verbatim, then complete `Ok` on `Done`. Resumed out of order it SHALL complete `Err` with `OutOfOrder`.

It SHALL NOT read, verify or count the tokens: the caller feeds it what its own security context produced from each peer message, and only that context knows when the handshake is over. The security layer negotiation of RFC 4752 section 3.1 SHALL stay with the caller until this crate carries it as pure functions.

### Requirement: PLAIN
`SaslPlain` (RFC 4616) SHALL answer `None` with `authzid NUL authcid NUL passwd`, leaving the authorization identity empty when absent, and complete `Ok` on `Done`.

### Requirement: LOGIN
`SaslLogin` (draft-murchison-sasl-login) SHALL answer `None` with the username and the following challenge with the password, and complete `Ok` on `Done`. The mechanism SHALL see only the password prompt: the username prompt is the implicit empty challenge whose answer is the initial response, as RFC 4959 defines it.

### Requirement: OAUTHBEARER
`SaslOauthbearer` (RFC 7628) SHALL answer `None` with the GS2 header, the host, the port and the bearer token, separated and terminated by `%x01`. A JSON error challenge SHALL be answered with the single `%x01` of RFC 7628 section 3.2.3, after which the mechanism SHALL complete `Err` on `Done`, carrying the JSON the server sent.

### Requirement: XOAUTH2
`SaslXoauth2` (Google) SHALL answer `None` with the username and the bearer token, separated and terminated by `%x01`. A JSON error challenge SHALL be answered with the empty response Google documents, after which the mechanism SHALL complete `Err` on `Done`, carrying the JSON the server sent.

### Requirement: Credential handling
Passwords and tokens SHALL stay inside secret wrappers and SHALL NOT appear in logs or in debug output.
