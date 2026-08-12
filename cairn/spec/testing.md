---
cairn: spec
capability: testing
status: current
---

# Testing

The crate is a security primitive with no I/O, so everything it does is reachable from a test and nothing it does needs a server. Three layers answer three different questions: the unit tests pin each mechanism against its own specification, the integration tests pin the contract the mechanisms share, and the fuzz targets pin what no example exchange can, which is that acceptance is never granted to something that was not verified.

### Requirement: Specification vectors
Each mechanism SHALL be pinned by unit tests asserting the exact payloads its specification defines. SCRAM-SHA-256 SHALL be pinned by the exchange published in RFC 7677 section 3; when it fails, the code is wrong, never the vector.

### Requirement: Contract properties
The integration tests SHALL state the coroutine contract as properties over the whole mechanism set rather than as statements about single mechanisms, so a mechanism added later is held to the same edges: every mechanism answers `Start` with a response, every mechanism completes on `PeerFinished`, a mechanism performing mutual authentication completes `Err` on `PeerFinished` at every point before its verification ran, and a challenge arriving after a mechanism has said its last word completes with its unexpected-challenge failure instead of another success.

### Requirement: Vocabulary sweep
The closed vocabulary SHALL be walked whole rather than sampled one mechanism at a time, since what a set of near-identical arms gets wrong is two of them landing on the same place. The `mechanism` module SHALL walk its own routing: every `SaslMechanism` against the wire name it is registered under, and every credential struct against the `Sasl` variant it converts into, with no two mechanisms sharing a name or a variant. The tag every mechanism coroutine reports SHALL be walked in the integration tests, being the one claim no single module can make; it is load-bearing, since that tag is what a protocol crate writes on the wire and a crossed arm would name one mechanism while running another.

### Requirement: Coverage
Line coverage of the library SHALL stay at 100%, measured with cargo-tarpaulin over all features. Production code SHALL NOT be shaped to move the number: code no meaningful test can reach is deleted rather than covered. The fuzz package SHALL be excluded from the measured surface, which tarpaulin.toml does.

### Requirement: Fuzz targets
The repository SHALL carry a cargo-fuzz package, unpublished and detached from the library's cargo workspace, holding at least two coverage-guided targets: one driving all six mechanisms with arbitrary credentials and arbitrary peer messages, in order and out of order, and one driving SCRAM-SHA-256 with arbitrary server messages.

### Requirement: SCRAM acceptance oracle
The SCRAM-SHA-256 target SHALL check acceptance against arithmetic performed outside the mechanism: it derives the salted password, the server key and the server signature itself, from the RFC 5802 primitives and from the messages it watched the mechanism send, and asserts that the mechanism neither acknowledges a server-final-message other than that one nor completes `Ok` without having verified one.
