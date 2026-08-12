#![no_std]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! # io-sasl
//!
//! I/O-free [SASL] mechanisms. An authentication exchange is a
//! resumable state machine computing the payloads a mechanism sends
//! and checking the ones it receives, while the protocol crate owns
//! the socket and the framing. The crate is no_std and alloc-only: it
//! opens nothing, reads nothing, and generates no randomness.
//!
//! ## Scope
//!
//! The cut is payload and challenge/response computation here, wire
//! framing there. What a mechanism transmits is fixed by its
//! specification and identical everywhere: PLAIN is `authzid NUL
//! authcid NUL passwd` whether it travels inside an IMAP
//! `AUTHENTICATE` command or an SMTP `AUTH` command. What differs is
//! only how the bytes are carried, so io-imap and io-smtp keep their
//! command grammars, their continuation requests and their reply
//! codes, and share the mechanisms.
//!
//! Six mechanisms are implemented, all client-side: ANONYMOUS, LOGIN,
//! PLAIN, OAUTHBEARER, XOAUTH2 and SCRAM-SHA-256. Server-side SASL,
//! channel binding and the GSSAPI family are out of scope.
//!
//! ## Layout
//!
//! One module per RFC where one exists, and a root module for the
//! mechanisms that never got one:
//!
//! - [`rfc4505::anonymous`], the ANONYMOUS mechanism
//! - [`rfc4616::plain`], the PLAIN mechanism
//! - [`rfc7628::oauthbearer`], the OAUTHBEARER mechanism
//! - [`rfc7677::scram_sha_256`], the SCRAM-SHA-256 mechanism, behind
//!   the `scram` cargo feature, which pulls in the HMAC, PBKDF2,
//!   SHA-256 and base64 crates the algorithm needs
//! - [`login`], the LOGIN mechanism (draft-murchison-sasl-login)
//! - [`xoauth2`], the XOAUTH2 mechanism (Google, pre-standard)
//!
//! Each mechanism module opens with a runnable example driving its
//! exchange step by step, which is the shortest description of what a
//! protocol crate has to do with it.
//!
//! Each module holds one mechanism whole: its coroutine, its failure
//! type, and the credential struct describing what it needs, since what
//! a mechanism transmits is part of that mechanism rather than of a
//! catalogue somewhere else.
//!
//! [`coroutine`] holds the contract spanning them, and [`mechanism`]
//! the vocabulary tying them together: [`mechanism::SaslMechanism`]
//! tags a mechanism without its credentials, which is what a consumer
//! matches a server capability list against, and [`mechanism::Sasl`]
//! pairs a tag with the credentials of one, gathering the six structs
//! into the closed set a protocol crate dispatches on.
//!
//! ## The coroutine contract
//!
//! Every mechanism implements [`coroutine::SaslCoroutine`], whose
//! resume method takes a [`coroutine::SaslResume`] and returns either
//! a [`coroutine::SaslYield`] or the terminal `Result<(), Error>`.
//!
//! The resume argument has three cases rather than an optional
//! challenge, because "the peer ended the exchange" has to stay
//! distinguishable from "here is a challenge". On
//! [`coroutine::SaslResume::PeerFinished`] the one-shot mechanisms
//! complete `Ok`, while SCRAM-SHA-256 completes `Err` whenever the
//! server signature has not been verified yet. Were the protocol crate
//! deciding for itself when an exchange ends, PLAIN and SCRAM would
//! look identical from outside, send then await the success reply, and
//! SCRAM's mutual authentication would be skipped by omission.
//!
//! The first resume takes [`coroutine::SaslResume::Start`]. A
//! mechanism answering it with [`coroutine::SaslYield::Respond`] has
//! an initial response ([RFC 4422]), which the protocol may inline in
//! its authentication command: IMAP needs the `SASL-IR` capability
//! ([RFC 4959]) for that, SMTP carries it unconditionally in the
//! [RFC 4954] grammar. Whether to inline it, and whether a given
//! server can be trusted to accept it, is the protocol crate's
//! decision, not this crate's. A mechanism answering
//! [`coroutine::SaslYield::AwaitChallenge`] is server-first instead;
//! none of the six are, but the vocabulary expresses it.
//!
//! ## Boundaries
//!
//! Errors split by whose rule was broken. A mechanism failure lives
//! here: a mismatched server signature, a server nonce that does not
//! extend the client nonce, a malformed server message, a rejected
//! OAuth token. A framing violation stays in the protocol crate: an
//! expected continuation request that never came, a success reply
//! arriving mid-exchange. The one case on the line is a challenge
//! arriving when the mechanism has nothing left to say, which only the
//! mechanism can recognise, so each mechanism reports it as its own
//! unexpected-challenge failure.
//!
//! Base64 splits the same way. Transport encoding belongs to the
//! protocol crate, which encodes a response before writing it and
//! decodes a challenge before handing it over, so this crate deals in
//! raw bytes at that boundary. The exception is the intra-message
//! base64 of [RFC 5802], the `s=` salt and the `p=` proof, which is
//! part of the algorithm rather than of the transport and lives with
//! SCRAM-SHA-256.
//!
//! Randomness belongs to the caller. SCRAM-SHA-256 reads its client
//! nonce off the credentials it is built from, since an I/O-free
//! mechanism cannot generate entropy, and the exchange stays
//! deterministically testable against the published test vectors.
//! Keeping the nonce with the other credentials rather than beside them
//! means a protocol crate holding a [`mechanism::Sasl`] always has
//! everything the exchange needs, so there is no mechanism for which it
//! could forget to pass something.
//!
//! ## Conventions
//!
//! The conventions every Pimalaya repository shares are described in
//! the org
//! [ARCHITECTURE](https://github.com/pimalaya/.github/blob/master/ARCHITECTURE.md)
//! and
//! [GUIDELINES](https://github.com/pimalaya/.github/blob/master/GUIDELINES.md);
//! this crate's own deviations and its build matrix live in
//! CONTRIBUTING.md, and its living spec and history in the cairn/
//! folder. Logging follows the library rules: debug marks the
//! lifecycle points, trace carries the data; credentials never reach
//! the logs.
//!
//! [SASL]: https://www.rfc-editor.org/rfc/rfc4422
//! [RFC 4422]: https://www.rfc-editor.org/rfc/rfc4422#section-3
//! [RFC 4954]: https://www.rfc-editor.org/rfc/rfc4954#section-4
//! [RFC 4959]: https://www.rfc-editor.org/rfc/rfc4959
//! [RFC 5802]: https://www.rfc-editor.org/rfc/rfc5802

extern crate alloc;

pub mod coroutine;
pub mod login;
pub mod mechanism;
pub mod rfc4505;
pub mod rfc4616;
pub mod rfc7628;
#[cfg(feature = "scram")]
#[cfg_attr(docsrs, doc(cfg(feature = "scram")))]
pub mod rfc7677;
pub mod xoauth2;
