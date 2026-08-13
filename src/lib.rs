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
//! Every mechanism is client-side: ANONYMOUS, CRAM-MD5, EXTERNAL,
//! GSSAPI, GS2-KRB5, LOGIN, PLAIN, OAUTHBEARER, XOAUTH2, and the SCRAM
//! profiles SHA-1, SHA-256 and SHA-512, the last four under both the
//! name they are registered with and the `-PLUS` name they take when a
//! channel binding is in use. Server-side SASL is out of scope.
//!
//! Most of them compute what they send. The two Kerberos mechanisms
//! cannot: their tokens come from an implementation that reads a
//! credential cache and talks to a KDC, which is I/O this crate can
//! neither host nor hoist into its credentials. They are carried anyway,
//! as relays: [`rfc4752::gssapi`] and [`rfc5801::gs2_krb5`] hold the
//! SASL half of the mechanism, the name, the initial response and the
//! sequencing, while the caller holds the security context. That is the
//! building block a consumer needs, not the whole mechanism, and each
//! module says exactly where the line falls.
//!
//! ## Layout
//!
//! One module per RFC where one exists, and a root module for the
//! mechanisms that never got one:
//!
//! - [`rfc2195::cram_md5`], the CRAM-MD5 mechanism, behind the
//!   `cram-md5` cargo feature and the only server-first one
//! - [`rfc4013`], SASLprep, which is not a mechanism but the string
//!   preparation PLAIN and SCRAM run their credentials through, behind
//!   the `saslprep` feature
//! - [`rfc4422::external`], the EXTERNAL mechanism, defined by the SASL
//!   framework itself
//! - [`rfc4505::anonymous`], the ANONYMOUS mechanism
//! - [`rfc4616::plain`], the PLAIN mechanism
//! - [`rfc4752::gssapi`], the GSSAPI mechanism, relayed rather than
//!   computed
//! - [`rfc5801`], the GS2 bridge: the channel binding vocabulary every
//!   `-PLUS` name rests on, and [`rfc5801::gs2_krb5`], Kerberos through
//!   that bridge
//! - [`rfc5802`], the SCRAM family and its SHA-1 profile
//!   ([`rfc5802::scram_sha_1`], behind the `scram-sha-1` cargo feature)
//! - [`rfc7628::oauthbearer`], the OAUTHBEARER mechanism
//! - [`rfc7677::scram_sha_256`], the SHA-256 profile of SCRAM
//! - [`login`], the LOGIN mechanism (draft-murchison-sasl-login)
//! - [`scram_sha_512`], the SHA-512 profile of SCRAM
//!   (draft-melnikov-scram-sha-512)
//! - [`xoauth2`], the XOAUTH2 mechanism (Google, pre-standard)
//!
//! Everything SCRAM sits behind the `scram` cargo feature, which pulls
//! in the HMAC, PBKDF2, SHA-2 and base64 crates the algorithm needs, and
//! the SHA-1 profile behind `scram-sha-1` on top, since it is the one
//! that pulls another digest crate. The exchange itself is written once,
//! in [`rfc5802::SaslScram`]: a profile module is its digest, the two
//! names it is registered under, and the test vector it is pinned by.
//!
//! Each mechanism module opens with a runnable example driving its
//! exchange step by step, which is the shortest description of what a
//! protocol crate has to do with it.
//!
//! Each module holds one mechanism whole: its coroutine, its failure
//! type, and the credential struct describing what it needs, since what
//! a mechanism transmits is part of that mechanism rather than of a
//! catalogue somewhere else. The three are named after the mechanism
//! and nothing else ([`rfc4616::plain::SaslPlain`],
//! [`rfc4616::plain::SaslPlainError`],
//! [`rfc4616::plain::SaslPlainCreds`]): the naming canon would give the
//! coroutine an `Auth` verb, and this crate drops it, since a verb
//! every single item shares distinguishes none of them. `Creds` carries
//! the distinction instead, and it is the credentials rather than the
//! coroutine that read as data here.
//!
//! [`coroutine`] holds the contract spanning them, and [`mechanism`]
//! the vocabulary tying them together: [`mechanism::SaslMechanism`]
//! tags a mechanism without its credentials, which is what a consumer
//! matches a server capability list against, and [`mechanism::Sasl`]
//! pairs a tag with the credentials of one, gathering those structs
//! into the closed set a protocol crate dispatches on.
//!
//! ## The coroutine contract
//!
//! Every mechanism implements [`coroutine::SaslCoroutine`], whose
//! resume method takes a [`coroutine::SaslArg`] and returns either
//! a [`coroutine::SaslYield`] or the terminal `Result<(), Error>`.
//!
//! The resume argument has three cases rather than an optional
//! challenge, because "the peer ended the exchange" has to stay
//! distinguishable from "here is a challenge". On
//! [`coroutine::SaslArg::Done`] the one-shot mechanisms
//! complete `Ok`, while every SCRAM profile completes `Err` whenever the
//! server signature has not been verified yet. Were the protocol crate
//! deciding for itself when an exchange ends, PLAIN and SCRAM would
//! look identical from outside, send then await the success reply, and
//! SCRAM's mutual authentication would be skipped by omission.
//!
//! The first resume takes [`coroutine::SaslArg::None`]. A
//! mechanism answering it with [`coroutine::SaslYield::WantsWrite`] has
//! an initial response ([RFC 4422]), which the protocol may inline in
//! its authentication command: IMAP needs the `SASL-IR` capability
//! ([RFC 4959]) for that, SMTP carries it unconditionally in the
//! [RFC 4954] grammar. Whether to inline it, and whether a given
//! server can be trusted to accept it, is the protocol crate's
//! decision, not this crate's. A mechanism answering
//! [`coroutine::SaslYield::WantsRead`] is server-first instead, which
//! CRAM-MD5 is and nothing else here: the protocol then has no initial
//! response to inline and sends its command bare.
//!
//! ## The command surface
//!
//! Driving a mechanism is the same loop for every one of them, and the
//! `client` module holds it, one submodule per flavour: `client::std`
//! carries the blocking `SaslClient`, `client::r#async` its twin
//! `SaslClientAsync`. Each requires one `run` method, the loop itself,
//! and gives back one method per mechanism. A protocol crate writes its
//! framing once instead of once per mechanism, which is where its six
//! or twelve near-identical authentication paths go.
//!
//! Both sit behind the `client` cargo feature, on by default, so a
//! consumer driving the mechanisms itself compiles neither. One feature
//! covers both flavours, since neither pulls a dependency in and there
//! is nothing to save by leaving the other out. Neither adds I/O
//! either: the implementation brings its own transport, borrowing it
//! for the exchange, so nothing in either trait names a stream and this
//! crate still opens nothing. The failure type is the implementation's
//! for the same reason, it being what holds the framing errors this
//! crate has no vocabulary for.
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
//! Randomness belongs to the caller, and so does the TLS session. SCRAM
//! reads its client nonce off the credentials it is built from, since an
//! I/O-free mechanism cannot generate entropy, and reads its channel
//! binding off them too, since asking a TLS session what it exported is
//! not something this crate can do either. Both stay with the other
//! credentials rather than beside them, so a protocol crate holding a
//! [`mechanism::Sasl`] always has everything the exchange needs and
//! there is no mechanism for which it could forget to pass something.
//! The exchange also stays deterministically testable against the
//! published vectors.
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

#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub mod client;
pub mod coroutine;
pub mod login;
pub mod mechanism;
#[cfg(feature = "cram-md5")]
#[cfg_attr(docsrs, doc(cfg(feature = "cram-md5")))]
pub mod rfc2195;
#[cfg(feature = "saslprep")]
#[cfg_attr(docsrs, doc(cfg(feature = "saslprep")))]
pub mod rfc4013;
pub mod rfc4422;
pub mod rfc4505;
pub mod rfc4616;
pub mod rfc4752;
pub mod rfc5801;
#[cfg(feature = "scram")]
#[cfg_attr(docsrs, doc(cfg(feature = "scram")))]
pub mod rfc5802;
pub mod rfc7628;
#[cfg(feature = "scram")]
#[cfg_attr(docsrs, doc(cfg(feature = "scram")))]
pub mod rfc7677;
#[cfg(feature = "scram")]
#[cfg_attr(docsrs, doc(cfg(feature = "scram")))]
pub mod scram_sha_512;
pub mod xoauth2;
