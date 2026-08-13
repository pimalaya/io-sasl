//! The command surface a protocol crate implements once, and inherits
//! every mechanism from.
//!
//! Driving a mechanism is the same loop everywhere: name it on the
//! wire, resume it, write what it asks for, read what the peer says,
//! hand that back, stop when it completes. What differs between io-imap
//! and io-smtp is the framing on either side of the loop, which is the
//! part the loop delegates anyway. So the loop is written once, as the
//! `run` method each trait requires, and every mechanism arrives as a
//! default body calling it.
//!
//! This adds no I/O to the crate. The implementation brings its own
//! transport and borrows it for the exchange: there is no stream here
//! to own, no connection to open, and nothing in either trait that
//! names one. That is also why the failure type belongs to the
//! implementation rather than to this crate, since the implementation
//! is what holds both kinds of failure, its framing errors and the
//! mechanism's.
//!
//! One module per flavour, since a driver is one or the other:
//! [`std`] carries the blocking [`std::SaslClient`], and `r#async` the
//! `SaslClientAsync` whose methods hand back futures, unlinked here
//! because rustdoc reads the `#` of a raw identifier as the start of a
//! URL fragment. The
//! two are twins, written out rather than generated from one list of
//! delegations: each body is a single call, and a surface read as often
//! as this one is worth reading as it was written. What a macro would
//! guarantee, that the two never drift, they get from carrying the same
//! method names, arguments and documentation, so a mechanism given to
//! one and not to the other is visible in the diff that adds it.

pub mod r#async;
pub mod std;
