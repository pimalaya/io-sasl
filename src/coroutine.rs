//! The SASL coroutine contract, shared by every mechanism.
//!
//! A mechanism is a resumable state machine computing challenge and
//! response payloads, never touching a socket and never framing
//! anything: the protocol crate owns the wire, feeds the mechanism what
//! the peer said, and writes back what the mechanism asks for. The
//! contract is deliberately three-cased on the way in, so that "the
//! peer ended the exchange" stays distinguishable from "here is a
//! challenge": a mechanism performing mutual authentication has to be
//! able to refuse an exchange that ended before it verified anything.

use alloc::vec::Vec;

use crate::mechanism::SaslMechanism;

/// State returned by a [`SaslCoroutine::resume`] step.
#[derive(Debug)]
pub enum SaslCoroutineState<Y, R> {
    /// Intermediate step: the mechanism needs the caller to act on the
    /// carried request before the next resume.
    Yielded(Y),
    /// Terminal step: the exchange is over and carries its outcome.
    Complete(R),
}

/// What the protocol crate feeds back into the mechanism.
///
/// Input is carried already base64-decoded: transport encoding belongs
/// to the protocol, which decodes an IMAP continuation request or an
/// SMTP 334 line before handing the bytes over.
#[derive(Debug, Default)]
pub enum SaslArg<'a> {
    /// Nothing has been exchanged yet.
    ///
    /// A mechanism answering [`SaslYield::WantsWrite`] has an initial
    /// response ([RFC 4422 section 3]), which the protocol may inline
    /// in its authentication command when its grammar allows it. A
    /// mechanism answering [`SaslYield::WantsRead`] is server-first
    /// and has nothing to say yet.
    ///
    /// [RFC 4422 section 3]: https://www.rfc-editor.org/rfc/rfc4422#section-3
    #[default]
    None,
    /// The bytes the mechanism asked for.
    ///
    /// For a mechanism computing its own payloads, which is all of them
    /// but one, this is the challenge the peer sent, decoded. For a
    /// mechanism relaying an outside security context
    /// ([`crate::rfc4752::gssapi`]) it is what that context produced
    /// from the peer's message, since the relay computes nothing and
    /// the caller is what holds the context. The variant is named for
    /// the role rather than for the origin, so that both fit.
    Input(&'a [u8]),
    /// The peer ended the exchange (an IMAP tagged OK, an SMTP 235,
    /// ...) without a further challenge.
    Done,
}

/// What the mechanism wants the protocol crate to do next.
///
/// The two variants are io-imap's, down to the word, so that a driver
/// written against both crates matches on one vocabulary. Each names
/// the caller's action rather than the mechanism's, since the caller is
/// what has to act before the next resume.
///
/// What the crates differ on is not the yield but what comes back from
/// a read: io-imap resumes with the bytes it read, while here the
/// caller strips its framing and its transport base64 first, and a
/// relaying mechanism gets what the caller's own security context made
/// of the result. That is why the argument carrying it is named
/// [`SaslArg::Input`], for its role rather than for its origin.
#[derive(Debug)]
pub enum SaslYield {
    /// The mechanism has nothing to send and wants what the caller
    /// reads next, which comes back as [`SaslArg::Input`], or as
    /// [`SaslArg::Done`] when the peer ends the exchange instead of
    /// speaking again.
    WantsRead,
    /// The caller writes these raw bytes as the next response,
    /// base64-encoding and framing them for its own transport first.
    ///
    /// An empty payload is an acknowledgement rather than data: a
    /// protocol whose framing already ended the exchange may drop it
    /// instead of writing an empty line.
    WantsWrite(Vec<u8>),
}

/// Standard-shape SASL mechanism: owns its exchange state, names
/// itself, and returns `Result<(), Error>` on completion.
///
/// Completing `Ok(())` means the mechanism is satisfied, which for a
/// mutual mechanism such as SCRAM implies the server proved itself
/// too. Completing `Err` means the mechanism failed on its own terms
/// (a bad signature, a mismatched nonce, a malformed message); the
/// protocol crate keeps its own framing errors for its own violations.
pub trait SaslCoroutine {
    /// The mechanism failure type.
    type Error;

    /// The mechanism tag, so the protocol crate can name it on the
    /// wire.
    fn mechanism(&self) -> SaslMechanism;

    /// Advances the exchange one step.
    ///
    /// The first call takes [`SaslArg::None`]. Every following
    /// call answers the previous yield: a challenge the peer sent, or
    /// [`SaslArg::Done`] when the peer closed the exchange
    /// instead of challenging again.
    fn resume(
        &mut self,
        arg: SaslArg<'_>,
    ) -> SaslCoroutineState<SaslYield, Result<(), Self::Error>>;
}
