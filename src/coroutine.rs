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
/// Challenges are carried already base64-decoded: transport encoding
/// belongs to the protocol, which decodes an IMAP continuation request
/// or an SMTP 334 line before handing the bytes over.
#[derive(Debug)]
pub enum SaslResume<'a> {
    /// Nothing has been exchanged yet.
    ///
    /// A mechanism answering [`SaslYield::Respond`] has an initial
    /// response ([RFC 4422 section 3]), which the protocol may inline
    /// in its authentication command when its grammar allows it. A
    /// mechanism answering [`SaslYield::AwaitChallenge`] is
    /// server-first and has nothing to say yet.
    ///
    /// [RFC 4422 section 3]: https://www.rfc-editor.org/rfc/rfc4422#section-3
    Start,
    /// The peer sent this (already base64-decoded) challenge.
    Challenge(&'a [u8]),
    /// The peer ended the exchange (an IMAP tagged OK, an SMTP 235,
    /// ...) without a further challenge.
    PeerFinished,
}

/// What the mechanism asks the protocol crate to do.
#[derive(Debug)]
pub enum SaslYield {
    /// Send these raw (not yet base64-encoded) bytes as the next
    /// response.
    ///
    /// An empty payload is an acknowledgement rather than data: a
    /// protocol whose framing already ended the exchange may drop it
    /// instead of writing an empty line.
    Respond(Vec<u8>),
    /// The mechanism has nothing to send and needs the peer's next
    /// challenge.
    AwaitChallenge,
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
    /// The first call takes [`SaslResume::Start`]. Every following
    /// call answers the previous yield: a challenge the peer sent, or
    /// [`SaslResume::PeerFinished`] when the peer closed the exchange
    /// instead of challenging again.
    fn resume(
        &mut self,
        arg: SaslResume<'_>,
    ) -> SaslCoroutineState<SaslYield, Result<(), Self::Error>>;
}
