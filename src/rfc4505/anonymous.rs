//! The ANONYMOUS mechanism ([RFC 4505]).
//!
//! One message, no secret: the client sends an optional trace token
//! the server may log, and the server ends the exchange. The token is
//! UTF-8 and at most 255 characters, and an absent token is sent as an
//! empty response.
//!
//! # Example
//!
//! ```rust
//! use io_sasl::{
//!     coroutine::{SaslCoroutine, SaslCoroutineState, SaslResume, SaslYield},
//!     rfc4505::anonymous::{SaslAnonymous, SaslAnonymousCreds},
//! };
//!
//! let mut auth = SaslAnonymous::new(SaslAnonymousCreds {
//!     message: Some("alice@localhost".into()),
//! });
//!
//! let state = auth.resume(SaslResume::Start);
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(payload)) = state else {
//!     panic!("expected the trace token");
//! };
//!
//! assert_eq!(payload, b"alice@localhost");
//!
//! // The server accepted, so its success reply ends the exchange
//! // without a further challenge.
//! let state = auth.resume(SaslResume::PeerFinished);
//!
//! let SaslCoroutineState::Complete(result) = state else {
//!     panic!("expected the exchange to end");
//! };
//!
//! result.unwrap();
//! ```
//!
//! [RFC 4505]: https://www.rfc-editor.org/rfc/rfc4505

use alloc::string::String;

use log::debug;
use thiserror::Error;

use crate::{coroutine::*, mechanism::SaslMechanism};

/// Failure causes of the ANONYMOUS exchange.
#[derive(Clone, Debug, Error)]
pub enum SaslAnonymousError {
    /// The mechanism was resumed with a challenge it does not expect,
    /// or out of order.
    #[error("SASL ANONYMOUS failed: unexpected challenge after the trace token")]
    UnexpectedChallenge,
}

/// ANONYMOUS mechanism credentials ([RFC 4505]).
///
/// Carries an optional trace token (typically an email-like string the
/// server can log); no secrets.
///
/// [RFC 4505]: https://www.rfc-editor.org/rfc/rfc4505
#[derive(Clone, Debug)]
pub struct SaslAnonymousCreds {
    /// The optional trace token logged by the server.
    pub message: Option<String>,
}

/// I/O-free SASL ANONYMOUS mechanism.
pub struct SaslAnonymous {
    creds: SaslAnonymousCreds,
    state: State,
}

impl SaslAnonymous {
    /// Builds the mechanism from its optional trace token.
    pub fn new(creds: SaslAnonymousCreds) -> Self {
        Self {
            creds,
            state: State::SendTraceToken,
        }
    }
}

impl SaslCoroutine for SaslAnonymous {
    type Error = SaslAnonymousError;

    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::Anonymous
    }

    fn resume(
        &mut self,
        arg: SaslResume<'_>,
    ) -> SaslCoroutineState<SaslYield, Result<(), Self::Error>> {
        if let SaslResume::PeerFinished = arg {
            debug!("anonymous exchange completed");
            return SaslCoroutineState::Complete(Ok(()));
        }

        match self.state {
            State::SendTraceToken => {
                let trace = self.creds.message.take().unwrap_or_default();
                self.state = State::Done;
                debug!("anonymous trace token sent");
                SaslCoroutineState::Yielded(SaslYield::WantsWrite(trace.into_bytes()))
            }
            State::Done => {
                let err = SaslAnonymousError::UnexpectedChallenge;
                SaslCoroutineState::Complete(Err(err))
            }
        }
    }
}

enum State {
    SendTraceToken,
    Done,
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use crate::{coroutine::*, rfc4505::anonymous::*};

    #[test]
    fn start_responds_with_the_trace_token() {
        let creds = SaslAnonymousCreds {
            message: Some("alice@localhost".to_string()),
        };
        let mut auth = SaslAnonymous::new(creds);

        assert_eq!(respond(&mut auth, SaslResume::Start), b"alice@localhost");
    }

    #[test]
    fn start_responds_empty_without_trace_token() {
        let mut auth = SaslAnonymous::new(SaslAnonymousCreds { message: None });

        assert!(respond(&mut auth, SaslResume::Start).is_empty());
    }

    #[test]
    fn peer_finished_completes_ok() {
        let mut auth = SaslAnonymous::new(SaslAnonymousCreds { message: None });

        let _ = respond(&mut auth, SaslResume::Start);

        assert!(matches!(
            auth.resume(SaslResume::PeerFinished),
            SaslCoroutineState::Complete(Ok(())),
        ));
    }

    #[test]
    fn extra_challenge_completes_err() {
        let mut auth = SaslAnonymous::new(SaslAnonymousCreds { message: None });

        let _ = respond(&mut auth, SaslResume::Start);

        assert!(matches!(
            auth.resume(SaslResume::Challenge(b"")),
            SaslCoroutineState::Complete(Err(SaslAnonymousError::UnexpectedChallenge)),
        ));
    }

    fn respond(auth: &mut SaslAnonymous, arg: SaslResume<'_>) -> Vec<u8> {
        match auth.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }
}
