//! The EXTERNAL mechanism ([RFC 4422 appendix A]).
//!
//! One message, no secret and no computation: the client names the
//! identity it wants to act as, or sends nothing and lets the server
//! derive it from what the outer channel already proved. That channel is
//! typically a TLS client certificate, sometimes an IPsec association or
//! a peer-credentialed unix socket.
//!
//! The mechanism transmits no credential of its own, which is the whole
//! point: it says the authentication happened somewhere else. An empty
//! authorization identity is the usual case and the one a server can
//! always answer, since it already knows who the channel belongs to.
//!
//! # Example
//!
//! ```rust
//! use io_sasl::{
//!     coroutine::{SaslCoroutine, SaslCoroutineState, SaslArg, SaslYield},
//!     rfc4422::external::{SaslExternal, SaslExternalCreds},
//! };
//!
//! let mut auth = SaslExternal::new(SaslExternalCreds { authzid: None });
//!
//! // The empty payload is data, not an absence: it tells the server to
//! // use the identity the channel already carries.
//! let state = auth.resume(SaslArg::None);
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(payload)) = state else {
//!     panic!("expected the authorization identity");
//! };
//!
//! assert!(payload.is_empty());
//!
//! let state = auth.resume(SaslArg::Done);
//!
//! let SaslCoroutineState::Complete(result) = state else {
//!     panic!("expected the exchange to end");
//! };
//!
//! result.unwrap();
//! ```
//!
//! [RFC 4422 appendix A]: https://www.rfc-editor.org/rfc/rfc4422#appendix-A

use alloc::string::String;

use log::debug;
use thiserror::Error;

use crate::{coroutine::*, mechanism::SaslMechanism};

/// Failure causes of the EXTERNAL exchange.
#[derive(Clone, Debug, Error)]
pub enum SaslExternalError {
    /// The mechanism was resumed with a challenge it does not expect,
    /// or out of order.
    #[error("SASL EXTERNAL failed: unexpected challenge after the authorization identity")]
    UnexpectedChallenge,
}

/// EXTERNAL mechanism credentials ([RFC 4422 appendix A]).
///
/// Carries no secret, since the outer channel is what authenticates:
/// the only thing to say is which identity to act as, and saying
/// nothing asks the server to use the one the channel proved.
///
/// [RFC 4422 appendix A]: https://www.rfc-editor.org/rfc/rfc4422#appendix-A
#[derive(Clone, Debug)]
pub struct SaslExternalCreds {
    /// The optional authorization identity, sent as UTF-8.
    pub authzid: Option<String>,
}

/// I/O-free SASL EXTERNAL mechanism.
pub struct SaslExternal {
    creds: SaslExternalCreds,
    state: State,
}

impl SaslExternal {
    /// Builds the mechanism from its optional authorization identity.
    pub fn new(creds: SaslExternalCreds) -> Self {
        Self {
            creds,
            state: State::SendAuthzid,
        }
    }
}

impl SaslCoroutine for SaslExternal {
    type Error = SaslExternalError;

    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::External
    }

    fn resume(
        &mut self,
        arg: SaslArg<'_>,
    ) -> SaslCoroutineState<SaslYield, Result<(), Self::Error>> {
        if let SaslArg::Done = arg {
            debug!("external exchange completed");
            return SaslCoroutineState::Complete(Ok(()));
        }

        match self.state {
            State::SendAuthzid => {
                let authzid = self.creds.authzid.take().unwrap_or_default();
                self.state = State::Done;
                debug!("external authorization identity sent");
                SaslCoroutineState::Yielded(SaslYield::WantsWrite(authzid.into_bytes()))
            }
            State::Done => {
                let err = SaslExternalError::UnexpectedChallenge;
                SaslCoroutineState::Complete(Err(err))
            }
        }
    }
}

enum State {
    SendAuthzid,
    Done,
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use crate::{coroutine::*, rfc4422::external::*};

    #[test]
    fn start_responds_with_the_authorization_identity() {
        let creds = SaslExternalCreds {
            authzid: Some("alice@localhost".to_string()),
        };
        let mut auth = SaslExternal::new(creds);

        assert_eq!(respond(&mut auth, SaslArg::None), b"alice@localhost");
    }

    #[test]
    fn start_responds_empty_without_authorization_identity() {
        let mut auth = SaslExternal::new(SaslExternalCreds { authzid: None });

        assert!(respond(&mut auth, SaslArg::None).is_empty());
    }

    #[test]
    fn peer_finished_completes_ok() {
        let mut auth = SaslExternal::new(SaslExternalCreds { authzid: None });

        let _ = respond(&mut auth, SaslArg::None);

        assert!(matches!(
            auth.resume(SaslArg::Done),
            SaslCoroutineState::Complete(Ok(())),
        ));
    }

    #[test]
    fn extra_challenge_completes_err() {
        let mut auth = SaslExternal::new(SaslExternalCreds { authzid: None });

        let _ = respond(&mut auth, SaslArg::None);

        assert!(matches!(
            auth.resume(SaslArg::Input(b"")),
            SaslCoroutineState::Complete(Err(SaslExternalError::UnexpectedChallenge)),
        ));
    }

    fn respond(auth: &mut SaslExternal, arg: SaslArg<'_>) -> Vec<u8> {
        match auth.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }
}
