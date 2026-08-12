//! The LOGIN mechanism ([draft-murchison-sasl-login], never
//! standardised).
//!
//! Two cleartext prompts, username then password, each answered by one
//! response. The mechanism is obsolete but still the only one some
//! servers offer, and like PLAIN it belongs on a TLS-protected
//! connection only.
//!
//! The mechanism sees a single challenge, the password prompt. The
//! username prompt is the implicit empty challenge whose answer is the
//! initial response, exactly as [RFC 4959] defines it for SASL-IR, so
//! the protocol crate feeds only the second prompt: a server-first
//! flow answers the empty "Username:" challenge with the initial
//! response the mechanism already produced on
//! [`SaslResume::Start`].
//!
//! # Example
//!
//! ```rust
//! use io_sasl::{
//!     coroutine::{SaslCoroutine, SaslCoroutineState, SaslResume, SaslYield},
//!     login::SaslAuthLogin,
//!     mechanism::SaslLogin,
//! };
//! use secrecy::SecretString;
//!
//! let mut auth = SaslAuthLogin::new(SaslLogin {
//!     username: "alice".into(),
//!     password: SecretString::from("pencil"),
//! });
//!
//! let state = auth.resume(SaslResume::Start);
//!
//! let SaslCoroutineState::Yielded(SaslYield::Respond(user)) = state else {
//!     panic!("expected the username");
//! };
//!
//! assert_eq!(user, b"alice");
//!
//! // The server prompts for the password. The prompt is human-readable
//! // filler the mechanism ignores, the step alone being what matters.
//! let state = auth.resume(SaslResume::Challenge(b"Password:"));
//!
//! let SaslCoroutineState::Yielded(SaslYield::Respond(pass)) = state else {
//!     panic!("expected the password");
//! };
//!
//! assert_eq!(pass, b"pencil");
//!
//! let state = auth.resume(SaslResume::PeerFinished);
//!
//! let SaslCoroutineState::Complete(result) = state else {
//!     panic!("expected the exchange to end");
//! };
//!
//! result.unwrap();
//! ```
//!
//! [draft-murchison-sasl-login]: https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login-00
//! [RFC 4959]: https://www.rfc-editor.org/rfc/rfc4959

use alloc::string::ToString;

use log::debug;
use secrecy::ExposeSecret;
use thiserror::Error;

use crate::{
    coroutine::*,
    mechanism::{SaslLogin, SaslMechanism},
};

/// Failure causes of the LOGIN exchange.
#[derive(Clone, Debug, Error)]
pub enum SaslAuthLoginError {
    /// The mechanism was resumed with a challenge it does not expect,
    /// or out of order.
    #[error("SASL LOGIN failed: unexpected challenge after the password")]
    UnexpectedChallenge,
}

/// I/O-free SASL LOGIN mechanism.
pub struct SaslAuthLogin {
    creds: SaslLogin,
    state: State,
}

impl SaslAuthLogin {
    /// Builds the mechanism from its credentials.
    pub fn new(creds: SaslLogin) -> Self {
        Self {
            creds,
            state: State::Start,
        }
    }
}

impl SaslCoroutine for SaslAuthLogin {
    type Error = SaslAuthLoginError;

    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::Login
    }

    fn resume(
        &mut self,
        arg: SaslResume<'_>,
    ) -> SaslCoroutineState<SaslYield, Result<(), Self::Error>> {
        if let SaslResume::PeerFinished = arg {
            debug!("login exchange completed");
            return SaslCoroutineState::Complete(Ok(()));
        }

        match self.state {
            State::Start => {
                let username = self.creds.username.as_bytes().to_vec();
                self.state = State::SentUsername;
                debug!("login username sent");
                SaslCoroutineState::Yielded(SaslYield::Respond(username))
            }
            State::SentUsername => {
                let password = self.creds.password.expose_secret().to_string();
                self.state = State::SentPassword;
                debug!("login password sent");
                SaslCoroutineState::Yielded(SaslYield::Respond(password.into_bytes()))
            }
            State::SentPassword => {
                let err = SaslAuthLoginError::UnexpectedChallenge;
                SaslCoroutineState::Complete(Err(err))
            }
        }
    }
}

enum State {
    Start,
    SentUsername,
    SentPassword,
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use secrecy::SecretString;

    use crate::{coroutine::*, login::*, mechanism::SaslLogin};

    #[test]
    fn exchange_sequences_username_then_password() {
        let mut auth = SaslAuthLogin::new(creds());

        assert_eq!(respond(&mut auth, SaslResume::Start), b"alice");
        assert_eq!(
            respond(&mut auth, SaslResume::Challenge(b"Password:")),
            b"pencil",
        );
    }

    #[test]
    fn peer_finished_completes_ok() {
        let mut auth = SaslAuthLogin::new(creds());

        let _ = respond(&mut auth, SaslResume::Start);
        let _ = respond(&mut auth, SaslResume::Challenge(b"Password:"));

        assert!(matches!(
            auth.resume(SaslResume::PeerFinished),
            SaslCoroutineState::Complete(Ok(())),
        ));
    }

    #[test]
    fn peer_finished_after_the_username_completes_ok() {
        let mut auth = SaslAuthLogin::new(creds());

        let _ = respond(&mut auth, SaslResume::Start);

        assert!(matches!(
            auth.resume(SaslResume::PeerFinished),
            SaslCoroutineState::Complete(Ok(())),
        ));
    }

    #[test]
    fn extra_challenge_completes_err() {
        let mut auth = SaslAuthLogin::new(creds());

        let _ = respond(&mut auth, SaslResume::Start);
        let _ = respond(&mut auth, SaslResume::Challenge(b"Password:"));

        assert!(matches!(
            auth.resume(SaslResume::Challenge(b"Password:")),
            SaslCoroutineState::Complete(Err(SaslAuthLoginError::UnexpectedChallenge)),
        ));
    }

    fn creds() -> SaslLogin {
        SaslLogin {
            username: "alice".to_string(),
            password: SecretString::from("pencil".to_string()),
        }
    }

    fn respond(auth: &mut SaslAuthLogin, arg: SaslResume<'_>) -> Vec<u8> {
        match auth.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::Respond(bytes)) => bytes,
            state => panic!("expected Respond, got {state:?}"),
        }
    }
}
