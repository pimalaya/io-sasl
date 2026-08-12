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
//!     login::{SaslLogin, SaslLoginCreds},
//! };
//! use secrecy::SecretString;
//!
//! let mut auth = SaslLogin::new(SaslLoginCreds {
//!     username: "alice".into(),
//!     password: SecretString::from("pencil"),
//! });
//!
//! let state = auth.resume(SaslResume::Start);
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(user)) = state else {
//!     panic!("expected the username");
//! };
//!
//! assert_eq!(user, b"alice");
//!
//! // The server prompts for the password. The prompt is human-readable
//! // filler the mechanism ignores, the step alone being what matters.
//! let state = auth.resume(SaslResume::Challenge(b"Password:"));
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(pass)) = state else {
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

use alloc::string::{String, ToString};

use log::debug;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::{coroutine::*, mechanism::SaslMechanism};

/// Failure causes of the LOGIN exchange.
#[derive(Clone, Debug, Error)]
pub enum SaslLoginError {
    /// The mechanism was resumed with a challenge it does not expect,
    /// or out of order.
    #[error("SASL LOGIN failed: unexpected challenge after the password")]
    UnexpectedChallenge,
}

/// LOGIN mechanism credentials ([draft-murchison-sasl-login]).
///
/// Legacy two-prompt cleartext scheme; also used as the credential
/// shape for protocol-level `LOGIN` commands (e.g. IMAP `LOGIN`,
/// [RFC 3501 section 6.2.3]).
///
/// [draft-murchison-sasl-login]: https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login-00
/// [RFC 3501 section 6.2.3]: https://www.rfc-editor.org/rfc/rfc3501#section-6.2.3
#[derive(Clone, Debug)]
pub struct SaslLoginCreds {
    /// The login username.
    pub username: String,
    /// The login password.
    pub password: SecretString,
}

/// I/O-free SASL LOGIN mechanism.
pub struct SaslLogin {
    creds: SaslLoginCreds,
    state: State,
}

impl SaslLogin {
    /// Builds the mechanism from its credentials.
    pub fn new(creds: SaslLoginCreds) -> Self {
        Self {
            creds,
            state: State::SendUsername,
        }
    }
}

impl SaslCoroutine for SaslLogin {
    type Error = SaslLoginError;

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
            State::SendUsername => {
                let username = self.creds.username.as_bytes().to_vec();
                self.state = State::SendPassword;
                debug!("login username sent");
                SaslCoroutineState::Yielded(SaslYield::WantsWrite(username))
            }
            State::SendPassword => {
                let password = self.creds.password.expose_secret().to_string();
                self.state = State::Done;
                debug!("login password sent");
                SaslCoroutineState::Yielded(SaslYield::WantsWrite(password.into_bytes()))
            }
            State::Done => {
                let err = SaslLoginError::UnexpectedChallenge;
                SaslCoroutineState::Complete(Err(err))
            }
        }
    }
}

enum State {
    SendUsername,
    SendPassword,
    Done,
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use secrecy::SecretString;

    use crate::{coroutine::*, login::*};

    #[test]
    fn exchange_sequences_username_then_password() {
        let mut auth = SaslLogin::new(creds());

        assert_eq!(respond(&mut auth, SaslResume::Start), b"alice");
        assert_eq!(
            respond(&mut auth, SaslResume::Challenge(b"Password:")),
            b"pencil",
        );
    }

    #[test]
    fn peer_finished_completes_ok() {
        let mut auth = SaslLogin::new(creds());

        let _ = respond(&mut auth, SaslResume::Start);
        let _ = respond(&mut auth, SaslResume::Challenge(b"Password:"));

        assert!(matches!(
            auth.resume(SaslResume::PeerFinished),
            SaslCoroutineState::Complete(Ok(())),
        ));
    }

    #[test]
    fn peer_finished_after_the_username_completes_ok() {
        let mut auth = SaslLogin::new(creds());

        let _ = respond(&mut auth, SaslResume::Start);

        assert!(matches!(
            auth.resume(SaslResume::PeerFinished),
            SaslCoroutineState::Complete(Ok(())),
        ));
    }

    #[test]
    fn extra_challenge_completes_err() {
        let mut auth = SaslLogin::new(creds());

        let _ = respond(&mut auth, SaslResume::Start);
        let _ = respond(&mut auth, SaslResume::Challenge(b"Password:"));

        assert!(matches!(
            auth.resume(SaslResume::Challenge(b"Password:")),
            SaslCoroutineState::Complete(Err(SaslLoginError::UnexpectedChallenge)),
        ));
    }

    fn creds() -> SaslLoginCreds {
        SaslLoginCreds {
            username: "alice".to_string(),
            password: SecretString::from("pencil".to_string()),
        }
    }

    fn respond(auth: &mut SaslLogin, arg: SaslResume<'_>) -> Vec<u8> {
        match auth.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }
}
