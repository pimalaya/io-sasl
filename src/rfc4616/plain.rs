//! The PLAIN mechanism ([RFC 4616]).
//!
//! One message carrying `authzid NUL authcid NUL passwd`, where the
//! authorization identity is usually empty, so the payload commonly
//! starts with a NUL. The password travels in the clear, which is why
//! the mechanism belongs on a TLS-protected connection only.
//!
//! # Example
//!
//! ```rust
//! use io_sasl::{
//!     coroutine::{SaslCoroutine, SaslCoroutineState, SaslResume, SaslYield},
//!     rfc4616::plain::{SaslPlain, SaslPlainCreds},
//! };
//! use secrecy::SecretString;
//!
//! let mut auth = SaslPlain::new(SaslPlainCreds {
//!     authzid: None,
//!     authcid: "alice".into(),
//!     passwd: SecretString::from("pencil"),
//! });
//!
//! // The protocol crate base64-encodes the payload and writes it as
//! // its authentication command, inline as an initial response or as
//! // the answer to the first continuation request.
//! let state = auth.resume(SaslResume::Start);
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(payload)) = state else {
//!     panic!("expected the credentials");
//! };
//!
//! assert_eq!(payload, b"\0alice\0pencil");
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
//! [RFC 4616]: https://www.rfc-editor.org/rfc/rfc4616

use alloc::{string::String, vec::Vec};

use log::debug;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::{coroutine::*, mechanism::SaslMechanism};

/// Failure causes of the PLAIN exchange.
#[derive(Clone, Debug, Error)]
pub enum SaslPlainError {
    /// The mechanism was resumed with a challenge it does not expect,
    /// or out of order.
    #[error("SASL PLAIN failed: unexpected challenge after the credentials")]
    UnexpectedChallenge,
}

/// PLAIN mechanism credentials ([RFC 4616]).
///
/// Single-message scheme sending `authzid NUL authcid NUL password`;
/// `authzid` is optional.
///
/// [RFC 4616]: https://www.rfc-editor.org/rfc/rfc4616
#[derive(Clone, Debug)]
pub struct SaslPlainCreds {
    /// The optional authorization identity.
    pub authzid: Option<String>,
    /// The authentication identity.
    pub authcid: String,
    /// The password.
    pub passwd: SecretString,
}

/// I/O-free SASL PLAIN mechanism.
pub struct SaslPlain {
    creds: SaslPlainCreds,
    state: State,
}

impl SaslPlain {
    /// Builds the mechanism from its credentials.
    pub fn new(creds: SaslPlainCreds) -> Self {
        Self {
            creds,
            state: State::SendCreds,
        }
    }
}

impl SaslCoroutine for SaslPlain {
    type Error = SaslPlainError;

    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::Plain
    }

    fn resume(
        &mut self,
        arg: SaslResume<'_>,
    ) -> SaslCoroutineState<SaslYield, Result<(), Self::Error>> {
        if let SaslResume::PeerFinished = arg {
            debug!("plain exchange completed");
            return SaslCoroutineState::Complete(Ok(()));
        }

        match self.state {
            State::SendCreds => {
                let authzid = self.creds.authzid.as_deref().unwrap_or_default();
                let passwd = self.creds.passwd.expose_secret();

                let mut payload = Vec::new();
                payload.extend_from_slice(authzid.as_bytes());
                payload.push(0);
                payload.extend_from_slice(self.creds.authcid.as_bytes());
                payload.push(0);
                payload.extend_from_slice(passwd.as_bytes());

                self.state = State::Done;
                debug!("plain credentials sent");
                SaslCoroutineState::Yielded(SaslYield::WantsWrite(payload))
            }
            State::Done => {
                let err = SaslPlainError::UnexpectedChallenge;
                SaslCoroutineState::Complete(Err(err))
            }
        }
    }
}

enum State {
    SendCreds,
    Done,
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use secrecy::SecretString;

    use crate::{coroutine::*, rfc4616::plain::*};

    #[test]
    fn start_responds_with_the_nul_separated_triple() {
        let creds = SaslPlainCreds {
            authzid: Some("admin".to_string()),
            authcid: "alice".to_string(),
            passwd: SecretString::from("pencil".to_string()),
        };
        let mut auth = SaslPlain::new(creds);

        let payload = respond(&mut auth, SaslResume::Start);

        assert_eq!(payload, b"admin\0alice\0pencil");
    }

    #[test]
    fn start_leaves_the_authzid_empty_when_absent() {
        let creds = SaslPlainCreds {
            authzid: None,
            authcid: "alice".to_string(),
            passwd: SecretString::from("pencil".to_string()),
        };
        let mut auth = SaslPlain::new(creds);

        let payload = respond(&mut auth, SaslResume::Start);

        assert_eq!(payload, b"\0alice\0pencil");
        assert_eq!(payload.split(|b| *b == 0).count(), 3);
    }

    #[test]
    fn peer_finished_completes_ok() {
        let mut auth = SaslPlain::new(creds());

        let _ = respond(&mut auth, SaslResume::Start);

        assert!(matches!(
            auth.resume(SaslResume::PeerFinished),
            SaslCoroutineState::Complete(Ok(())),
        ));
    }

    #[test]
    fn extra_challenge_completes_err() {
        let mut auth = SaslPlain::new(creds());

        let _ = respond(&mut auth, SaslResume::Start);

        assert!(matches!(
            auth.resume(SaslResume::Challenge(b"")),
            SaslCoroutineState::Complete(Err(SaslPlainError::UnexpectedChallenge)),
        ));
    }

    fn creds() -> SaslPlainCreds {
        SaslPlainCreds {
            authzid: None,
            authcid: "alice".to_string(),
            passwd: SecretString::from("pencil".to_string()),
        }
    }

    fn respond(auth: &mut SaslPlain, arg: SaslResume<'_>) -> Vec<u8> {
        match auth.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }
}
