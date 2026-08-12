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
//!     coroutine::{SaslCoroutine, SaslCoroutineState, SaslArg, SaslYield},
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
//! let state = auth.resume(SaslArg::None);
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(payload)) = state else {
//!     panic!("expected the credentials");
//! };
//!
//! assert_eq!(payload, b"\0alice\0pencil");
//!
//! // The server accepted, so its success reply ends the exchange
//! // without a further challenge.
//! let state = auth.resume(SaslArg::Done);
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

#[cfg(feature = "saslprep")]
use crate::rfc4013::{SaslPrepError, saslprep};

/// Failure causes of the PLAIN exchange.
#[derive(Clone, Debug, Error)]
pub enum SaslPlainError {
    /// A credential carried a code point SASLprep prohibits, so it
    /// cannot be prepared and the server would read something other
    /// than what was typed.
    #[cfg(feature = "saslprep")]
    #[cfg_attr(docsrs, doc(cfg(feature = "saslprep")))]
    #[error("SASL PLAIN failed: {0}")]
    Preparation(#[from] SaslPrepError),
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
        arg: SaslArg<'_>,
    ) -> SaslCoroutineState<SaslYield, Result<(), Self::Error>> {
        if let SaslArg::Done = arg {
            debug!("plain exchange completed");
            return SaslCoroutineState::Complete(Ok(()));
        }

        match self.state {
            State::SendCreds => {
                let authzid = self.creds.authzid.as_deref().unwrap_or_default();
                let authcid = self.creds.authcid.as_str();
                let passwd = self.creds.passwd.expose_secret();

                // NOTE: RFC 4616 section 2 asks the client to prepare
                // all three, since the server compares against what it
                // prepared when the password was set.
                #[cfg(feature = "saslprep")]
                let (authzid, authcid, passwd) = {
                    let prepared = [authzid, authcid, passwd].map(saslprep);

                    let [authzid, authcid, passwd] = match prepared {
                        [Ok(authzid), Ok(authcid), Ok(passwd)] => [authzid, authcid, passwd],
                        prepared => {
                            let err = prepared.into_iter().find_map(Result::err);
                            let err = err.expect("one of the three failed to prepare");
                            return SaslCoroutineState::Complete(Err(err.into()));
                        }
                    };

                    (authzid, authcid, passwd)
                };

                let mut payload = Vec::new();
                payload.extend_from_slice(authzid.as_bytes());
                payload.push(0);
                payload.extend_from_slice(authcid.as_bytes());
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

        let payload = respond(&mut auth, SaslArg::None);

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

        let payload = respond(&mut auth, SaslArg::None);

        assert_eq!(payload, b"\0alice\0pencil");
        assert_eq!(payload.split(|b| *b == 0).count(), 3);
    }

    #[cfg(feature = "saslprep")]
    #[test]
    fn the_credentials_are_prepared_before_they_are_sent() {
        // NOTE: RFC 4616 section 2 asks for this, and it is what makes a
        // password the user typed with a non-breaking space match the
        // one the server prepared when it was set.
        let creds = SaslPlainCreds {
            authzid: None,
            authcid: "ali\u{00ad}ce".to_string(),
            passwd: SecretString::from("pen\u{00a0}cil".to_string()),
        };
        let mut auth = SaslPlain::new(creds);

        assert_eq!(respond(&mut auth, SaslArg::None), b"\0alice\0pen cil");
    }

    #[cfg(feature = "saslprep")]
    #[test]
    fn a_credential_that_cannot_be_prepared_completes_err() {
        let creds = SaslPlainCreds {
            authzid: None,
            authcid: "alice".to_string(),
            passwd: SecretString::from("pen\u{0007}cil".to_string()),
        };
        let mut auth = SaslPlain::new(creds);

        assert!(matches!(
            auth.resume(SaslArg::None),
            SaslCoroutineState::Complete(Err(SaslPlainError::Preparation(_))),
        ));
    }

    #[test]
    fn peer_finished_completes_ok() {
        let mut auth = SaslPlain::new(creds());

        let _ = respond(&mut auth, SaslArg::None);

        assert!(matches!(
            auth.resume(SaslArg::Done),
            SaslCoroutineState::Complete(Ok(())),
        ));
    }

    #[test]
    fn extra_challenge_completes_err() {
        let mut auth = SaslPlain::new(creds());

        let _ = respond(&mut auth, SaslArg::None);

        assert!(matches!(
            auth.resume(SaslArg::Input(b"")),
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

    fn respond(auth: &mut SaslPlain, arg: SaslArg<'_>) -> Vec<u8> {
        match auth.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }
}
