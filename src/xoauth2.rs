//! The XOAUTH2 mechanism ([Google XOAUTH2], pre-standard).
//!
//! One message carrying `user=<username>` and `auth=Bearer <token>`,
//! separated and terminated by `%x01` control characters. It predates
//! and was superseded by OAUTHBEARER ([RFC 7628]), but Google and
//! Microsoft still speak it, so it stays.
//!
//! A rejected token is not answered by an error status: the server
//! sends a base64 JSON error as a challenge and waits for one more
//! client response before ending the exchange. Google documents that
//! response as empty, unlike OAUTHBEARER's single `%x01`, so the
//! mechanism answers the JSON challenge with an empty payload and then
//! fails with the JSON the server sent.
//!
//! # Example
//!
//! ```rust
//! use io_sasl::{
//!     coroutine::{SaslCoroutine, SaslCoroutineState, SaslArg, SaslYield},
//!     xoauth2::{SaslXoauth2, SaslXoauth2Creds},
//! };
//! use secrecy::SecretString;
//!
//! let mut auth = SaslXoauth2::new(SaslXoauth2Creds {
//!     username: "someuser@example.com".into(),
//!     token: SecretString::from("vF9dft4qmT"),
//! });
//!
//! let state = auth.resume(SaslArg::None);
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(payload)) = state else {
//!     panic!("expected the token");
//! };
//!
//! assert_eq!(
//!     payload,
//!     b"user=someuser@example.com\x01auth=Bearer vF9dft4qmT\x01\x01",
//! );
//!
//! // The server accepted, so its success reply ends the exchange. Had
//! // it refused, it would have sent a JSON error challenge first, which
//! // the mechanism answers with an empty payload before failing.
//! let state = auth.resume(SaslArg::Done);
//!
//! let SaslCoroutineState::Complete(result) = state else {
//!     panic!("expected the exchange to end");
//! };
//!
//! result.unwrap();
//! ```
//!
//! [Google XOAUTH2]: https://developers.google.com/gmail/imap/xoauth2-protocol
//! [RFC 7628]: https://www.rfc-editor.org/rfc/rfc7628

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use log::{debug, trace};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::{coroutine::*, mechanism::SaslMechanism};

/// Failure causes of the XOAUTH2 exchange.
#[derive(Clone, Debug, Error)]
pub enum SaslXoauth2Error {
    /// The server rejected the token, describing why in a JSON
    /// challenge.
    #[error("SASL XOAUTH2 failed: server rejected the token: {0}")]
    Rejected(String),
    /// The mechanism was resumed with a challenge it does not expect,
    /// or out of order.
    #[error("SASL XOAUTH2 failed: unexpected challenge")]
    UnexpectedChallenge,
}

/// XOAUTH2 mechanism credentials ([Google XOAUTH2]).
///
/// Pre-standard OAuth 2.0 SASL scheme; same shape as OAUTHBEARER minus
/// the GS2 host/port fields. Not IETF-standardised.
///
/// [Google XOAUTH2]: https://developers.google.com/gmail/imap/xoauth2-protocol
#[derive(Clone, Debug)]
pub struct SaslXoauth2Creds {
    /// The account username.
    pub username: String,
    /// The OAuth 2.0 access token.
    pub token: SecretString,
}

/// I/O-free SASL XOAUTH2 mechanism.
pub struct SaslXoauth2 {
    creds: SaslXoauth2Creds,
    state: State,
}

impl SaslXoauth2 {
    /// Builds the mechanism from its credentials.
    pub fn new(creds: SaslXoauth2Creds) -> Self {
        Self {
            creds,
            state: State::SendToken,
        }
    }
}

impl SaslCoroutine for SaslXoauth2 {
    type Error = SaslXoauth2Error;

    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::XOAuth2
    }

    fn resume(
        &mut self,
        arg: SaslArg<'_>,
    ) -> SaslCoroutineState<SaslYield, Result<(), Self::Error>> {
        match (&self.state, arg) {
            (State::SendToken, SaslArg::None) => {
                let token = self.creds.token.expose_secret();

                let mut payload = Vec::new();
                payload.extend_from_slice(b"user=");
                payload.extend_from_slice(self.creds.username.as_bytes());
                payload.push(0x01);
                payload.extend_from_slice(b"auth=Bearer ");
                payload.extend_from_slice(token.as_bytes());
                payload.push(0x01);
                payload.push(0x01);

                self.state = State::Done;
                debug!("xoauth2 token sent");
                SaslCoroutineState::Yielded(SaslYield::WantsWrite(payload))
            }
            (State::Done, SaslArg::Input(json)) => {
                let json = String::from_utf8_lossy(json).to_string();
                debug!("xoauth2 token rejected, acknowledging the error");
                trace!("{json}");
                self.state = State::Fail(json);
                SaslCoroutineState::Yielded(SaslYield::WantsWrite(Vec::new()))
            }
            (State::Fail(json), SaslArg::Done) => {
                let err = SaslXoauth2Error::Rejected(json.clone());
                SaslCoroutineState::Complete(Err(err))
            }
            (_, SaslArg::Done) => {
                debug!("xoauth2 exchange completed");
                SaslCoroutineState::Complete(Ok(()))
            }
            (_, _) => {
                let err = SaslXoauth2Error::UnexpectedChallenge;
                SaslCoroutineState::Complete(Err(err))
            }
        }
    }
}

enum State {
    SendToken,
    Done,
    Fail(String),
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use secrecy::SecretString;

    use crate::{coroutine::*, xoauth2::*};

    #[test]
    fn start_responds_with_the_documented_payload() {
        let mut auth = SaslXoauth2::new(creds());

        let payload = respond(&mut auth, SaslArg::None);

        assert_eq!(
            payload,
            b"user=someuser@example.com\x01auth=Bearer vF9dft4qmT\x01\x01",
        );
    }

    #[test]
    fn peer_finished_completes_ok() {
        let mut auth = SaslXoauth2::new(creds());

        let _ = respond(&mut auth, SaslArg::None);

        assert!(matches!(
            auth.resume(SaslArg::Done),
            SaslCoroutineState::Complete(Ok(())),
        ));
    }

    #[test]
    fn error_challenge_is_acknowledged_then_fails_with_the_json() {
        let mut auth = SaslXoauth2::new(creds());
        let json = br#"{"status":"401","schemes":"bearer mac"}"#;

        let _ = respond(&mut auth, SaslArg::None);

        assert!(respond(&mut auth, SaslArg::Input(json)).is_empty());

        let SaslCoroutineState::Complete(Err(err)) = auth.resume(SaslArg::Done) else {
            panic!("expected Complete(Err)");
        };
        let SaslXoauth2Error::Rejected(reported) = err else {
            panic!("expected SaslXoauth2Error::Rejected, got {err:?}");
        };
        assert_eq!(reported.as_bytes(), json);
    }

    #[test]
    fn extra_challenge_completes_err() {
        let mut auth = SaslXoauth2::new(creds());
        let json = br#"{"status":"401"}"#;

        let _ = respond(&mut auth, SaslArg::None);
        let _ = respond(&mut auth, SaslArg::Input(json));

        assert!(matches!(
            auth.resume(SaslArg::Input(json)),
            SaslCoroutineState::Complete(Err(SaslXoauth2Error::UnexpectedChallenge)),
        ));
    }

    fn creds() -> SaslXoauth2Creds {
        SaslXoauth2Creds {
            username: "someuser@example.com".to_string(),
            token: SecretString::from("vF9dft4qmT".to_string()),
        }
    }

    fn respond(auth: &mut SaslXoauth2, arg: SaslArg<'_>) -> Vec<u8> {
        match auth.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }
}
