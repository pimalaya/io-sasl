//! The OAUTHBEARER mechanism ([RFC 7628]).
//!
//! One message made of a GS2 header naming the authorization identity,
//! then the `host`, `port` and `auth=Bearer <token>` key/value pairs,
//! separated and terminated by `%x01` control characters ([RFC 7628
//! section 3.1]). The host and port describe the server being
//! contacted and let it detect a token replayed against another
//! service.
//!
//! A rejected token is not answered by an error status: the server
//! sends a base64 JSON error as a challenge, and the client must reply
//! with a single `%x01` so the server can end the exchange ([RFC 7628
//! section 3.2.3]). The mechanism answers that challenge, then fails
//! with the JSON the server sent.
//!
//! # Example
//!
//! ```rust
//! use io_sasl::{
//!     coroutine::{SaslCoroutine, SaslCoroutineState, SaslResume, SaslYield},
//!     rfc7628::oauthbearer::{
//!         SaslOauthbearer, SaslOauthbearerCreds, SaslOauthbearerError,
//!     },
//! };
//! use secrecy::SecretString;
//!
//! let mut auth = SaslOauthbearer::new(SaslOauthbearerCreds {
//!     username: "user@example.com".into(),
//!     host: "server.example.com".into(),
//!     port: 143,
//!     token: SecretString::from("expired"),
//! });
//!
//! let state = auth.resume(SaslResume::Start);
//!
//! let SaslCoroutineState::Yielded(SaslYield::Respond(payload)) = state else {
//!     panic!("expected the token");
//! };
//!
//! assert!(payload.starts_with(b"n,a=user@example.com,\x01host="));
//!
//! // The server refused the token and describes why in a JSON
//! // challenge, which the mechanism acknowledges with a single %x01 so
//! // the server can end the exchange.
//! let state = auth.resume(SaslResume::Challenge(br#"{"status":"401"}"#));
//!
//! let SaslCoroutineState::Yielded(SaslYield::Respond(ack)) = state else {
//!     panic!("expected the error acknowledgement");
//! };
//!
//! assert_eq!(ack, [0x01]);
//!
//! // Only now does the exchange end, and the failure carries the JSON.
//! let state = auth.resume(SaslResume::PeerFinished);
//!
//! let SaslCoroutineState::Complete(Err(err)) = state else {
//!     panic!("expected the refused token to fail");
//! };
//!
//! assert!(matches!(err, SaslOauthbearerError::Rejected(_)));
//! ```
//!
//! [RFC 7628]: https://www.rfc-editor.org/rfc/rfc7628
//! [RFC 7628 section 3.1]: https://www.rfc-editor.org/rfc/rfc7628#section-3.1
//! [RFC 7628 section 3.2.3]: https://www.rfc-editor.org/rfc/rfc7628#section-3.2.3

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use log::{debug, trace};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::{coroutine::*, mechanism::SaslMechanism};

/// Failure causes of the OAUTHBEARER exchange.
#[derive(Clone, Debug, Error)]
pub enum SaslOauthbearerError {
    /// The server rejected the token, describing why in a JSON
    /// challenge.
    #[error("SASL OAUTHBEARER failed: server rejected the token: {0}")]
    Rejected(String),
    /// The mechanism was resumed with a challenge it does not expect,
    /// or out of order.
    #[error("SASL OAUTHBEARER failed: unexpected challenge")]
    UnexpectedChallenge,
}

/// OAUTHBEARER mechanism credentials ([RFC 7628]).
///
/// `host` and `port` are sent verbatim in the GS2 header and should
/// match the server being contacted.
///
/// [RFC 7628]: https://www.rfc-editor.org/rfc/rfc7628
#[derive(Clone, Debug)]
pub struct SaslOauthbearerCreds {
    /// The account username.
    pub username: String,
    /// The server host, sent verbatim in the GS2 header.
    pub host: String,
    /// The server port, sent verbatim in the GS2 header.
    pub port: u16,
    /// The OAuth 2.0 access token.
    pub token: SecretString,
}

/// I/O-free SASL OAUTHBEARER mechanism.
pub struct SaslOauthbearer {
    creds: SaslOauthbearerCreds,
    state: State,
}

impl SaslOauthbearer {
    /// Builds the mechanism from its credentials.
    pub fn new(creds: SaslOauthbearerCreds) -> Self {
        Self {
            creds,
            state: State::Start,
        }
    }
}

impl SaslCoroutine for SaslOauthbearer {
    type Error = SaslOauthbearerError;

    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::OAuthBearer
    }

    fn resume(
        &mut self,
        arg: SaslResume<'_>,
    ) -> SaslCoroutineState<SaslYield, Result<(), Self::Error>> {
        match (&self.state, arg) {
            (State::Start, SaslResume::Start) => {
                let host = &self.creds.host;
                let port = self.creds.port;
                let token = self.creds.token.expose_secret();

                let mut payload = Vec::new();
                payload.extend_from_slice(b"n,a=");
                payload.extend_from_slice(self.creds.username.as_bytes());
                payload.push(b',');
                payload.push(0x01);
                payload.extend_from_slice(format!("host={host}").as_bytes());
                payload.push(0x01);
                payload.extend_from_slice(format!("port={port}").as_bytes());
                payload.push(0x01);
                payload.extend_from_slice(b"auth=Bearer ");
                payload.extend_from_slice(token.as_bytes());
                payload.push(0x01);
                payload.push(0x01);

                self.state = State::Responded;
                debug!("oauthbearer token sent");
                SaslCoroutineState::Yielded(SaslYield::Respond(payload))
            }
            (State::Responded, SaslResume::Challenge(json)) => {
                let json = String::from_utf8_lossy(json).to_string();
                debug!("oauthbearer token rejected, acknowledging the error");
                trace!("{json}");
                self.state = State::Rejected(json);
                SaslCoroutineState::Yielded(SaslYield::Respond(vec![0x01]))
            }
            (State::Rejected(json), SaslResume::PeerFinished) => {
                let err = SaslOauthbearerError::Rejected(json.clone());
                SaslCoroutineState::Complete(Err(err))
            }
            (_, SaslResume::PeerFinished) => {
                debug!("oauthbearer exchange completed");
                SaslCoroutineState::Complete(Ok(()))
            }
            (_, _) => {
                let err = SaslOauthbearerError::UnexpectedChallenge;
                SaslCoroutineState::Complete(Err(err))
            }
        }
    }
}

enum State {
    Start,
    Responded,
    Rejected(String),
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use secrecy::SecretString;

    use crate::{coroutine::*, rfc7628::oauthbearer::*};

    #[test]
    fn start_responds_with_the_rfc_7628_example_payload() {
        let mut auth = SaslOauthbearer::new(creds());

        let payload = respond(&mut auth, SaslResume::Start);

        assert_eq!(
            payload,
            b"n,a=user@example.com,\x01host=server.example.com\x01port=143\x01auth=Bearer vF9dft4qmT\x01\x01",
        );
    }

    #[test]
    fn peer_finished_completes_ok() {
        let mut auth = SaslOauthbearer::new(creds());

        let _ = respond(&mut auth, SaslResume::Start);

        assert!(matches!(
            auth.resume(SaslResume::PeerFinished),
            SaslCoroutineState::Complete(Ok(())),
        ));
    }

    #[test]
    fn error_challenge_is_acknowledged_then_fails_with_the_json() {
        let mut auth = SaslOauthbearer::new(creds());
        let json = br#"{"status":"invalid_token","scope":"example"}"#;

        let _ = respond(&mut auth, SaslResume::Start);

        assert_eq!(respond(&mut auth, SaslResume::Challenge(json)), [0x01]);

        let SaslCoroutineState::Complete(Err(err)) = auth.resume(SaslResume::PeerFinished) else {
            panic!("expected Complete(Err)");
        };
        let SaslOauthbearerError::Rejected(reported) = err else {
            panic!("expected SaslOauthbearerError::Rejected, got {err:?}");
        };
        assert_eq!(reported.as_bytes(), json);
    }

    #[test]
    fn extra_challenge_completes_err() {
        let mut auth = SaslOauthbearer::new(creds());
        let json = br#"{"status":"invalid_token"}"#;

        let _ = respond(&mut auth, SaslResume::Start);
        let _ = respond(&mut auth, SaslResume::Challenge(json));

        assert!(matches!(
            auth.resume(SaslResume::Challenge(json)),
            SaslCoroutineState::Complete(Err(SaslOauthbearerError::UnexpectedChallenge)),
        ));
    }

    fn creds() -> SaslOauthbearerCreds {
        SaslOauthbearerCreds {
            username: "user@example.com".to_string(),
            host: "server.example.com".to_string(),
            port: 143,
            token: SecretString::from("vF9dft4qmT".to_string()),
        }
    }

    fn respond(auth: &mut SaslOauthbearer, arg: SaslResume<'_>) -> Vec<u8> {
        match auth.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::Respond(bytes)) => bytes,
            state => panic!("expected Respond, got {state:?}"),
        }
    }
}
