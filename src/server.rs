//! Server-side [SASL] exchanges.
//!
//! The mirror of the client mechanisms: a resumable state machine
//! parsing what a client sends and emitting the challenges it answers,
//! while the protocol crate owns the socket, the framing and the base64
//! transport encoding. The server never checks a password itself: once
//! the exchange has gathered the credentials it yields
//! [`SaslServerState::Verify`], the caller checks them against its own
//! store and resumes with [`SaslServerArg::Verdict`].
//!
//! Two mechanisms are carried, both cleartext and both meant for a
//! TLS-protected connection only: PLAIN ([RFC 4616]) and LOGIN
//! ([draft-murchison-sasl-login]).
//!
//! Responses arrive already base64-decoded. A client cancelling the
//! exchange (`*` in SMTP and IMAP) is [`SaslServerArg::Cancel`], and an
//! empty initial response (`=`) is `Some(vec![])`.
//!
//! # Example
//!
//! ```rust
//! use io_sasl::server::*;
//! use secrecy::ExposeSecret;
//!
//! let initial = b"\0alice\0pencil".to_vec();
//! let mut server = SaslServer::new(SaslServerMechanism::Plain, Some(initial));
//!
//! let SaslServerState::Verify(creds) = server.resume(SaslServerArg::None) else {
//!     panic!("expected the credentials");
//! };
//!
//! assert_eq!(creds.authcid, "alice");
//! assert_eq!(creds.password.expose_secret(), "pencil");
//!
//! let state = server.resume(SaslServerArg::Verdict(true));
//!
//! let SaslServerState::Success { authzid, authcid } = state else {
//!     panic!("expected the exchange to succeed");
//! };
//!
//! assert_eq!(authzid, None);
//! assert_eq!(authcid, "alice");
//! ```
//!
//! [SASL]: https://www.rfc-editor.org/rfc/rfc4422
//! [RFC 4616]: https://www.rfc-editor.org/rfc/rfc4616
//! [draft-murchison-sasl-login]: https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login-00

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, mem, str};

use log::debug;
use secrecy::{SecretString, zeroize::Zeroizing};
use thiserror::Error;

/// The LOGIN username prompt.
const LOGIN_USERNAME_PROMPT: &[u8] = b"Username:";

/// The LOGIN password prompt.
const LOGIN_PASSWORD_PROMPT: &[u8] = b"Password:";

/// Mechanisms the server side can run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SaslServerMechanism {
    /// PLAIN ([RFC 4616]).
    ///
    /// [RFC 4616]: https://www.rfc-editor.org/rfc/rfc4616
    Plain,
    /// LOGIN ([draft-murchison-sasl-login]).
    ///
    /// [draft-murchison-sasl-login]: https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login-00
    Login,
}

impl SaslServerMechanism {
    /// Parses a mechanism name, case-insensitively.
    pub fn from_name(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("PLAIN") {
            Some(Self::Plain)
        } else if name.eq_ignore_ascii_case("LOGIN") {
            Some(Self::Login)
        } else {
            None
        }
    }

    /// Returns the name the mechanism is registered under.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::Login => "LOGIN",
        }
    }
}

/// Argument a server exchange is resumed with.
#[derive(Clone, Default, Eq, PartialEq)]
pub enum SaslServerArg {
    /// Nothing, for the first resume.
    #[default]
    None,
    /// The client response to the last challenge, base64-decoded.
    Response(Vec<u8>),
    /// The client cancelled the exchange.
    Cancel,
    /// The caller verdict on the credentials of
    /// [`SaslServerState::Verify`].
    Verdict(bool),
}

impl fmt::Debug for SaslServerArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Response(bytes) => write!(f, "Response([{} bytes])", bytes.len()),
            Self::Cancel => f.write_str("Cancel"),
            Self::Verdict(verdict) => write!(f, "Verdict({verdict})"),
        }
    }
}

/// State a server exchange yields.
#[derive(Debug)]
pub enum SaslServerState {
    /// Raw challenge bytes to send, base64-encoded by the protocol.
    Challenge(Vec<u8>),
    /// Credentials to check, answered with [`SaslServerArg::Verdict`].
    Verify(SaslServerCredentials),
    /// The exchange succeeded.
    Success {
        /// The authorization identity, if the client asked for one.
        authzid: Option<String>,
        /// The authentication identity.
        authcid: String,
    },
    /// The exchange failed.
    Failure(SaslServerError),
}

/// Credentials a client presented.
#[derive(Clone, Debug)]
pub struct SaslServerCredentials {
    /// The authorization identity, if the client asked for one.
    pub authzid: Option<String>,
    /// The authentication identity.
    pub authcid: String,
    /// The password.
    pub password: SecretString,
}

/// Failure causes of a server exchange.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SaslServerError {
    /// The client response does not follow the mechanism grammar.
    #[error("SASL server failed: malformed client response")]
    Malformed,
    /// The client cancelled the exchange.
    #[error("SASL server failed: exchange cancelled by the client")]
    Cancelled,
    /// The caller rejected the credentials.
    #[error("SASL server failed: credentials rejected")]
    Rejected,
    /// The exchange was resumed with an argument it does not expect.
    #[error("SASL server failed: unexpected argument")]
    UnexpectedArg,
}

/// I/O-free server side of a SASL exchange.
#[derive(Debug)]
pub struct SaslServer {
    mechanism: SaslServerMechanism,
    state: State,
}

impl SaslServer {
    /// Builds the exchange, with the initial response if the client
    /// sent one inline.
    pub fn new(mechanism: SaslServerMechanism, initial_response: Option<Vec<u8>>) -> Self {
        Self {
            mechanism,
            state: State::Start(initial_response.map(Zeroizing::new)),
        }
    }

    /// Returns the mechanism being run.
    pub fn mechanism(&self) -> SaslServerMechanism {
        self.mechanism
    }

    /// Resumes the exchange.
    pub fn resume(&mut self, arg: SaslServerArg) -> SaslServerState {
        let state = mem::replace(&mut self.state, State::Done);

        if let SaslServerArg::Cancel = arg {
            if let State::Done = state {
                return SaslServerState::Failure(SaslServerError::UnexpectedArg);
            }

            debug!("sasl server exchange cancelled");
            return SaslServerState::Failure(SaslServerError::Cancelled);
        }

        match (self.mechanism, state, arg) {
            (SaslServerMechanism::Plain, State::Start(None), SaslServerArg::None) => {
                self.state = State::ReceivePlain;
                SaslServerState::Challenge(Vec::new())
            }
            (SaslServerMechanism::Plain, State::Start(Some(bytes)), SaslServerArg::None) => {
                self.verify(parse_plain(&bytes))
            }
            (SaslServerMechanism::Plain, State::ReceivePlain, SaslServerArg::Response(bytes)) => {
                self.verify(parse_plain(&Zeroizing::new(bytes)))
            }
            (SaslServerMechanism::Login, State::Start(None), SaslServerArg::None) => {
                self.state = State::ReceiveUsername;
                SaslServerState::Challenge(LOGIN_USERNAME_PROMPT.to_vec())
            }
            (SaslServerMechanism::Login, State::Start(Some(bytes)), SaslServerArg::None) => {
                self.receive_username(&bytes)
            }
            (_, State::ReceiveUsername, SaslServerArg::Response(bytes)) => {
                self.receive_username(&bytes)
            }
            (_, State::ReceivePassword(authcid), SaslServerArg::Response(bytes)) => {
                let bytes = Zeroizing::new(bytes);

                match str::from_utf8(&bytes) {
                    Ok(password) if !password.is_empty() => {
                        self.verify(Ok(SaslServerCredentials {
                            authzid: None,
                            authcid,
                            password: SecretString::from(password),
                        }))
                    }
                    _ => SaslServerState::Failure(SaslServerError::Malformed),
                }
            }
            (_, State::ReceiveVerdict { authzid, authcid }, SaslServerArg::Verdict(true)) => {
                debug!("sasl server credentials accepted");
                SaslServerState::Success { authzid, authcid }
            }
            (_, State::ReceiveVerdict { .. }, SaslServerArg::Verdict(false)) => {
                debug!("sasl server credentials rejected");
                SaslServerState::Failure(SaslServerError::Rejected)
            }
            _ => SaslServerState::Failure(SaslServerError::UnexpectedArg),
        }
    }

    fn receive_username(&mut self, bytes: &[u8]) -> SaslServerState {
        match str::from_utf8(bytes) {
            Ok(username) if !username.is_empty() => {
                self.state = State::ReceivePassword(username.to_string());
                SaslServerState::Challenge(LOGIN_PASSWORD_PROMPT.to_vec())
            }
            _ => SaslServerState::Failure(SaslServerError::Malformed),
        }
    }

    fn verify(&mut self, creds: Result<SaslServerCredentials, SaslServerError>) -> SaslServerState {
        match creds {
            Ok(creds) => {
                debug!("sasl server credentials received");
                self.state = State::ReceiveVerdict {
                    authzid: creds.authzid.clone(),
                    authcid: creds.authcid.clone(),
                };
                SaslServerState::Verify(creds)
            }
            Err(err) => SaslServerState::Failure(err),
        }
    }
}

/// Parses the PLAIN message `authzid NUL authcid NUL passwd`.
fn parse_plain(bytes: &[u8]) -> Result<SaslServerCredentials, SaslServerError> {
    let message = str::from_utf8(bytes).map_err(|_| SaslServerError::Malformed)?;
    let mut fields = message.split('\0');

    let (Some(authzid), Some(authcid), Some(password), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(SaslServerError::Malformed);
    };

    if authcid.is_empty() || password.is_empty() {
        return Err(SaslServerError::Malformed);
    }

    Ok(SaslServerCredentials {
        authzid: (!authzid.is_empty()).then(|| authzid.to_string()),
        authcid: authcid.to_string(),
        password: SecretString::from(password),
    })
}

/// What the next resume is about to do.
enum State {
    Start(Option<Zeroizing<Vec<u8>>>),
    ReceivePlain,
    ReceiveUsername,
    ReceivePassword(String),
    ReceiveVerdict {
        authzid: Option<String>,
        authcid: String,
    },
    Done,
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(_) => f.write_str("Start"),
            Self::ReceivePlain => f.write_str("ReceivePlain"),
            Self::ReceiveUsername => f.write_str("ReceiveUsername"),
            Self::ReceivePassword(_) => f.write_str("ReceivePassword"),
            Self::ReceiveVerdict { .. } => f.write_str("ReceiveVerdict"),
            Self::Done => f.write_str("Done"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use secrecy::ExposeSecret;

    use crate::server::*;

    #[test]
    fn mechanism_names_parse_case_insensitively() {
        for (name, mechanism) in [
            ("PLAIN", SaslServerMechanism::Plain),
            ("plain", SaslServerMechanism::Plain),
            ("LoGiN", SaslServerMechanism::Login),
        ] {
            assert_eq!(SaslServerMechanism::from_name(name), Some(mechanism));
            assert!(mechanism.name().eq_ignore_ascii_case(name));
        }

        assert_eq!(SaslServerMechanism::from_name("CRAM-MD5"), None);
    }

    #[test]
    fn plain_with_initial_response_verifies_then_succeeds() {
        let initial = b"admin\0alice\0pencil".to_vec();
        let mut server = SaslServer::new(SaslServerMechanism::Plain, Some(initial));

        let creds = verify(server.resume(SaslServerArg::None));
        assert_eq!(creds.authzid.as_deref(), Some("admin"));
        assert_eq!(creds.authcid, "alice");
        assert_eq!(creds.password.expose_secret(), "pencil");

        let SaslServerState::Success { authzid, authcid } =
            server.resume(SaslServerArg::Verdict(true))
        else {
            panic!("expected success");
        };

        assert_eq!(authzid.as_deref(), Some("admin"));
        assert_eq!(authcid, "alice");
    }

    #[test]
    fn plain_without_initial_response_challenges_empty() {
        let mut server = SaslServer::new(SaslServerMechanism::Plain, None);

        assert_eq!(challenge(server.resume(SaslServerArg::None)), b"");

        let arg = SaslServerArg::Response(b"\0alice\0pencil".to_vec());
        let creds = verify(server.resume(arg));
        assert_eq!(creds.authzid, None);
        assert_eq!(creds.authcid, "alice");
    }

    #[test]
    fn plain_rejected_verdict_fails() {
        let initial = b"\0alice\0wrong".to_vec();
        let mut server = SaslServer::new(SaslServerMechanism::Plain, Some(initial));

        verify(server.resume(SaslServerArg::None));

        assert_failure(
            server.resume(SaslServerArg::Verdict(false)),
            SaslServerError::Rejected,
        );
        assert_failure(
            server.resume(SaslServerArg::Verdict(true)),
            SaslServerError::UnexpectedArg,
        );
    }

    #[test]
    fn plain_malformed_messages_fail() {
        let messages: [&[u8]; 7] = [
            b"alice",
            b"\0alice",
            b"\0alice\0pen\0cil",
            b"\0\0pencil",
            b"\0alice\0",
            b"\0al\xffice\0pencil",
            b"",
        ];

        for message in messages {
            let mut server = SaslServer::new(SaslServerMechanism::Plain, Some(message.to_vec()));
            let state = server.resume(SaslServerArg::None);
            assert_failure(state, SaslServerError::Malformed);
        }
    }

    #[test]
    fn plain_empty_initial_response_is_malformed() {
        let mut server = SaslServer::new(SaslServerMechanism::Plain, Some(vec![]));
        let state = server.resume(SaslServerArg::None);
        assert_failure(state, SaslServerError::Malformed);
    }

    #[test]
    fn cancel_fails_with_cancelled() {
        let mut server = SaslServer::new(SaslServerMechanism::Plain, None);
        challenge(server.resume(SaslServerArg::None));
        assert_failure(
            server.resume(SaslServerArg::Cancel),
            SaslServerError::Cancelled,
        );

        let mut server = SaslServer::new(SaslServerMechanism::Login, None);
        challenge(server.resume(SaslServerArg::None));
        challenge(server.resume(SaslServerArg::Response(b"alice".to_vec())));
        assert_failure(
            server.resume(SaslServerArg::Cancel),
            SaslServerError::Cancelled,
        );
        assert_failure(
            server.resume(SaslServerArg::Cancel),
            SaslServerError::UnexpectedArg,
        );
    }

    #[test]
    fn login_without_initial_response_prompts_twice() {
        let mut server = SaslServer::new(SaslServerMechanism::Login, None);

        assert_eq!(challenge(server.resume(SaslServerArg::None)), b"Username:");

        let arg = SaslServerArg::Response(b"alice".to_vec());
        assert_eq!(challenge(server.resume(arg)), b"Password:");

        let arg = SaslServerArg::Response(b"pencil".to_vec());
        let creds = verify(server.resume(arg));
        assert_eq!(creds.authzid, None);
        assert_eq!(creds.authcid, "alice");
        assert_eq!(creds.password.expose_secret(), "pencil");

        assert!(matches!(
            server.resume(SaslServerArg::Verdict(true)),
            SaslServerState::Success { authcid, .. } if authcid == "alice",
        ));
    }

    #[test]
    fn login_with_initial_response_prompts_for_the_password() {
        let initial = b"alice".to_vec();
        let mut server = SaslServer::new(SaslServerMechanism::Login, Some(initial));

        assert_eq!(challenge(server.resume(SaslServerArg::None)), b"Password:");

        let arg = SaslServerArg::Response(b"pencil".to_vec());
        let creds = verify(server.resume(arg));
        assert_eq!(creds.authcid, "alice");
    }

    #[test]
    fn login_malformed_responses_fail() {
        let mut server = SaslServer::new(SaslServerMechanism::Login, Some(b"\xff".to_vec()));
        let state = server.resume(SaslServerArg::None);
        assert_failure(state, SaslServerError::Malformed);

        let mut server = SaslServer::new(SaslServerMechanism::Login, Some(vec![]));
        let state = server.resume(SaslServerArg::None);
        assert_failure(state, SaslServerError::Malformed);

        let mut server = SaslServer::new(SaslServerMechanism::Login, Some(b"alice".to_vec()));
        challenge(server.resume(SaslServerArg::None));
        let state = server.resume(SaslServerArg::Response(vec![]));
        assert_failure(state, SaslServerError::Malformed);
    }

    #[test]
    fn out_of_order_arguments_fail() {
        let args = [
            SaslServerArg::Response(b"\0alice\0pencil".to_vec()),
            SaslServerArg::Verdict(true),
        ];

        for arg in args {
            let mut server = SaslServer::new(SaslServerMechanism::Plain, None);
            assert_failure(server.resume(arg), SaslServerError::UnexpectedArg);
        }

        let initial = b"\0alice\0pencil".to_vec();
        let mut server = SaslServer::new(SaslServerMechanism::Plain, Some(initial));
        verify(server.resume(SaslServerArg::None));
        let arg = SaslServerArg::Response(Vec::new());
        assert_failure(server.resume(arg), SaslServerError::UnexpectedArg);
    }

    #[test]
    fn debug_hides_the_secrets() {
        let arg = SaslServerArg::Response(b"\0alice\0pencil".to_vec());
        assert_eq!(alloc::format!("{arg:?}"), "Response([13 bytes])");

        let initial = b"\0alice\0pencil".to_vec();
        let mut server = SaslServer::new(SaslServerMechanism::Plain, Some(initial));
        let state = server.resume(SaslServerArg::None);
        assert!(!alloc::format!("{state:?}{server:?}").contains("pencil"));
        assert_eq!(server.mechanism(), SaslServerMechanism::Plain);
    }

    fn challenge(state: SaslServerState) -> Vec<u8> {
        match state {
            SaslServerState::Challenge(bytes) => bytes,
            state => panic!("expected Challenge, got {state:?}"),
        }
    }

    fn verify(state: SaslServerState) -> SaslServerCredentials {
        match state {
            SaslServerState::Verify(creds) => creds,
            state => panic!("expected Verify, got {state:?}"),
        }
    }

    fn assert_failure(state: SaslServerState, expected: SaslServerError) {
        match state {
            SaslServerState::Failure(err) => assert_eq!(err, expected),
            state => panic!("expected Failure({expected:?}), got {state:?}"),
        }
    }
}
