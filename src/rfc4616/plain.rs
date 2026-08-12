//! The PLAIN mechanism ([RFC 4616]).
//!
//! One message carrying `authzid NUL authcid NUL passwd`, where the
//! authorization identity is usually empty, so the payload commonly
//! starts with a NUL. The password travels in the clear, which is why
//! the mechanism belongs on a TLS-protected connection only.
//!
//! [RFC 4616]: https://www.rfc-editor.org/rfc/rfc4616

use alloc::vec::Vec;

use log::debug;
use secrecy::ExposeSecret;
use thiserror::Error;

use crate::{
    coroutine::*,
    mechanism::{SaslMechanism, SaslPlain},
};

/// Failure causes of the PLAIN exchange.
#[derive(Clone, Debug, Error)]
pub enum SaslAuthPlainError {
    /// The mechanism was resumed with a challenge it does not expect,
    /// or out of order.
    #[error("SASL PLAIN failed: unexpected challenge after the credentials")]
    UnexpectedChallenge,
}

/// I/O-free SASL PLAIN mechanism.
pub struct SaslAuthPlain {
    creds: SaslPlain,
    state: State,
}

impl SaslAuthPlain {
    /// Builds the mechanism from its credentials.
    pub fn new(creds: SaslPlain) -> Self {
        Self {
            creds,
            state: State::Start,
        }
    }
}

impl SaslCoroutine for SaslAuthPlain {
    type Error = SaslAuthPlainError;

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
            State::Start => {
                let authzid = self.creds.authzid.as_deref().unwrap_or_default();
                let passwd = self.creds.passwd.expose_secret();

                let mut payload = Vec::new();
                payload.extend_from_slice(authzid.as_bytes());
                payload.push(0);
                payload.extend_from_slice(self.creds.authcid.as_bytes());
                payload.push(0);
                payload.extend_from_slice(passwd.as_bytes());

                self.state = State::Responded;
                debug!("plain credentials sent");
                SaslCoroutineState::Yielded(SaslYield::Respond(payload))
            }
            State::Responded => {
                let err = SaslAuthPlainError::UnexpectedChallenge;
                SaslCoroutineState::Complete(Err(err))
            }
        }
    }
}

enum State {
    Start,
    Responded,
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use secrecy::SecretString;

    use crate::{coroutine::*, mechanism::SaslPlain, rfc4616::plain::*};

    #[test]
    fn start_responds_with_the_nul_separated_triple() {
        let creds = SaslPlain {
            authzid: Some("admin".to_string()),
            authcid: "alice".to_string(),
            passwd: SecretString::from("pencil".to_string()),
        };
        let mut auth = SaslAuthPlain::new(creds);

        let payload = respond(&mut auth, SaslResume::Start);

        assert_eq!(payload, b"admin\0alice\0pencil");
    }

    #[test]
    fn start_leaves_the_authzid_empty_when_absent() {
        let creds = SaslPlain {
            authzid: None,
            authcid: "alice".to_string(),
            passwd: SecretString::from("pencil".to_string()),
        };
        let mut auth = SaslAuthPlain::new(creds);

        let payload = respond(&mut auth, SaslResume::Start);

        assert_eq!(payload, b"\0alice\0pencil");
        assert_eq!(payload.split(|b| *b == 0).count(), 3);
    }

    #[test]
    fn peer_finished_completes_ok() {
        let mut auth = SaslAuthPlain::new(creds());

        let _ = respond(&mut auth, SaslResume::Start);

        assert!(matches!(
            auth.resume(SaslResume::PeerFinished),
            SaslCoroutineState::Complete(Ok(())),
        ));
    }

    #[test]
    fn extra_challenge_completes_err() {
        let mut auth = SaslAuthPlain::new(creds());

        let _ = respond(&mut auth, SaslResume::Start);

        assert!(matches!(
            auth.resume(SaslResume::Challenge(b"")),
            SaslCoroutineState::Complete(Err(SaslAuthPlainError::UnexpectedChallenge)),
        ));
    }

    fn creds() -> SaslPlain {
        SaslPlain {
            authzid: None,
            authcid: "alice".to_string(),
            passwd: SecretString::from("pencil".to_string()),
        }
    }

    fn respond(auth: &mut SaslAuthPlain, arg: SaslResume<'_>) -> Vec<u8> {
        match auth.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::Respond(bytes)) => bytes,
            state => panic!("expected Respond, got {state:?}"),
        }
    }
}
