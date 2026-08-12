//! The CRAM-MD5 mechanism ([RFC 2195]).
//!
//! The one mechanism here the server speaks first in. It sends a
//! challenge, conventionally a message-id built from a timestamp and
//! the server name, and the client answers with its username, a space,
//! and the HMAC-MD5 of that challenge keyed by its shared secret, in
//! lowercase hexadecimal. The secret never travels, and a challenge
//! carrying a timestamp cannot be replayed against the same server
//! twice.
//!
//! It is a legacy mechanism kept for servers that offer nothing better,
//! which is why it sits behind the `cram-md5` cargo feature. Two
//! reasons to prefer anything else: the server has to store a
//! plaintext-equivalent secret to compute the same HMAC, and MD5 is
//! long past retirement, even though HMAC-MD5 is not broken by the
//! collision attacks that killed the bare hash.
//!
//! Being server-first is what a protocol crate has to notice: the
//! mechanism answers its first resume with
//! [`SaslYield::WantsRead`], so there is no initial response to inline
//! and the authentication command goes out bare.
//!
//! # Example
//!
//! The exchange published in [RFC 2195 section 2], for the user `tim`
//! with the secret `tanstaaftanstaaf`.
//!
//! ```rust
//! use io_sasl::{
//!     coroutine::{SaslArg, SaslCoroutine, SaslCoroutineState, SaslYield},
//!     rfc2195::cram_md5::{SaslCramMd5, SaslCramMd5Creds},
//! };
//! use secrecy::SecretString;
//!
//! let mut auth = SaslCramMd5::new(SaslCramMd5Creds {
//!     username: "tim".into(),
//!     secret: SecretString::from("tanstaaftanstaaf"),
//! });
//!
//! // Server-first: the mechanism has nothing to say until the
//! // challenge arrives.
//! let state = auth.resume(SaslArg::None);
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsRead) = state else {
//!     panic!("expected the mechanism to wait for the challenge");
//! };
//!
//! let challenge = b"<1896.697170952@postoffice.reston.mci.net>";
//!
//! let state = auth.resume(SaslArg::Input(challenge));
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(response)) = state else {
//!     panic!("expected the keyed digest");
//! };
//!
//! assert_eq!(response, b"tim b913a602c7eda7a495b4e6e7334d3890");
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
//! [RFC 2195]: https://www.rfc-editor.org/rfc/rfc2195
//! [RFC 2195 section 2]: https://www.rfc-editor.org/rfc/rfc2195#section-2

use alloc::{format, string::String};

use hmac::{Hmac, KeyInit, Mac};
use log::debug;
use md5::Md5;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::{coroutine::*, mechanism::SaslMechanism};

/// Failure causes of the CRAM-MD5 exchange.
#[derive(Clone, Debug, Error)]
pub enum SaslCramMd5Error {
    /// The mechanism was resumed with a challenge it does not expect,
    /// or out of order.
    #[error("SASL CRAM-MD5 failed: unexpected challenge after the keyed digest")]
    UnexpectedChallenge,
}

/// CRAM-MD5 mechanism credentials ([RFC 2195]).
///
/// The secret keys an HMAC rather than travelling, but the server holds
/// it in a form it can key the same HMAC with, so it is as sensitive as
/// a password and rather more exposed.
///
/// [RFC 2195]: https://www.rfc-editor.org/rfc/rfc2195
#[derive(Clone, Debug)]
pub struct SaslCramMd5Creds {
    /// The account username.
    pub username: String,
    /// The shared secret keying the digest.
    pub secret: SecretString,
}

/// I/O-free SASL CRAM-MD5 mechanism.
pub struct SaslCramMd5 {
    creds: SaslCramMd5Creds,
    state: State,
}

impl SaslCramMd5 {
    /// Builds the mechanism from its credentials.
    pub fn new(creds: SaslCramMd5Creds) -> Self {
        Self {
            creds,
            state: State::AwaitChallenge,
        }
    }

    /// The response to a challenge: the username, a space, and the
    /// keyed digest in lowercase hexadecimal.
    fn digest(&self, challenge: &[u8]) -> String {
        let secret = self.creds.secret.expose_secret().as_bytes();

        let mut mac = Hmac::<Md5>::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(challenge);

        let digest = mac.finalize().into_bytes();
        let username = &self.creds.username;

        let mut response = format!("{username} ");

        for byte in digest {
            response.push_str(&format!("{byte:02x}"));
        }

        response
    }
}

impl SaslCoroutine for SaslCramMd5 {
    type Error = SaslCramMd5Error;

    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::CramMd5
    }

    fn resume(
        &mut self,
        arg: SaslArg<'_>,
    ) -> SaslCoroutineState<SaslYield, Result<(), Self::Error>> {
        if let SaslArg::Done = arg {
            debug!("cram-md5 exchange completed");
            return SaslCoroutineState::Complete(Ok(()));
        }

        match (&self.state, arg) {
            // NOTE: the only server-first mechanism here, so the first
            // resume asks for a read instead of answering with an
            // initial response, and the protocol crate has nothing to
            // inline in its authentication command.
            (State::AwaitChallenge, SaslArg::None) => {
                self.state = State::SendDigest;
                debug!("cram-md5 awaiting the server challenge");
                SaslCoroutineState::Yielded(SaslYield::WantsRead)
            }
            (State::SendDigest, SaslArg::Input(challenge)) => {
                let response = self.digest(challenge);
                self.state = State::Done;
                debug!("cram-md5 keyed digest sent");
                SaslCoroutineState::Yielded(SaslYield::WantsWrite(response.into_bytes()))
            }
            (_, _) => {
                let err = SaslCramMd5Error::UnexpectedChallenge;
                SaslCoroutineState::Complete(Err(err))
            }
        }
    }
}

enum State {
    AwaitChallenge,
    SendDigest,
    Done,
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use secrecy::SecretString;

    use crate::{coroutine::*, rfc2195::cram_md5::*};

    // NOTE: the published exchange of RFC 2195 section 2, for the user
    // "tim" with the secret "tanstaaftanstaaf".
    const CHALLENGE: &[u8] = b"<1896.697170952@postoffice.reston.mci.net>";
    const RESPONSE: &[u8] = b"tim b913a602c7eda7a495b4e6e7334d3890";

    #[test]
    fn exchange_matches_the_rfc_2195_test_vector() {
        let mut auth = SaslCramMd5::new(creds());

        assert!(matches!(
            auth.resume(SaslArg::None),
            SaslCoroutineState::Yielded(SaslYield::WantsRead),
        ));

        assert_eq!(respond(&mut auth, SaslArg::Input(CHALLENGE)), RESPONSE);

        assert!(matches!(
            auth.resume(SaslArg::Done),
            SaslCoroutineState::Complete(Ok(())),
        ));
    }

    #[test]
    fn peer_finished_completes_ok() {
        let mut auth = SaslCramMd5::new(creds());

        assert!(matches!(
            auth.resume(SaslArg::Done),
            SaslCoroutineState::Complete(Ok(())),
        ));
    }

    #[test]
    fn extra_challenge_completes_err() {
        let mut auth = SaslCramMd5::new(creds());

        let _ = auth.resume(SaslArg::None);
        let _ = respond(&mut auth, SaslArg::Input(CHALLENGE));

        assert!(matches!(
            auth.resume(SaslArg::Input(CHALLENGE)),
            SaslCoroutineState::Complete(Err(SaslCramMd5Error::UnexpectedChallenge)),
        ));
    }

    #[test]
    fn a_challenge_before_the_exchange_started_completes_err() {
        let mut auth = SaslCramMd5::new(creds());

        assert!(matches!(
            auth.resume(SaslArg::Input(CHALLENGE)),
            SaslCoroutineState::Complete(Err(SaslCramMd5Error::UnexpectedChallenge)),
        ));
    }

    fn creds() -> SaslCramMd5Creds {
        SaslCramMd5Creds {
            username: "tim".to_string(),
            secret: SecretString::from("tanstaaftanstaaf".to_string()),
        }
    }

    fn respond(auth: &mut SaslCramMd5, arg: SaslArg<'_>) -> Vec<u8> {
        match auth.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }
}
