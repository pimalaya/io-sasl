//! The SCRAM-SHA-256 mechanism ([RFC 7677]), the SHA-256 profile of
//! the SCRAM family ([RFC 5802]).
//!
//! Four steps, the last of which is the point of the mechanism. The
//! client sends a client-first-message naming the user and a nonce,
//! the server answers with its own nonce, a salt and an iteration
//! count, the client proves it knows the password without sending it,
//! and the server proves the same in return. That last proof is mutual
//! authentication: an exchange ending before the server signature was
//! verified is a failure, not a success, which is why
//! [`SaslResume::PeerFinished`] arriving early completes
//! [`SaslAuthScramSha256Error::ServerSignatureNotVerified`].
//!
//! Only the intra-message base64 of RFC 5802 lives here, the `s=` salt
//! and the `p=` proof. Transport-level base64 stays with the protocol
//! crate, which decodes a challenge before handing it over.
//!
//! Channel binding is not implemented: the client advertises `n` (no
//! channel binding) in its GS2 header, so the client-final-message
//! always carries `c=biws`, the base64 of that header.
//!
//! The last response is an empty acknowledgement of the server-final
//! message. A protocol whose framing already ended the exchange, such
//! as SMTP carrying the server-final message inside its final reply,
//! feeds that message as a challenge and then drops the empty response
//! rather than writing it.
//!
//! # Example
//!
//! The exchange published in [RFC 7677 section 3], for the user `user`
//! with the password `pencil`. A real client draws its nonce from a
//! cryptographic source instead of hard-coding one.
//!
//! ```rust
//! use io_sasl::{
//!     coroutine::{SaslCoroutine, SaslCoroutineState, SaslResume, SaslYield},
//!     rfc7677::scram_sha_256::{SaslAuthScramSha256, SaslScramSha256},
//! };
//! use secrecy::SecretString;
//!
//! let mut auth = SaslAuthScramSha256::new(SaslScramSha256 {
//!     username: "user".into(),
//!     password: SecretString::from("pencil"),
//!     nonce: b"rOprNGfwEbeRWgbNEkqO".to_vec(),
//! });
//!
//! let state = auth.resume(SaslResume::Start);
//!
//! let SaslCoroutineState::Yielded(SaslYield::Respond(first)) = state else {
//!     panic!("expected the client-first-message");
//! };
//!
//! assert_eq!(first, b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
//!
//! // The server extends the nonce and names its salt and iteration
//! // count; the mechanism answers with the proof it knows the password.
//! let server_first = SaslResume::Challenge(
//!     b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
//! );
//!
//! let state = auth.resume(server_first);
//!
//! let SaslCoroutineState::Yielded(SaslYield::Respond(proof)) = state else {
//!     panic!("expected the client-final-message");
//! };
//!
//! assert!(proof.starts_with(b"c=biws,r=rOprNGfwEbeRWgbNEkqO"));
//!
//! // The server proves itself in return. Feeding this message back is
//! // what mutual authentication rests on: ending the exchange here
//! // instead would complete with ServerSignatureNotVerified.
//! let signature = b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
//!
//! let state = auth.resume(SaslResume::Challenge(signature));
//!
//! let SaslCoroutineState::Yielded(SaslYield::Respond(ack)) = state else {
//!     panic!("expected the server-final-message to verify");
//! };
//!
//! assert!(ack.is_empty());
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
//! [RFC 7677 section 3]: https://www.rfc-editor.org/rfc/rfc7677#section-3
//! [RFC 7677]: https://www.rfc-editor.org/rfc/rfc7677
//! [RFC 5802]: https://www.rfc-editor.org/rfc/rfc5802

use core::str::from_utf8;

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use base64::{Engine, engine::general_purpose::STANDARD as base64};
use hmac::{Hmac, KeyInit, Mac};
use log::{debug, trace};
use pbkdf2::pbkdf2_hmac;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{coroutine::*, mechanism::SaslMechanism};

type HmacSha256 = Hmac<Sha256>;

/// Failure causes of the SCRAM-SHA-256 exchange.
#[derive(Clone, Debug, Error)]
pub enum SaslAuthScramSha256Error {
    /// A server message was not valid UTF-8.
    #[error("SASL SCRAM-SHA-256 failed: invalid server message encoding")]
    InvalidEncoding,
    /// The server-first-message carried no `r=` nonce.
    #[error("SASL SCRAM-SHA-256 failed: server-first-message missing nonce")]
    MissingNonce,
    /// The server-first-message carried no `s=` salt.
    #[error("SASL SCRAM-SHA-256 failed: server-first-message missing salt")]
    MissingSalt,
    /// The server-first-message carried no `i=` iteration count.
    #[error("SASL SCRAM-SHA-256 failed: server-first-message missing iteration count")]
    MissingIterations,
    /// The `i=` iteration count did not parse as an integer.
    #[error("SASL SCRAM-SHA-256 failed: invalid iteration count")]
    InvalidIterationCount,
    /// A base64 value in a server message failed to decode.
    #[error("SASL SCRAM-SHA-256 failed: invalid base64 in server message")]
    InvalidBase64,
    /// The server nonce did not extend the client nonce, so the server
    /// is replaying another exchange.
    #[error("SASL SCRAM-SHA-256 failed: server nonce does not start with client nonce")]
    NonceMismatch,
    /// The server-final-message carried neither `v=` nor `e=`.
    #[error("SASL SCRAM-SHA-256 failed: invalid server-final-message")]
    InvalidServerFinal,
    /// The server-final-message reported an `e=` error.
    #[error("SASL SCRAM-SHA-256 failed: server error: {0}")]
    ServerError(String),
    /// The `v=` signature did not match the locally computed one, so
    /// the server does not know the password.
    #[error("SASL SCRAM-SHA-256 failed: server signature mismatch")]
    ServerSignatureMismatch,
    /// The peer ended the exchange before the server proved itself.
    ///
    /// The variant exists so that mutual authentication cannot be
    /// skipped by omission: a protocol that accepts its own success
    /// reply (an IMAP tagged OK, an SMTP 235) without ever feeding the
    /// server-final-message back gets a failure rather than a silent
    /// half-verified success.
    #[error("SASL SCRAM-SHA-256 failed: exchange ended before the server signature was verified")]
    ServerSignatureNotVerified,
    /// The mechanism was resumed with a challenge it does not expect,
    /// or out of order.
    #[error("SASL SCRAM-SHA-256 failed: unexpected challenge")]
    UnexpectedChallenge,
}

/// SCRAM-SHA-256 mechanism credentials ([RFC 7677], [RFC 5802]).
///
/// Salted password-based scheme; the password never leaves the client.
///
/// [RFC 7677]: https://www.rfc-editor.org/rfc/rfc7677
/// [RFC 5802]: https://www.rfc-editor.org/rfc/rfc5802
#[derive(Clone, Debug)]
pub struct SaslScramSha256 {
    /// The account username.
    pub username: String,
    /// The password, never sent on the wire.
    pub password: SecretString,
    /// The client nonce, printable ASCII without commas.
    ///
    /// [RFC 5802 section 5.1] recommends at least 18 bytes of
    /// cryptographic randomness. It sits with the credentials rather
    /// than being generated by the mechanism because an I/O-free
    /// coroutine cannot generate randomness: the entropy decision
    /// belongs to whoever builds the credentials, and carrying it here
    /// means a protocol crate holding a [`Sasl`] always has everything
    /// the exchange needs.
    ///
    /// [`Sasl`]: crate::mechanism::Sasl
    /// [RFC 5802 section 5.1]: https://www.rfc-editor.org/rfc/rfc5802#section-5.1
    pub nonce: Vec<u8>,
}

/// I/O-free SASL SCRAM-SHA-256 mechanism.
pub struct SaslAuthScramSha256 {
    password: SecretString,
    client_nonce: String,
    client_first_bare: String,
    expected_server_signature: Vec<u8>,
    state: State,
}

impl SaslAuthScramSha256 {
    /// Builds the mechanism from its credentials, whose
    /// [`nonce`](SaslScramSha256::nonce) the caller supplied.
    ///
    /// An I/O-free mechanism cannot generate randomness itself, so the
    /// caller owns that decision and the exchange stays
    /// deterministically testable.
    pub fn new(creds: SaslScramSha256) -> Self {
        let client_nonce = String::from_utf8_lossy(&creds.nonce).to_string();

        let mut escaped = String::with_capacity(creds.username.len());

        for c in creds.username.chars() {
            match c {
                '=' => escaped.push_str("=3D"),
                ',' => escaped.push_str("=2C"),
                c => escaped.push(c),
            }
        }

        Self {
            password: creds.password,
            client_first_bare: format!("n={escaped},r={client_nonce}"),
            client_nonce,
            expected_server_signature: Vec::new(),
            state: State::Start,
        }
    }

    /// Parses the server-first-message and computes the
    /// client-final-message, remembering the server signature to
    /// expect in return.
    fn client_final(&mut self, server_first: &[u8]) -> Result<Vec<u8>, SaslAuthScramSha256Error> {
        let server_first =
            from_utf8(server_first).map_err(|_| SaslAuthScramSha256Error::InvalidEncoding)?;

        let mut nonce = None;
        let mut salt = None;
        let mut iterations = None;

        for field in server_first.split(',') {
            if let Some(r) = field.strip_prefix("r=") {
                nonce = Some(r);
            } else if let Some(s) = field.strip_prefix("s=") {
                let s = base64
                    .decode(s)
                    .map_err(|_| SaslAuthScramSha256Error::InvalidBase64)?;
                salt = Some(s);
            } else if let Some(i) = field.strip_prefix("i=") {
                let i = i
                    .parse::<u32>()
                    .map_err(|_| SaslAuthScramSha256Error::InvalidIterationCount)?;
                iterations = Some(i);
            }
        }

        let nonce = nonce.ok_or(SaslAuthScramSha256Error::MissingNonce)?;
        let salt = salt.ok_or(SaslAuthScramSha256Error::MissingSalt)?;
        let iterations = iterations.ok_or(SaslAuthScramSha256Error::MissingIterations)?;

        if !nonce.starts_with(&self.client_nonce) {
            return Err(SaslAuthScramSha256Error::NonceMismatch);
        }

        trace!("iterations: {iterations}");

        // NOTE: c=biws is the base64 of the GS2 header "n,,", which
        // advertises a client that does not support channel binding.
        let client_final_without_proof = format!("c=biws,r={nonce}");

        let client_first_bare = &self.client_first_bare;
        let auth_message =
            format!("{client_first_bare},{server_first},{client_final_without_proof}");

        let mut salted_password = [0u8; 32];
        let password = self.password.expose_secret().as_bytes();
        pbkdf2_hmac::<Sha256>(password, &salt, iterations, &mut salted_password);

        let client_key = hmac_sha256(&salted_password, b"Client Key");
        let stored_key: [u8; 32] = Sha256::digest(client_key).into();
        let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());

        let mut client_proof = client_key;

        for (proof, signature) in client_proof.iter_mut().zip(client_signature) {
            *proof ^= signature;
        }

        let server_key = hmac_sha256(&salted_password, b"Server Key");
        self.expected_server_signature = hmac_sha256(&server_key, auth_message.as_bytes()).to_vec();

        let proof = base64.encode(client_proof);

        Ok(format!("{client_final_without_proof},p={proof}").into_bytes())
    }

    /// Checks the server-final-message against the signature computed
    /// while building the client-final-message.
    fn verify_server_final(&self, server_final: &[u8]) -> Result<(), SaslAuthScramSha256Error> {
        let server_final =
            from_utf8(server_final).map_err(|_| SaslAuthScramSha256Error::InvalidEncoding)?;

        if let Some(error) = server_final.strip_prefix("e=") {
            return Err(SaslAuthScramSha256Error::ServerError(error.to_string()));
        }

        let signature = server_final
            .strip_prefix("v=")
            .ok_or(SaslAuthScramSha256Error::InvalidServerFinal)?;

        let signature = base64
            .decode(signature)
            .map_err(|_| SaslAuthScramSha256Error::InvalidBase64)?;

        // NOTE: the bytes are compared in constant time, so a wrong
        // signature leaks nothing about how much of it matched.
        let expected = &self.expected_server_signature;
        let matching = signature.len() == expected.len()
            && signature
                .iter()
                .zip(expected)
                .fold(0u8, |diff, (left, right)| diff | (left ^ right))
                == 0;

        if !matching {
            return Err(SaslAuthScramSha256Error::ServerSignatureMismatch);
        }

        Ok(())
    }
}

impl SaslCoroutine for SaslAuthScramSha256 {
    type Error = SaslAuthScramSha256Error;

    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::ScramSha256
    }

    fn resume(
        &mut self,
        arg: SaslResume<'_>,
    ) -> SaslCoroutineState<SaslYield, Result<(), Self::Error>> {
        match (&self.state, arg) {
            (State::Start, SaslResume::Start) => {
                let client_first_bare = &self.client_first_bare;
                let client_first = format!("n,,{client_first_bare}");

                self.state = State::SentClientFirst;
                debug!("client-first-message sent");
                trace!("{client_first}");
                SaslCoroutineState::Yielded(SaslYield::Respond(client_first.into_bytes()))
            }
            (State::SentClientFirst, SaslResume::Challenge(server_first)) => {
                let client_final = match self.client_final(server_first) {
                    Ok(client_final) => client_final,
                    Err(err) => return SaslCoroutineState::Complete(Err(err)),
                };

                self.state = State::SentClientFinal;
                debug!("server-first-message received, client-final-message sent");
                SaslCoroutineState::Yielded(SaslYield::Respond(client_final))
            }
            (State::SentClientFinal, SaslResume::Challenge(server_final)) => {
                if let Err(err) = self.verify_server_final(server_final) {
                    return SaslCoroutineState::Complete(Err(err));
                }

                self.state = State::Verified;
                debug!("server signature verified");
                SaslCoroutineState::Yielded(SaslYield::Respond(Vec::new()))
            }
            (State::Verified, SaslResume::PeerFinished) => {
                debug!("scram-sha-256 exchange completed");
                SaslCoroutineState::Complete(Ok(()))
            }
            (_, SaslResume::PeerFinished) => {
                let err = SaslAuthScramSha256Error::ServerSignatureNotVerified;
                SaslCoroutineState::Complete(Err(err))
            }
            (_, _) => {
                let err = SaslAuthScramSha256Error::UnexpectedChallenge;
                SaslCoroutineState::Complete(Err(err))
            }
        }
    }
}

enum State {
    Start,
    SentClientFirst,
    SentClientFinal,
    Verified,
}

/// HMAC-SHA-256 as RFC 5802 uses it: `HMAC(key, data)`.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use alloc::{
        string::{String, ToString},
        vec::Vec,
    };

    use secrecy::SecretString;

    use crate::{coroutine::*, rfc7677::scram_sha_256::*};

    // NOTE: the published exchange of RFC 7677 section 3, for the user
    // "user" with the password "pencil".
    const CLIENT_NONCE: &[u8] = b"rOprNGfwEbeRWgbNEkqO";
    const CLIENT_FIRST: &str = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
    const SERVER_FIRST: &str =
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    const CLIENT_FINAL: &str = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    const SERVER_FINAL: &str = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

    #[test]
    fn exchange_matches_the_rfc_7677_test_vector() {
        let mut auth = SaslAuthScramSha256::new(creds());

        assert_eq!(
            respond(&mut auth, SaslResume::Start),
            CLIENT_FIRST.as_bytes()
        );

        let client_final = respond(&mut auth, SaslResume::Challenge(SERVER_FIRST.as_bytes()));
        assert_eq!(client_final, CLIENT_FINAL.as_bytes());

        let ack = respond(&mut auth, SaslResume::Challenge(SERVER_FINAL.as_bytes()));
        assert!(ack.is_empty());

        assert!(matches!(
            auth.resume(SaslResume::PeerFinished),
            SaslCoroutineState::Complete(Ok(())),
        ));
    }

    #[test]
    fn peer_finished_before_verification_completes_err() {
        let mut auth = SaslAuthScramSha256::new(creds());

        let _ = respond(&mut auth, SaslResume::Start);
        let _ = respond(&mut auth, SaslResume::Challenge(SERVER_FIRST.as_bytes()));

        assert!(matches!(
            auth.resume(SaslResume::PeerFinished),
            SaslCoroutineState::Complete(Err(SaslAuthScramSha256Error::ServerSignatureNotVerified)),
        ));
    }

    #[test]
    fn server_nonce_not_extending_the_client_nonce_completes_err() {
        let mut auth = SaslAuthScramSha256::new(creds());

        let _ = respond(&mut auth, SaslResume::Start);

        let server_first = "r=someOtherNonce,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";

        assert!(matches!(
            auth.resume(SaslResume::Challenge(server_first.as_bytes())),
            SaslCoroutineState::Complete(Err(SaslAuthScramSha256Error::NonceMismatch)),
        ));
    }

    #[test]
    fn tampered_server_signature_completes_err() {
        let mut auth = SaslAuthScramSha256::new(creds());

        let _ = respond(&mut auth, SaslResume::Start);
        let _ = respond(&mut auth, SaslResume::Challenge(SERVER_FIRST.as_bytes()));

        let server_final = "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        assert!(matches!(
            auth.resume(SaslResume::Challenge(server_final.as_bytes())),
            SaslCoroutineState::Complete(Err(SaslAuthScramSha256Error::ServerSignatureMismatch)),
        ));
    }

    #[test]
    fn server_error_completes_err() {
        let mut auth = SaslAuthScramSha256::new(creds());

        let _ = respond(&mut auth, SaslResume::Start);
        let _ = respond(&mut auth, SaslResume::Challenge(SERVER_FIRST.as_bytes()));

        let SaslCoroutineState::Complete(Err(err)) =
            auth.resume(SaslResume::Challenge(b"e=invalid-proof"))
        else {
            panic!("expected Complete(Err)");
        };
        let SaslAuthScramSha256Error::ServerError(reported) = err else {
            panic!("expected SaslAuthScramSha256Error::ServerError, got {err:?}");
        };
        assert_eq!(reported, "invalid-proof");
    }

    #[test]
    fn username_separators_are_escaped() {
        let creds = SaslScramSha256 {
            username: "a=b,c".to_string(),
            password: SecretString::from("pencil".to_string()),
            nonce: CLIENT_NONCE.to_vec(),
        };
        let mut auth = SaslAuthScramSha256::new(creds);

        let client_first = respond(&mut auth, SaslResume::Start);
        let client_first = String::from_utf8(client_first).expect("utf8 client-first-message");

        assert_eq!(client_first, "n,,n=a=3Db=2Cc,r=rOprNGfwEbeRWgbNEkqO");
    }

    fn creds() -> SaslScramSha256 {
        SaslScramSha256 {
            username: "user".to_string(),
            password: SecretString::from("pencil".to_string()),
            nonce: CLIENT_NONCE.to_vec(),
        }
    }

    fn respond(auth: &mut SaslAuthScramSha256, arg: SaslResume<'_>) -> Vec<u8> {
        match auth.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::Respond(bytes)) => bytes,
            state => panic!("expected Respond, got {state:?}"),
        }
    }
}
