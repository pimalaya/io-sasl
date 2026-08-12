//! The SCRAM family ([RFC 5802]), shared by every digest profile.
//!
//! Four steps, the last of which is the point of the family. The client
//! sends a client-first-message naming the user and a nonce, the server
//! answers with its own nonce, a salt and an iteration count, the client
//! proves it knows the password without sending it, and the server
//! proves the same in return. That last proof is mutual authentication:
//! an exchange ending before the server signature was verified is a
//! failure, not a success, which is why
//! [`SaslArg::Done`] arriving early completes
//! [`SaslScramError::ServerSignatureNotVerified`].
//!
//! ## What a profile adds
//!
//! Everything above is digest-agnostic and lives here, in
//! [`SaslScram`]. A profile module adds three things: the digest, the
//! two names the profile is registered under, and the exchange it is
//! pinned by. [`rfc5802::scram_sha_1`](self::scram_sha_1) is the
//! original profile of this RFC, [`crate::rfc7677::scram_sha_256`] the
//! one every current server offers, and [`crate::scram_sha_512`] the
//! one that never got an RFC.
//!
//! ## Channel binding
//!
//! Every profile is registered twice, plain and `-PLUS`, and the
//! difference is entirely in the GS2 header of the client-first-message
//! and in the `c=` field that repeats it. The three cases are the three
//! variants of [`SaslGs2ChannelBinding`], and picking one picks the
//! mechanism name [`SaslCoroutine::mechanism`] reports.
//!
//! The binding material itself is supplied with the credentials rather
//! than computed here, exactly as the client nonce is: extracting it
//! means asking a TLS session what it exported, which an I/O-free crate
//! has no way to do. The caller is also the only party that knows which
//! kind it extracted.
//!
//! ## Base64
//!
//! Only the intra-message base64 of RFC 5802 lives here, the `s=` salt,
//! the `c=` channel binding and the `p=` proof. Transport-level base64
//! stays with the protocol crate, which decodes a challenge before
//! handing it over.
//!
//! [RFC 5802]: https://www.rfc-editor.org/rfc/rfc5802

use core::{marker::PhantomData, str::from_utf8};

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use base64::{Engine, engine::general_purpose::STANDARD as base64};
use hmac::{EagerHash, Hmac, KeyInit, Mac, digest::Output};
use log::{debug, trace};
use pbkdf2::pbkdf2_hmac;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::{
    coroutine::*,
    mechanism::SaslMechanism,
    rfc5801::{SaslGs2ChannelBinding, escape},
};

#[cfg(feature = "saslprep")]
use crate::rfc4013::{SaslPrepError, saslprep};

#[cfg(feature = "scram-sha-1")]
#[cfg_attr(docsrs, doc(cfg(feature = "scram-sha-1")))]
pub mod scram_sha_1;

/// Failure causes of a SCRAM exchange, whatever the profile.
///
/// The messages name the family rather than the profile, since the
/// protocol crate chose the mechanism and already knows which one it
/// is running.
#[derive(Clone, Debug, Error)]
pub enum SaslScramError {
    /// A credential carried a code point SASLprep prohibits, so it
    /// cannot be prepared and the key derivation would run on bytes
    /// the server never stored.
    #[cfg(feature = "saslprep")]
    #[cfg_attr(docsrs, doc(cfg(feature = "saslprep")))]
    #[error("SASL SCRAM failed: {0}")]
    Preparation(#[from] SaslPrepError),
    /// A server message was not valid UTF-8.
    #[error("SASL SCRAM failed: invalid server message encoding")]
    InvalidEncoding,
    /// The server-first-message carried no `r=` nonce.
    #[error("SASL SCRAM failed: server-first-message missing nonce")]
    MissingNonce,
    /// The server-first-message carried no `s=` salt.
    #[error("SASL SCRAM failed: server-first-message missing salt")]
    MissingSalt,
    /// The server-first-message carried no `i=` iteration count.
    #[error("SASL SCRAM failed: server-first-message missing iteration count")]
    MissingIterations,
    /// The `i=` iteration count did not parse as an integer.
    #[error("SASL SCRAM failed: invalid iteration count")]
    InvalidIterationCount,
    /// A base64 value in a server message failed to decode.
    #[error("SASL SCRAM failed: invalid base64 in server message")]
    InvalidBase64,
    /// The server nonce did not extend the client nonce, so the server
    /// is replaying another exchange.
    #[error("SASL SCRAM failed: server nonce does not start with client nonce")]
    NonceMismatch,
    /// The server-final-message carried neither `v=` nor `e=`.
    #[error("SASL SCRAM failed: invalid server-final-message")]
    InvalidServerFinal,
    /// The server-final-message reported an `e=` error.
    #[error("SASL SCRAM failed: server error: {0}")]
    ServerError(String),
    /// The `v=` signature did not match the locally computed one, so
    /// the server does not know the password.
    #[error("SASL SCRAM failed: server signature mismatch")]
    ServerSignatureMismatch,
    /// The peer ended the exchange before the server proved itself.
    ///
    /// The variant exists so that mutual authentication cannot be
    /// skipped by omission: a protocol that accepts its own success
    /// reply (an IMAP tagged OK, an SMTP 235) without ever feeding the
    /// server-final-message back gets a failure rather than a silent
    /// half-verified success.
    #[error("SASL SCRAM failed: exchange ended before the server signature was verified")]
    ServerSignatureNotVerified,
    /// The mechanism was resumed with a challenge it does not expect,
    /// or out of order.
    #[error("SASL SCRAM failed: unexpected challenge")]
    UnexpectedChallenge,
}

/// SCRAM credentials, shared by every profile since the profiles differ
/// only in the digest they run the same exchange with.
#[derive(Clone, Debug)]
pub struct SaslScramCreds {
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
    /// The channel binding, which picks between the profile's plain and
    /// `-PLUS` names.
    pub channel_binding: SaslGs2ChannelBinding,
}

/// A digest a SCRAM profile is built on, with the two names that
/// profile is registered under.
///
/// The trait is what makes [`SaslScram`] generic without losing the
/// mechanism name: a profile module implements it for its digest and is
/// then one type alias long.
pub trait SaslScramDigest: EagerHash {
    /// The name the profile is registered under without channel
    /// binding.
    const MECHANISM: SaslMechanism;
    /// The name the profile is registered under with channel binding.
    const MECHANISM_PLUS: SaslMechanism;
}

/// I/O-free SASL SCRAM mechanism, in the profile of its digest.
///
/// Reach for it through a profile alias rather than directly:
/// [`scram_sha_1::SaslScramSha1`],
/// [`crate::rfc7677::scram_sha_256::SaslScramSha256`] or
/// [`crate::scram_sha_512::SaslScramSha512`].
pub struct SaslScram<D> {
    username: String,
    password: SecretString,
    client_nonce: String,
    client_first_bare: String,
    gs2_header: String,
    cbind_input: String,
    mechanism: SaslMechanism,
    expected_server_signature: Vec<u8>,
    state: State,
    digest: PhantomData<D>,
}

impl<D: SaslScramDigest> SaslScram<D> {
    /// Builds the mechanism from its credentials, whose
    /// [`nonce`](SaslScramCreds::nonce) and channel binding the caller
    /// supplied.
    ///
    /// An I/O-free mechanism can neither generate randomness nor ask a
    /// TLS session what it exported, so the caller owns both decisions
    /// and the exchange stays deterministically testable.
    pub fn new(creds: SaslScramCreds) -> Self {
        let client_nonce = String::from_utf8_lossy(&creds.nonce).to_string();

        // NOTE: SCRAM sends no authorization identity of its own, so the
        // header carries the flag and nothing else. The mechanism name
        // follows the same choice, a bound exchange running under the
        // -PLUS one.
        let gs2_header = creds.channel_binding.header(None);
        let cbind_input = creds.channel_binding.cbind_input(None);

        let mechanism = match creds.channel_binding.is_bound() {
            true => D::MECHANISM_PLUS,
            false => D::MECHANISM,
        };

        Self {
            username: creds.username,
            password: creds.password,
            client_first_bare: String::new(),
            client_nonce,
            gs2_header,
            cbind_input: base64.encode(cbind_input),
            mechanism,
            expected_server_signature: Vec::new(),
            state: State::SendClientFirst,
            digest: PhantomData,
        }
    }

    /// Parses the server-first-message and computes the
    /// client-final-message, remembering the server signature to
    /// expect in return.
    fn client_final(&mut self, server_first: &[u8]) -> Result<Vec<u8>, SaslScramError> {
        let server_first = from_utf8(server_first).map_err(|_| SaslScramError::InvalidEncoding)?;

        let mut nonce = None;
        let mut salt = None;
        let mut iterations = None;

        for field in server_first.split(',') {
            if let Some(r) = field.strip_prefix("r=") {
                nonce = Some(r);
            } else if let Some(s) = field.strip_prefix("s=") {
                let s = base64
                    .decode(s)
                    .map_err(|_| SaslScramError::InvalidBase64)?;
                salt = Some(s);
            } else if let Some(i) = field.strip_prefix("i=") {
                let i = i
                    .parse::<u32>()
                    .map_err(|_| SaslScramError::InvalidIterationCount)?;
                iterations = Some(i);
            }
        }

        let nonce = nonce.ok_or(SaslScramError::MissingNonce)?;
        let salt = salt.ok_or(SaslScramError::MissingSalt)?;
        let iterations = iterations.ok_or(SaslScramError::MissingIterations)?;

        if !nonce.starts_with(&self.client_nonce) {
            return Err(SaslScramError::NonceMismatch);
        }

        trace!("iterations: {iterations}");

        let cbind_input = &self.cbind_input;
        let client_final_without_proof = format!("c={cbind_input},r={nonce}");

        let client_first_bare = &self.client_first_bare;
        let auth_message =
            format!("{client_first_bare},{server_first},{client_final_without_proof}");

        let mut salted_password = Output::<D>::default();
        let password = self.password.expose_secret().as_bytes();
        pbkdf2_hmac::<D>(password, &salt, iterations, &mut salted_password);

        let client_key = hmac::<D>(&salted_password, b"Client Key");
        let stored_key = D::digest(&client_key);
        let client_signature = hmac::<D>(&stored_key, auth_message.as_bytes());

        let mut client_proof = client_key;

        for (proof, signature) in client_proof.iter_mut().zip(client_signature) {
            *proof ^= signature;
        }

        let server_key = hmac::<D>(&salted_password, b"Server Key");
        self.expected_server_signature = hmac::<D>(&server_key, auth_message.as_bytes()).to_vec();

        let proof = base64.encode(client_proof);

        Ok(format!("{client_final_without_proof},p={proof}").into_bytes())
    }

    /// Checks the server-final-message against the signature computed
    /// while building the client-final-message.
    fn verify_server_final(&self, server_final: &[u8]) -> Result<(), SaslScramError> {
        let server_final = from_utf8(server_final).map_err(|_| SaslScramError::InvalidEncoding)?;

        if let Some(error) = server_final.strip_prefix("e=") {
            return Err(SaslScramError::ServerError(error.to_string()));
        }

        let signature = server_final
            .strip_prefix("v=")
            .ok_or(SaslScramError::InvalidServerFinal)?;

        let signature = base64
            .decode(signature)
            .map_err(|_| SaslScramError::InvalidBase64)?;

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
            return Err(SaslScramError::ServerSignatureMismatch);
        }

        Ok(())
    }
}

impl<D: SaslScramDigest> SaslCoroutine for SaslScram<D> {
    type Error = SaslScramError;

    fn mechanism(&self) -> SaslMechanism {
        self.mechanism
    }

    fn resume(
        &mut self,
        arg: SaslArg<'_>,
    ) -> SaslCoroutineState<SaslYield, Result<(), Self::Error>> {
        match (&self.state, arg) {
            (State::SendClientFirst, SaslArg::None) => {
                // NOTE: RFC 5802 section 5.1 asks the client to prepare
                // both, and the password reaches the key derivation, so
                // preparing late would derive a key from bytes the
                // server never stored.
                #[cfg(feature = "saslprep")]
                {
                    let prepared = [self.username.as_str(), self.password.expose_secret()];

                    let [username, password] = match prepared.map(saslprep) {
                        [Ok(username), Ok(password)] => [username, password],
                        prepared => {
                            let err = prepared.into_iter().find_map(Result::err);
                            let err = err.expect("one of the two failed to prepare");
                            return SaslCoroutineState::Complete(Err(err.into()));
                        }
                    };

                    self.username = username;
                    self.password = SecretString::from(password);
                }

                let escaped = escape(&self.username);
                let client_nonce = &self.client_nonce;
                self.client_first_bare = format!("n={escaped},r={client_nonce}");

                let gs2_header = &self.gs2_header;
                let client_first_bare = &self.client_first_bare;
                let client_first = format!("{gs2_header}{client_first_bare}");

                self.state = State::SendClientFinal;
                debug!("client-first-message sent");
                trace!("{client_first}");
                SaslCoroutineState::Yielded(SaslYield::WantsWrite(client_first.into_bytes()))
            }
            (State::SendClientFinal, SaslArg::Input(server_first)) => {
                let client_final = match self.client_final(server_first) {
                    Ok(client_final) => client_final,
                    Err(err) => return SaslCoroutineState::Complete(Err(err)),
                };

                self.state = State::Acknowledge;
                debug!("server-first-message received, client-final-message sent");
                SaslCoroutineState::Yielded(SaslYield::WantsWrite(client_final))
            }
            (State::Acknowledge, SaslArg::Input(server_final)) => {
                if let Err(err) = self.verify_server_final(server_final) {
                    return SaslCoroutineState::Complete(Err(err));
                }

                self.state = State::Done;
                debug!("server signature verified");
                SaslCoroutineState::Yielded(SaslYield::WantsWrite(Vec::new()))
            }
            (State::Done, SaslArg::Done) => {
                debug!("scram exchange completed");
                SaslCoroutineState::Complete(Ok(()))
            }
            (_, SaslArg::Done) => {
                let err = SaslScramError::ServerSignatureNotVerified;
                SaslCoroutineState::Complete(Err(err))
            }
            (_, _) => {
                let err = SaslScramError::UnexpectedChallenge;
                SaslCoroutineState::Complete(Err(err))
            }
        }
    }
}

enum State {
    SendClientFirst,
    SendClientFinal,
    Acknowledge,
    Done,
}

/// HMAC as RFC 5802 uses it, in the digest of the profile:
/// `HMAC(key, data)`.
///
/// NOTE: the output is sized by `Hmac<D>` rather than by `D`, which is
/// the same length by construction; only the compiler needs telling
/// them apart.
fn hmac<D: EagerHash>(key: &[u8], data: &[u8]) -> Output<Hmac<D>> {
    let mut mac = Hmac::<D>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes()
}

#[cfg(test)]
mod tests {
    use alloc::{
        string::{String, ToString},
        vec::Vec,
    };

    use secrecy::SecretString;

    use crate::{
        coroutine::*,
        rfc5801::{SaslGs2ChannelBinding, SaslGs2ChannelBindingKind},
        rfc5802::*,
        rfc7677::scram_sha_256::SaslScramSha256,
    };

    // NOTE: everything here is about the family rather than about a
    // profile, so it runs on SCRAM-SHA-256, whose exchange the RFC 7677
    // vector pins in its own module. The nonces and the salt are that
    // vector's.
    const CLIENT_NONCE: &[u8] = b"rOprNGfwEbeRWgbNEkqO";
    const SERVER_FIRST: &str =
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    const SERVER_FINAL: &str = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

    #[test]
    fn peer_finished_before_verification_completes_err() {
        let mut auth = SaslScramSha256::new(creds(SaslGs2ChannelBinding::Unsupported));

        let _ = respond(&mut auth, SaslArg::None);
        let _ = respond(&mut auth, SaslArg::Input(SERVER_FIRST.as_bytes()));

        assert!(matches!(
            auth.resume(SaslArg::Done),
            SaslCoroutineState::Complete(Err(SaslScramError::ServerSignatureNotVerified)),
        ));
    }

    #[test]
    fn server_nonce_not_extending_the_client_nonce_completes_err() {
        let mut auth = SaslScramSha256::new(creds(SaslGs2ChannelBinding::Unsupported));

        let _ = respond(&mut auth, SaslArg::None);

        let server_first = "r=someOtherNonce,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";

        assert!(matches!(
            auth.resume(SaslArg::Input(server_first.as_bytes())),
            SaslCoroutineState::Complete(Err(SaslScramError::NonceMismatch)),
        ));
    }

    #[test]
    fn tampered_server_signature_completes_err() {
        let mut auth = SaslScramSha256::new(creds(SaslGs2ChannelBinding::Unsupported));

        let _ = respond(&mut auth, SaslArg::None);
        let _ = respond(&mut auth, SaslArg::Input(SERVER_FIRST.as_bytes()));

        let server_final = "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        assert!(matches!(
            auth.resume(SaslArg::Input(server_final.as_bytes())),
            SaslCoroutineState::Complete(Err(SaslScramError::ServerSignatureMismatch)),
        ));
    }

    #[test]
    fn server_error_completes_err() {
        let mut auth = SaslScramSha256::new(creds(SaslGs2ChannelBinding::Unsupported));

        let _ = respond(&mut auth, SaslArg::None);
        let _ = respond(&mut auth, SaslArg::Input(SERVER_FIRST.as_bytes()));

        let SaslCoroutineState::Complete(Err(err)) =
            auth.resume(SaslArg::Input(b"e=invalid-proof"))
        else {
            panic!("expected Complete(Err)");
        };
        let SaslScramError::ServerError(reported) = err else {
            panic!("expected SaslScramError::ServerError, got {err:?}");
        };
        assert_eq!(reported, "invalid-proof");
    }

    #[cfg(feature = "saslprep")]
    #[test]
    fn the_credentials_are_prepared_before_the_first_message() {
        // NOTE: the username reaches the wire and the password reaches
        // the key derivation, so preparing either late derives a key
        // from bytes the server never stored.
        let mut auth = SaslScramSha256::new(SaslScramCreds {
            username: "u\u{00ad}ser".to_string(),
            ..creds(SaslGs2ChannelBinding::Unsupported)
        });

        let client_first = respond(&mut auth, SaslArg::None);

        assert_eq!(client_first, b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO");

        // NOTE: the RFC 7677 exchange again, with a soft hyphen inside
        // the password. Preparation removes it, so the proof is the
        // published one: the vector is what says the derivation ran on
        // prepared bytes rather than on what was typed.
        let mut auth = SaslScramSha256::new(SaslScramCreds {
            password: SecretString::from("pen\u{00ad}cil".to_string()),
            ..creds(SaslGs2ChannelBinding::Unsupported)
        });

        let _ = respond(&mut auth, SaslArg::None);
        let client_final = respond(&mut auth, SaslArg::Input(SERVER_FIRST.as_bytes()));

        assert!(client_final.ends_with(b"p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="));
    }

    #[cfg(feature = "saslprep")]
    #[test]
    fn a_credential_that_cannot_be_prepared_completes_err() {
        let mut auth = SaslScramSha256::new(SaslScramCreds {
            password: SecretString::from("pen\u{0007}cil".to_string()),
            ..creds(SaslGs2ChannelBinding::Unsupported)
        });

        assert!(matches!(
            auth.resume(SaslArg::None),
            SaslCoroutineState::Complete(Err(SaslScramError::Preparation(_))),
        ));
    }

    #[test]
    fn username_separators_are_escaped() {
        let mut auth = SaslScramSha256::new(SaslScramCreds {
            username: "a=b,c".to_string(),
            ..creds(SaslGs2ChannelBinding::Unsupported)
        });

        let client_first = respond(&mut auth, SaslArg::None);
        let client_first = String::from_utf8(client_first).expect("utf8 client-first-message");

        assert_eq!(client_first, "n,,n=a=3Db=2Cc,r=rOprNGfwEbeRWgbNEkqO");
    }

    #[test]
    fn a_client_supporting_binding_without_using_it_says_so() {
        // NOTE: the y flag of RFC 5802 section 6, which is what lets a
        // server that does support channel binding notice that its
        // -PLUS name was stripped in flight. Sending n instead would
        // make the downgrade invisible.
        let mut auth = SaslScramSha256::new(creds(SaslGs2ChannelBinding::Unused));

        let client_first = respond(&mut auth, SaslArg::None);

        assert!(client_first.starts_with(b"y,,n=user"));

        let client_final = respond(&mut auth, SaslArg::Input(SERVER_FIRST.as_bytes()));

        // NOTE: c=eSws is the base64 of "y,,", so the flag the server
        // read is repeated inside the signed client-final-message and
        // cannot have been rewritten in between.
        assert!(client_final.starts_with(b"c=eSws,"));
    }

    #[test]
    fn a_bound_exchange_carries_the_binding_in_the_client_final_message() {
        // NOTE: derived from the RFC 5802 algorithm by an
        // implementation outside this crate, the RFC 7677 exchange with
        // a tls-exporter binding of eight bytes: c= is the base64 of
        // "p=tls-exporter,," followed by that binding, and the proof
        // changes with it since c= is part of the signed message.
        let mut auth = SaslScramSha256::new(creds(SaslGs2ChannelBinding::Bound {
            kind: SaslGs2ChannelBindingKind::TlsExporter,
            data: (0..8).collect(),
        }));

        let client_first = respond(&mut auth, SaslArg::None);

        assert!(client_first.starts_with(b"p=tls-exporter,,n=user"));

        let client_final = respond(&mut auth, SaslArg::Input(SERVER_FIRST.as_bytes()));
        let client_final = String::from_utf8(client_final).expect("utf8 client-final-message");

        assert_eq!(
            client_final,
            concat!(
                "c=cD10bHMtZXhwb3J0ZXIsLAABAgMEBQYH,",
                "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,",
                "p=QAd7eifevIt6X/f2Cv9W4HLXcFLw7OayX8dQ2scckyI=",
            ),
        );

        let server_final = "v=8dbpxwe4DaC4ESpY8u6aAvFeP2ks9+LClF/ADCxyWOE=";
        let ack = respond(&mut auth, SaslArg::Input(server_final.as_bytes()));

        assert!(ack.is_empty());
    }

    #[test]
    fn a_malformed_server_first_message_completes_err() {
        let missing = [
            ("s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096", "nonce"),
            ("r=rOprNGfwEbeRWgbNEkqOx,i=4096", "salt"),
            (
                "r=rOprNGfwEbeRWgbNEkqOx,s=W22ZaJ0SNY7soEsUEjb6gQ==",
                "iterations",
            ),
            (
                "r=rOprNGfwEbeRWgbNEkqOx,s=not!base64,i=4096",
                "salt encoding",
            ),
            (
                "r=rOprNGfwEbeRWgbNEkqOx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=many",
                "iteration count",
            ),
        ];

        for (server_first, what) in missing {
            let mut auth = SaslScramSha256::new(creds(SaslGs2ChannelBinding::Unsupported));

            let _ = respond(&mut auth, SaslArg::None);

            assert!(
                matches!(
                    auth.resume(SaslArg::Input(server_first.as_bytes())),
                    SaslCoroutineState::Complete(Err(_)),
                ),
                "a server-first-message with no valid {what} was accepted"
            );
        }
    }

    #[test]
    fn a_server_message_that_is_not_utf8_completes_err() {
        let mut auth = SaslScramSha256::new(creds(SaslGs2ChannelBinding::Unsupported));

        let _ = respond(&mut auth, SaslArg::None);

        assert!(matches!(
            auth.resume(SaslArg::Input(&[0xff])),
            SaslCoroutineState::Complete(Err(SaslScramError::InvalidEncoding)),
        ));
    }

    #[test]
    fn a_server_final_message_carrying_neither_signature_nor_error_completes_err() {
        let mut auth = SaslScramSha256::new(creds(SaslGs2ChannelBinding::Unsupported));

        let _ = respond(&mut auth, SaslArg::None);
        let _ = respond(&mut auth, SaslArg::Input(SERVER_FIRST.as_bytes()));

        assert!(matches!(
            auth.resume(SaslArg::Input(b"r=whatever")),
            SaslCoroutineState::Complete(Err(SaslScramError::InvalidServerFinal)),
        ));

        let mut auth = SaslScramSha256::new(creds(SaslGs2ChannelBinding::Unsupported));

        let _ = respond(&mut auth, SaslArg::None);
        let _ = respond(&mut auth, SaslArg::Input(SERVER_FIRST.as_bytes()));

        assert!(matches!(
            auth.resume(SaslArg::Input(b"v=not!base64")),
            SaslCoroutineState::Complete(Err(SaslScramError::InvalidBase64)),
        ));
    }

    #[test]
    fn an_extra_challenge_after_the_exchange_completes_err() {
        let mut auth = SaslScramSha256::new(creds(SaslGs2ChannelBinding::Unsupported));

        let _ = respond(&mut auth, SaslArg::None);
        let _ = respond(&mut auth, SaslArg::Input(SERVER_FIRST.as_bytes()));
        let _ = respond(&mut auth, SaslArg::Input(SERVER_FINAL.as_bytes()));

        assert!(matches!(
            auth.resume(SaslArg::Input(b"")),
            SaslCoroutineState::Complete(Err(SaslScramError::UnexpectedChallenge)),
        ));
    }

    fn creds(channel_binding: SaslGs2ChannelBinding) -> SaslScramCreds {
        SaslScramCreds {
            username: "user".to_string(),
            password: SecretString::from("pencil".to_string()),
            nonce: CLIENT_NONCE.to_vec(),
            channel_binding,
        }
    }

    fn respond(auth: &mut SaslScramSha256, arg: SaslArg<'_>) -> Vec<u8> {
        match auth.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }
}
