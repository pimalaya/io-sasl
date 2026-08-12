//! The SCRAM-SHA-256 profile ([RFC 7677]), the one to prefer.
//!
//! The exchange, the failure type and the credentials are the family's,
//! in [`crate::rfc5802`]; this module adds the digest and the two names
//! the profile is registered under, `SCRAM-SHA-256` and
//! `SCRAM-SHA-256-PLUS`.
//!
//! # Example
//!
//! The exchange published in [RFC 7677 section 3], for the user `user`
//! with the password `pencil`. A real client draws its nonce from a
//! cryptographic source instead of hard-coding one.
//!
//! ```rust
//! use io_sasl::{
//!     coroutine::{SaslCoroutine, SaslCoroutineState, SaslArg, SaslYield},
//!     rfc5802::{SaslScramChannelBinding, SaslScramCreds},
//!     rfc7677::scram_sha_256::SaslScramSha256,
//! };
//! use secrecy::SecretString;
//!
//! let mut auth = SaslScramSha256::new(SaslScramCreds {
//!     username: "user".into(),
//!     password: SecretString::from("pencil"),
//!     nonce: b"rOprNGfwEbeRWgbNEkqO".to_vec(),
//!     channel_binding: SaslScramChannelBinding::Unsupported,
//! });
//!
//! let state = auth.resume(SaslArg::None);
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(first)) = state else {
//!     panic!("expected the client-first-message");
//! };
//!
//! assert_eq!(first, b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
//!
//! // The server extends the nonce and names its salt and iteration
//! // count; the mechanism answers with the proof it knows the password.
//! let server_first = SaslArg::Input(
//!     b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
//! );
//!
//! let state = auth.resume(server_first);
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(proof)) = state else {
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
//! let state = auth.resume(SaslArg::Input(signature));
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(ack)) = state else {
//!     panic!("expected the server-final-message to verify");
//! };
//!
//! assert!(ack.is_empty());
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
//! [RFC 7677]: https://www.rfc-editor.org/rfc/rfc7677
//! [RFC 7677 section 3]: https://www.rfc-editor.org/rfc/rfc7677#section-3

use sha2::Sha256;

use crate::{
    mechanism::SaslMechanism,
    rfc5802::{SaslScram, SaslScramDigest},
};

/// I/O-free SASL SCRAM-SHA-256 mechanism.
pub type SaslScramSha256 = SaslScram<Sha256>;

impl SaslScramDigest for Sha256 {
    const MECHANISM: SaslMechanism = SaslMechanism::ScramSha256;
    const MECHANISM_PLUS: SaslMechanism = SaslMechanism::ScramSha256Plus;
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use secrecy::SecretString;

    use crate::{
        coroutine::*,
        mechanism::SaslMechanism,
        rfc5802::{SaslScramChannelBinding, SaslScramChannelBindingKind, SaslScramCreds},
        rfc7677::scram_sha_256::*,
    };

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
        let mut auth = SaslScramSha256::new(creds());

        assert_eq!(respond(&mut auth, SaslArg::None), CLIENT_FIRST.as_bytes());

        let client_final = respond(&mut auth, SaslArg::Input(SERVER_FIRST.as_bytes()));
        assert_eq!(client_final, CLIENT_FINAL.as_bytes());

        let ack = respond(&mut auth, SaslArg::Input(SERVER_FINAL.as_bytes()));
        assert!(ack.is_empty());

        assert!(matches!(
            auth.resume(SaslArg::Done),
            SaslCoroutineState::Complete(Ok(())),
        ));
    }

    #[test]
    fn the_profile_answers_to_both_names_it_is_registered_under() {
        let plain = SaslScramSha256::new(creds());

        assert_eq!(plain.mechanism(), SaslMechanism::ScramSha256);

        let bound = SaslScramSha256::new(SaslScramCreds {
            channel_binding: SaslScramChannelBinding::Bound {
                kind: SaslScramChannelBindingKind::TlsExporter,
                data: b"binding".to_vec(),
            },
            ..creds()
        });

        assert_eq!(bound.mechanism(), SaslMechanism::ScramSha256Plus);
    }

    fn creds() -> SaslScramCreds {
        SaslScramCreds {
            username: "user".to_string(),
            password: SecretString::from("pencil".to_string()),
            nonce: CLIENT_NONCE.to_vec(),
            channel_binding: SaslScramChannelBinding::Unsupported,
        }
    }

    fn respond(auth: &mut SaslScramSha256, arg: SaslArg<'_>) -> Vec<u8> {
        match auth.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }
}
