//! The SCRAM-SHA-512 profile ([draft-melnikov-scram-sha-512]), which
//! never became an RFC.
//!
//! The exchange, the failure type and the credentials are the family's,
//! in [`crate::rfc5802`]; this module adds the digest and the two names
//! the profile is registered under, `SCRAM-SHA-512` and
//! `SCRAM-SHA-512-PLUS`. Both are in the IANA SASL mechanism registry,
//! which is what a server advertises against, so the missing RFC costs
//! interoperability nothing.
//!
//! The draft publishes no example exchange, so the one below was
//! derived from the [RFC 5802] algorithm by an implementation outside
//! this crate, checked against the published SHA-1 and SHA-256
//! exchanges first.
//!
//! # Example
//!
//! ```rust
//! use io_sasl::{
//!     coroutine::{SaslCoroutine, SaslCoroutineState, SaslResume, SaslYield},
//!     rfc5802::{SaslScramChannelBinding, SaslScramCreds},
//!     scram_sha_512::SaslScramSha512,
//! };
//! use secrecy::SecretString;
//!
//! let mut auth = SaslScramSha512::new(SaslScramCreds {
//!     username: "user".into(),
//!     password: SecretString::from("pencil"),
//!     nonce: b"rOprNGfwEbeRWgbNEkqO".to_vec(),
//!     channel_binding: SaslScramChannelBinding::Unsupported,
//! });
//!
//! let state = auth.resume(SaslResume::Start);
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(first)) = state else {
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
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(proof)) = state else {
//!     panic!("expected the client-final-message");
//! };
//!
//! assert!(proof.starts_with(b"c=biws,r=rOprNGfwEbeRWgbNEkqO"));
//!
//! // The server proves itself in return. Feeding this message back is
//! // what mutual authentication rests on: ending the exchange here
//! // instead would complete with ServerSignatureNotVerified.
//! let signature = concat!(
//!     "v=ZQnYEgWQMFmmsM8aQMF0nDDCy/AgCzkwk8CmMZYcMg0v",
//!     "SVlKDanekLtifDSeVGT4+5ZxXnJq199RVG2rR7N7Zw==",
//! );
//!
//! let state = auth.resume(SaslResume::Challenge(signature.as_bytes()));
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(ack)) = state else {
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
//! [draft-melnikov-scram-sha-512]: https://datatracker.ietf.org/doc/html/draft-melnikov-scram-sha-512
//! [RFC 5802]: https://www.rfc-editor.org/rfc/rfc5802

use sha2::Sha512;

use crate::{
    mechanism::SaslMechanism,
    rfc5802::{SaslScram, SaslScramDigest},
};

/// I/O-free SASL SCRAM-SHA-512 mechanism.
pub type SaslScramSha512 = SaslScram<Sha512>;

impl SaslScramDigest for Sha512 {
    const MECHANISM: SaslMechanism = SaslMechanism::ScramSha512;
    const MECHANISM_PLUS: SaslMechanism = SaslMechanism::ScramSha512Plus;
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use secrecy::SecretString;

    use crate::{
        coroutine::*,
        mechanism::SaslMechanism,
        rfc5802::{SaslScramChannelBinding, SaslScramChannelBindingKind, SaslScramCreds},
        scram_sha_512::*,
    };

    // NOTE: the draft publishes no example, so this exchange was
    // derived from the RFC 5802 algorithm by an implementation outside
    // this crate, one that reproduces the published SHA-1 and SHA-256
    // exchanges byte for byte. The nonces and the salt are the ones of
    // the RFC 7677 exchange, so the two profiles differ here by their
    // digest and by nothing else.
    const CLIENT_NONCE: &[u8] = b"rOprNGfwEbeRWgbNEkqO";
    const CLIENT_FIRST: &str = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
    const SERVER_FIRST: &str =
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    const CLIENT_FINAL: &str = concat!(
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,",
        "p=gMGXRcevScNtxZ6/8lQYpGtnsNAc3mGcmNomv+xnoOMw+3R2xNJdMNnzMlTN8PPC6wdp6dybEmDYXYTxwnYPJQ==",
    );
    const SERVER_FINAL: &str = concat!(
        "v=ZQnYEgWQMFmmsM8aQMF0nDDCy/AgCzkwk8CmMZYcMg0v",
        "SVlKDanekLtifDSeVGT4+5ZxXnJq199RVG2rR7N7Zw==",
    );

    #[test]
    fn exchange_matches_the_derived_test_vector() {
        let mut auth = SaslScramSha512::new(creds());

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
    fn the_profile_answers_to_both_names_it_is_registered_under() {
        let plain = SaslScramSha512::new(creds());

        assert_eq!(plain.mechanism(), SaslMechanism::ScramSha512);

        let bound = SaslScramSha512::new(SaslScramCreds {
            channel_binding: SaslScramChannelBinding::Bound {
                kind: SaslScramChannelBindingKind::TlsExporter,
                data: b"binding".to_vec(),
            },
            ..creds()
        });

        assert_eq!(bound.mechanism(), SaslMechanism::ScramSha512Plus);
    }

    fn creds() -> SaslScramCreds {
        SaslScramCreds {
            username: "user".to_string(),
            password: SecretString::from("pencil".to_string()),
            nonce: CLIENT_NONCE.to_vec(),
            channel_binding: SaslScramChannelBinding::Unsupported,
        }
    }

    fn respond(auth: &mut SaslScramSha512, arg: SaslResume<'_>) -> Vec<u8> {
        match auth.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }
}
