//! The SCRAM-SHA-1 profile ([RFC 5802]), the original one.
//!
//! The exchange, the failure type and the credentials are the family's,
//! in [`crate::rfc5802`]; this module adds the digest and the two names
//! the profile is registered under, `SCRAM-SHA-1` and
//! `SCRAM-SHA-1-PLUS`.
//!
//! SHA-1 is broken for collision resistance, which SCRAM does not rest
//! on: the exchange uses HMAC-SHA-1 and PBKDF2-HMAC-SHA-1, neither of
//! which the published collisions break. It is still the weakest
//! profile of the three and exists for servers that never enabled
//! another, which is why it sits behind its own `scram-sha-1` cargo
//! feature rather than in the default set.
//!
//! # Example
//!
//! The exchange published in [RFC 5802 section 5], for the user `user`
//! with the password `pencil`.
//!
//! ```rust
//! use io_sasl::{
//!     coroutine::{SaslCoroutine, SaslCoroutineState, SaslArg, SaslYield},
//!     rfc5801::SaslGs2ChannelBinding,
//!     rfc5802::{SaslScramCreds, scram_sha_1::SaslScramSha1},
//! };
//! use secrecy::SecretString;
//!
//! let mut auth = SaslScramSha1::new(SaslScramCreds {
//!     username: "user".into(),
//!     password: SecretString::from("pencil"),
//!     nonce: b"fyko+d2lbbFgONRv9qkxdawL".to_vec(),
//!     channel_binding: SaslGs2ChannelBinding::Unsupported,
//! });
//!
//! let state = auth.resume(SaslArg::None);
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(first)) = state else {
//!     panic!("expected the client-first-message");
//! };
//!
//! assert_eq!(first, b"n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL");
//!
//! // The server extends the nonce and names its salt and iteration
//! // count; the mechanism answers with the proof it knows the password.
//! let server_first = SaslArg::Input(
//!     b"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
//! );
//!
//! let state = auth.resume(server_first);
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(proof)) = state else {
//!     panic!("expected the client-final-message");
//! };
//!
//! assert!(proof.ends_with(b"p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="));
//!
//! // The server proves itself in return. Feeding this message back is
//! // what mutual authentication rests on: ending the exchange here
//! // instead would complete with ServerSignatureNotVerified.
//! let signature = b"v=rmF9pqV8S7suAoZWja4dJRkFsKQ=";
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
//! [RFC 5802]: https://www.rfc-editor.org/rfc/rfc5802
//! [RFC 5802 section 5]: https://www.rfc-editor.org/rfc/rfc5802#section-5

use sha1::Sha1;

use crate::{
    mechanism::SaslMechanism,
    rfc5802::{SaslScram, SaslScramDigest},
};

/// I/O-free SASL SCRAM-SHA-1 mechanism.
pub type SaslScramSha1 = SaslScram<Sha1>;

impl SaslScramDigest for Sha1 {
    const MECHANISM: SaslMechanism = SaslMechanism::ScramSha1;
    const MECHANISM_PLUS: SaslMechanism = SaslMechanism::ScramSha1Plus;
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use secrecy::SecretString;

    use crate::{
        coroutine::*,
        mechanism::SaslMechanism,
        rfc5801::{SaslGs2ChannelBinding, SaslGs2ChannelBindingKind},
        rfc5802::{SaslScramCreds, scram_sha_1::*},
    };

    // NOTE: the published exchange of RFC 5802 section 5, for the user
    // "user" with the password "pencil".
    const CLIENT_NONCE: &[u8] = b"fyko+d2lbbFgONRv9qkxdawL";
    const CLIENT_FIRST: &str = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL";
    const SERVER_FIRST: &str =
        "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";
    const CLIENT_FINAL: &str =
        "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=";
    const SERVER_FINAL: &str = "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=";

    #[test]
    fn exchange_matches_the_rfc_5802_test_vector() {
        let mut auth = SaslScramSha1::new(creds());

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
        let plain = SaslScramSha1::new(creds());

        assert_eq!(plain.mechanism(), SaslMechanism::ScramSha1);

        let bound = SaslScramSha1::new(SaslScramCreds {
            channel_binding: SaslGs2ChannelBinding::Bound {
                kind: SaslGs2ChannelBindingKind::TlsExporter,
                data: b"binding".to_vec(),
            },
            ..creds()
        });

        assert_eq!(bound.mechanism(), SaslMechanism::ScramSha1Plus);
    }

    fn creds() -> SaslScramCreds {
        SaslScramCreds {
            username: "user".to_string(),
            password: SecretString::from("pencil".to_string()),
            nonce: CLIENT_NONCE.to_vec(),
            channel_binding: SaslGs2ChannelBinding::Unsupported,
        }
    }

    fn respond(auth: &mut SaslScramSha1, arg: SaslArg<'_>) -> Vec<u8> {
        match auth.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }
}
