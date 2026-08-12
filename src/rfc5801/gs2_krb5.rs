//! The GS2-KRB5 mechanism ([RFC 5801]), Kerberos through the GS2
//! bridge.
//!
//! The same Kerberos exchange as [`crate::rfc4752::gssapi`] and the
//! same relay: the tokens come from a security context this crate
//! cannot host, so the caller advances that context between two
//! resumes and this mechanism carries the SASL half. What GS2 adds is
//! the reason to prefer it. The client prefixes a header to its first
//! token naming the authorization identity and stating whether the
//! exchange is bound to the channel underneath, which gives Kerberos
//! the `-PLUS` name and the downgrade detection SCRAM already had, and
//! drops the security layer negotiation the older mechanism ends with
//! ([RFC 5801 section 12] explains the trade).
//!
//! The header is this crate's to write, so unlike the RFC 4752 relay
//! this one computes something: the flag, the escaped authorization
//! identity, and where the binding material joins them.
//!
//! # What the caller owes it
//!
//! The first token, in [`SaslGs2Krb5Creds::token`], obtained from its
//! context before the exchange starts, and the channel binding it
//! passed to that context, so that both ends describe the same
//! connection. Then, for every peer message, the caller feeds that
//! message to its context and resumes with what the context produced.
//!
//! It cannot tell when the context is established, only the GSS layer
//! knowing that, and it verifies nothing: mutual authentication lives
//! inside the tokens.
//!
//! # Example
//!
//! ```rust
//! use io_sasl::{
//!     coroutine::{SaslArg, SaslCoroutine, SaslCoroutineState, SaslYield},
//!     mechanism::SaslMechanism,
//!     rfc5801::{
//!         SaslGs2ChannelBinding, SaslGs2ChannelBindingKind,
//!         gs2_krb5::{SaslGs2Krb5, SaslGs2Krb5Creds},
//!     },
//! };
//!
//! let mut auth = SaslGs2Krb5::new(SaslGs2Krb5Creds {
//!     token: b"first token".to_vec(),
//!     authzid: None,
//!     channel_binding: SaslGs2ChannelBinding::Bound {
//!         kind: SaslGs2ChannelBindingKind::TlsExporter,
//!         data: b"exported from the TLS session".to_vec(),
//!     },
//! });
//!
//! // A bound exchange runs under the -PLUS name, which is what the
//! // protocol crate writes in its authentication command.
//! assert_eq!(auth.mechanism(), SaslMechanism::Gs2Krb5Plus);
//!
//! let state = auth.resume(SaslArg::None);
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(first)) = state else {
//!     panic!("expected the initial token");
//! };
//!
//! // The header the caller's context bound to, then the token itself.
//! assert_eq!(first, b"p=tls-exporter,,first token");
//!
//! // Every later token is relayed as it comes, the header belonging to
//! // the first message alone.
//! let state = auth.resume(SaslArg::Input(b"second token"));
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(second)) = state else {
//!     panic!("expected the next token");
//! };
//!
//! assert_eq!(second, b"second token");
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
//! [RFC 5801]: https://www.rfc-editor.org/rfc/rfc5801
//! [RFC 5801 section 12]: https://www.rfc-editor.org/rfc/rfc5801#section-12

use alloc::{borrow::ToOwned, string::String, vec::Vec};

use log::debug;
use thiserror::Error;

use crate::{coroutine::*, mechanism::SaslMechanism, rfc5801::SaslGs2ChannelBinding};

/// Failure causes of the GS2-KRB5 exchange.
///
/// One variant, and it is about ordering rather than about content: a
/// relay cannot judge a token it is not equipped to read.
#[derive(Clone, Debug, Error)]
pub enum SaslGs2Krb5Error {
    /// The mechanism was resumed out of order: input before the initial
    /// token went out, or a fresh start in the middle of the exchange.
    #[error("SASL GS2-KRB5 failed: resumed out of order")]
    OutOfOrder,
}

/// GS2-KRB5 mechanism credentials ([RFC 5801]).
///
/// The Kerberos credential stays in the caller's cache; what travels
/// here is the first token its context produced, plus what this crate
/// needs to write the header around it.
///
/// [RFC 5801]: https://www.rfc-editor.org/rfc/rfc5801
#[derive(Clone, Debug)]
pub struct SaslGs2Krb5Creds {
    /// The first GSS-API token, produced by the caller's security
    /// context before the exchange starts.
    pub token: Vec<u8>,
    /// The optional authorization identity, escaped into the header.
    pub authzid: Option<String>,
    /// The channel binding, which picks between `GS2-KRB5` and
    /// `GS2-KRB5-PLUS` and which the caller also passed to its own
    /// context.
    pub channel_binding: SaslGs2ChannelBinding,
}

/// I/O-free SASL GS2-KRB5 mechanism, relaying the tokens of a security
/// context the caller holds.
pub struct SaslGs2Krb5 {
    creds: SaslGs2Krb5Creds,
    mechanism: SaslMechanism,
    state: State,
}

impl SaslGs2Krb5 {
    /// Builds the mechanism from the first token of the caller's
    /// security context and the binding that context used.
    pub fn new(creds: SaslGs2Krb5Creds) -> Self {
        let mechanism = match creds.channel_binding.is_bound() {
            true => SaslMechanism::Gs2Krb5Plus,
            false => SaslMechanism::Gs2Krb5,
        };

        Self {
            creds,
            mechanism,
            state: State::SendFirstToken,
        }
    }
}

impl SaslCoroutine for SaslGs2Krb5 {
    type Error = SaslGs2Krb5Error;

    fn mechanism(&self) -> SaslMechanism {
        self.mechanism
    }

    fn resume(
        &mut self,
        arg: SaslArg<'_>,
    ) -> SaslCoroutineState<SaslYield, Result<(), Self::Error>> {
        match (&self.state, arg) {
            (_, SaslArg::Done) => {
                debug!("gs2-krb5 exchange completed");
                SaslCoroutineState::Complete(Ok(()))
            }
            // NOTE: the header opens the first token and nothing else,
            // the tokens after it being GSS-API's own framing.
            (State::SendFirstToken, SaslArg::None) => {
                let authzid = self.creds.authzid.as_deref();
                let header = self.creds.channel_binding.header(authzid);

                let mut payload = header.into_bytes();
                payload.append(&mut self.creds.token);

                self.state = State::RelayToken;
                debug!("gs2-krb5 header and initial token sent");
                SaslCoroutineState::Yielded(SaslYield::WantsWrite(payload))
            }
            (State::RelayToken, SaslArg::Input(token)) => {
                debug!("gs2-krb5 token relayed");
                SaslCoroutineState::Yielded(SaslYield::WantsWrite(token.to_owned()))
            }
            (_, _) => {
                let err = SaslGs2Krb5Error::OutOfOrder;
                SaslCoroutineState::Complete(Err(err))
            }
        }
    }
}

enum State {
    SendFirstToken,
    RelayToken,
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use crate::{
        coroutine::*,
        mechanism::SaslMechanism,
        rfc5801::{SaslGs2ChannelBindingKind, gs2_krb5::*},
    };

    #[test]
    fn start_responds_with_the_header_and_the_initial_token() {
        let mut auth = SaslGs2Krb5::new(creds(SaslGs2ChannelBinding::Unsupported));

        assert_eq!(respond(&mut auth, SaslArg::None), b"n,,first token");
    }

    #[test]
    fn the_authorization_identity_rides_in_the_header() {
        let mut auth = SaslGs2Krb5::new(SaslGs2Krb5Creds {
            authzid: Some("alice".to_string()),
            ..creds(SaslGs2ChannelBinding::Unsupported)
        });

        assert_eq!(respond(&mut auth, SaslArg::None), b"n,a=alice,first token");
    }

    #[test]
    fn a_bound_exchange_says_so_in_its_header_and_in_its_name() {
        let bound = SaslGs2ChannelBinding::Bound {
            kind: SaslGs2ChannelBindingKind::TlsExporter,
            data: b"binding".to_vec(),
        };
        let mut auth = SaslGs2Krb5::new(creds(bound));

        assert_eq!(auth.mechanism(), SaslMechanism::Gs2Krb5Plus);
        assert_eq!(
            respond(&mut auth, SaslArg::None),
            b"p=tls-exporter,,first token"
        );
    }

    #[test]
    fn a_client_supporting_binding_without_using_it_says_so() {
        // NOTE: the y flag, which is what lets a server supporting
        // channel binding notice that its -PLUS name was stripped in
        // flight. The name stays the plain one, since the exchange is
        // not bound.
        let mut auth = SaslGs2Krb5::new(creds(SaslGs2ChannelBinding::Unused));

        assert_eq!(auth.mechanism(), SaslMechanism::Gs2Krb5);
        assert_eq!(respond(&mut auth, SaslArg::None), b"y,,first token");
    }

    #[test]
    fn every_later_token_is_relayed_verbatim() {
        let mut auth = SaslGs2Krb5::new(creds(SaslGs2ChannelBinding::Unsupported));

        let _ = respond(&mut auth, SaslArg::None);

        for token in [&b"second"[..], b"third", b""] {
            assert_eq!(respond(&mut auth, SaslArg::Input(token)), token);
        }
    }

    #[test]
    fn peer_finished_completes_ok() {
        let mut auth = SaslGs2Krb5::new(creds(SaslGs2ChannelBinding::Unsupported));

        let _ = respond(&mut auth, SaslArg::None);

        assert!(matches!(
            auth.resume(SaslArg::Done),
            SaslCoroutineState::Complete(Ok(())),
        ));
    }

    #[test]
    fn a_resume_out_of_order_completes_err() {
        let mut auth = SaslGs2Krb5::new(creds(SaslGs2ChannelBinding::Unsupported));

        assert!(matches!(
            auth.resume(SaslArg::Input(b"token")),
            SaslCoroutineState::Complete(Err(SaslGs2Krb5Error::OutOfOrder)),
        ));

        let mut auth = SaslGs2Krb5::new(creds(SaslGs2ChannelBinding::Unsupported));

        let _ = respond(&mut auth, SaslArg::None);

        assert!(matches!(
            auth.resume(SaslArg::None),
            SaslCoroutineState::Complete(Err(SaslGs2Krb5Error::OutOfOrder)),
        ));
    }

    fn creds(channel_binding: SaslGs2ChannelBinding) -> SaslGs2Krb5Creds {
        SaslGs2Krb5Creds {
            token: b"first token".to_vec(),
            authzid: None,
            channel_binding,
        }
    }

    fn respond(auth: &mut SaslGs2Krb5, arg: SaslArg<'_>) -> Vec<u8> {
        match auth.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }
}
