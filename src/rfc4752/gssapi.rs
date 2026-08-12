//! The GSSAPI mechanism ([RFC 4752]), as far as a crate that performs
//! no I/O can carry it.
//!
//! Every other mechanism here computes what it sends. This one does
//! not: its messages are GSS-API tokens produced by a Kerberos
//! implementation that reads a credential cache, consults krb5.conf and
//! talks to a KDC over the network. None of that can happen inside an
//! I/O-free crate, and none of it can be hoisted into the credentials
//! either, since each token answers the one the peer just sent.
//!
//! So the coroutine is a relay. It holds the SASL half of the
//! mechanism, which is the part io-imap and io-smtp need: the name that
//! goes on the wire, the initial response, and the sequencing of who
//! speaks when. The caller holds the security context and does the
//! thinking, exactly as it holds the TLS session that SCRAM binds to.
//!
//! # What the caller owes it
//!
//! The first token, in [`SaslGssapiCreds::token`], obtained from its
//! context before the exchange starts. Then, for every peer message,
//! the caller feeds that message to its context and resumes with what
//! the context produced, not with what the peer said. The relay yields
//! it back as the next response.
//!
//! What this mechanism does not do follows from the same cut. It cannot
//! tell when the context is established, since only the GSS layer
//! knows, and it verifies nothing, mutual authentication living inside
//! the tokens.
//!
//! # The security layer negotiation
//!
//! What it does carry is the one message of the exchange that is SASL
//! rather than GSS: the four octets of [RFC 4752 section 3.1], a
//! bitmask of security layers and a maximum message size, with an
//! authorization identity after them.
//!
//! Those octets travel wrapped, so the relay never sees them.
//! [`SaslGssapiSecurityLayerOffer::parse`] reads the plaintext the
//! caller unwrapped, and [`SaslGssapiSecurityLayerChoice::to_bytes`]
//! assembles the plaintext it wraps in return; both are plain functions
//! rather than steps of the coroutine, since only the caller can move
//! bytes through its own context. Picking a layer other than
//! [`SaslGssapiSecurityLayer::None`] leaves every later message on that
//! connection wrapped, which is the caller's business too.
//!
//! # Example
//!
//! ```rust
//! use io_sasl::{
//!     coroutine::{SaslArg, SaslCoroutine, SaslCoroutineState, SaslYield},
//!     rfc4752::gssapi::{SaslGssapi, SaslGssapiCreds},
//! };
//!
//! // Stands in for the caller's Kerberos implementation, which is
//! // where every token in this exchange actually comes from.
//! fn gss_step(peer_token: &[u8]) -> Vec<u8> {
//!     let _ = peer_token;
//!     b"second token".to_vec()
//! }
//!
//! let mut auth = SaslGssapi::new(SaslGssapiCreds {
//!     token: b"first token".to_vec(),
//! });
//!
//! let state = auth.resume(SaslArg::None);
//!
//! let SaslCoroutineState::Yielded(SaslYield::WantsWrite(first)) = state else {
//!     panic!("expected the initial token");
//! };
//!
//! assert_eq!(first, b"first token");
//!
//! // The peer answered, so the caller advances its own context and
//! // resumes with the token that came out, never with the peer's.
//! let answer = gss_step(b"a token from the server");
//!
//! let state = auth.resume(SaslArg::Input(&answer));
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
//! [RFC 4752]: https://www.rfc-editor.org/rfc/rfc4752
//! [RFC 4752 section 3.1]: https://www.rfc-editor.org/rfc/rfc4752#section-3.1

use alloc::{borrow::ToOwned, string::String, vec::Vec};

use log::debug;
use thiserror::Error;

use crate::{coroutine::*, mechanism::SaslMechanism};

/// Failure causes of the GSSAPI exchange.
///
/// Ordering and shape, never content: a relay cannot judge a token it
/// is not equipped to read.
#[derive(Clone, Debug, Error)]
pub enum SaslGssapiError {
    /// The mechanism was resumed out of order: input before the initial
    /// token went out, or a fresh start in the middle of the exchange.
    #[error("SASL GSSAPI failed: resumed out of order")]
    OutOfOrder,
    /// The security layer offer was shorter than the four octets
    /// [RFC 4752 section 3.1] gives it.
    ///
    /// [RFC 4752 section 3.1]: https://www.rfc-editor.org/rfc/rfc4752#section-3.1
    #[error("SASL GSSAPI failed: truncated security layer offer")]
    TruncatedSecurityLayerOffer,
    /// The server offered no security layer this client could pick,
    /// its bitmask carrying none of the three defined bits.
    #[error("SASL GSSAPI failed: security layer offer carries no known layer")]
    UnknownSecurityLayerOffer,
}

/// A security layer the server offers over the authenticated
/// connection ([RFC 4752 section 3.1]).
///
/// [RFC 4752 section 3.1]: https://www.rfc-editor.org/rfc/rfc4752#section-3.1
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SaslGssapiSecurityLayer {
    /// No layer: the connection continues in clear once authenticated,
    /// which is the usual choice under TLS.
    None,
    /// Every later message is wrapped with integrity protection.
    Integrity,
    /// Every later message is wrapped with confidentiality protection.
    Confidentiality,
}

impl SaslGssapiSecurityLayer {
    /// The bit this layer occupies in the bitmask octet.
    pub fn bit(&self) -> u8 {
        match self {
            Self::None => 1,
            Self::Integrity => 2,
            Self::Confidentiality => 4,
        }
    }
}

/// What the server offers once the context is established: the layers
/// it supports, and the largest message it will accept.
///
/// The offer arrives wrapped, so the caller unwraps it with its own
/// security context and parses the plaintext here.
#[derive(Clone, Debug)]
pub struct SaslGssapiSecurityLayerOffer {
    /// The layers the server said it supports.
    pub layers: Vec<SaslGssapiSecurityLayer>,
    /// The largest message the server is willing to receive, zero when
    /// it offers no layer needing one.
    pub max_message_size: u32,
}

impl SaslGssapiSecurityLayerOffer {
    /// Parses the four octets of [RFC 4752 section 3.1]: a bitmask of
    /// layers, then the maximum message size in network byte order.
    ///
    /// [RFC 4752 section 3.1]: https://www.rfc-editor.org/rfc/rfc4752#section-3.1
    pub fn parse(unwrapped: &[u8]) -> Result<Self, SaslGssapiError> {
        let [mask, size @ ..] = unwrapped else {
            return Err(SaslGssapiError::TruncatedSecurityLayerOffer);
        };

        let [high, middle, low, ..] = size else {
            return Err(SaslGssapiError::TruncatedSecurityLayerOffer);
        };

        let offered = [
            SaslGssapiSecurityLayer::None,
            SaslGssapiSecurityLayer::Integrity,
            SaslGssapiSecurityLayer::Confidentiality,
        ];

        let layers: Vec<_> = offered
            .into_iter()
            .filter(|layer| mask & layer.bit() != 0)
            .collect();

        if layers.is_empty() {
            return Err(SaslGssapiError::UnknownSecurityLayerOffer);
        }

        let max_message_size = u32::from(*high) << 16 | u32::from(*middle) << 8 | u32::from(*low);

        Ok(Self {
            layers,
            max_message_size,
        })
    }
}

/// What the client answers the offer with: the one layer it picked, the
/// largest message it will accept in turn, and who it wants to act as.
///
/// The bytes go back through the caller's security context, which wraps
/// them, so this type stops at the plaintext.
#[derive(Clone, Debug)]
pub struct SaslGssapiSecurityLayerChoice {
    /// The layer the client picked, which SHOULD be one the offer
    /// carried.
    pub layer: SaslGssapiSecurityLayer,
    /// The largest message the client is willing to receive.
    pub max_message_size: u32,
    /// The optional authorization identity, sent as UTF-8 after the
    /// four octets.
    pub authzid: Option<String>,
}

impl SaslGssapiSecurityLayerChoice {
    /// Assembles the plaintext of the client's answer, the same four
    /// octets as the offer followed by the authorization identity.
    ///
    /// The size is truncated to the three octets the format gives it,
    /// since a client asking for more than 16 MiB per message cannot
    /// say so in this exchange.
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = self.max_message_size.min(0xff_ffff);

        let mut bytes = alloc::vec![
            self.layer.bit(),
            (size >> 16) as u8,
            (size >> 8) as u8,
            size as u8,
        ];

        if let Some(authzid) = &self.authzid {
            bytes.extend_from_slice(authzid.as_bytes());
        }

        bytes
    }
}

/// GSSAPI mechanism credentials ([RFC 4752]).
///
/// Not a credential in the sense the other mechanisms mean it: the
/// Kerberos credential stays in the caller's cache, and what travels
/// here is the first token its context produced.
///
/// [RFC 4752]: https://www.rfc-editor.org/rfc/rfc4752
#[derive(Clone, Debug)]
pub struct SaslGssapiCreds {
    /// The first GSS-API token, produced by the caller's security
    /// context before the exchange starts.
    pub token: Vec<u8>,
}

/// I/O-free SASL GSSAPI mechanism, relaying the tokens of a security
/// context the caller holds.
pub struct SaslGssapi {
    creds: SaslGssapiCreds,
    state: State,
}

impl SaslGssapi {
    /// Builds the mechanism from the first token of the caller's
    /// security context.
    pub fn new(creds: SaslGssapiCreds) -> Self {
        Self {
            creds,
            state: State::SendFirstToken,
        }
    }
}

impl SaslCoroutine for SaslGssapi {
    type Error = SaslGssapiError;

    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::Gssapi
    }

    fn resume(
        &mut self,
        arg: SaslArg<'_>,
    ) -> SaslCoroutineState<SaslYield, Result<(), Self::Error>> {
        match (&self.state, arg) {
            (_, SaslArg::Done) => {
                debug!("gssapi exchange completed");
                SaslCoroutineState::Complete(Ok(()))
            }
            (State::SendFirstToken, SaslArg::None) => {
                let token = self.creds.token.split_off(0);
                self.state = State::RelayToken;
                debug!("gssapi initial token sent");
                SaslCoroutineState::Yielded(SaslYield::WantsWrite(token))
            }
            // NOTE: the exchange has no fixed length. Only the caller's
            // security context knows that the handshake is over, so the
            // relay keeps forwarding for as long as it is fed, and the
            // peer ending the exchange is what stops it.
            (State::RelayToken, SaslArg::Input(token)) => {
                debug!("gssapi token relayed");
                SaslCoroutineState::Yielded(SaslYield::WantsWrite(token.to_owned()))
            }
            (_, _) => {
                let err = SaslGssapiError::OutOfOrder;
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

    use crate::{coroutine::*, rfc4752::gssapi::*};

    #[test]
    fn start_responds_with_the_initial_token() {
        let mut auth = SaslGssapi::new(creds());

        assert_eq!(respond(&mut auth, SaslArg::None), b"first token");
    }

    #[test]
    fn every_input_is_relayed_verbatim() {
        let mut auth = SaslGssapi::new(creds());

        let _ = respond(&mut auth, SaslArg::None);

        // NOTE: a relay puts no ceiling on the number of tokens, since
        // the round count belongs to the Kerberos mechanism the caller
        // negotiated rather than to the SASL exchange.
        for token in [&b"second"[..], b"third", b"fourth", b""] {
            assert_eq!(respond(&mut auth, SaslArg::Input(token)), token);
        }
    }

    #[test]
    fn peer_finished_completes_ok() {
        let mut auth = SaslGssapi::new(creds());

        let _ = respond(&mut auth, SaslArg::None);

        assert!(matches!(
            auth.resume(SaslArg::Done),
            SaslCoroutineState::Complete(Ok(())),
        ));
    }

    #[test]
    fn input_before_the_initial_token_completes_err() {
        let mut auth = SaslGssapi::new(creds());

        assert!(matches!(
            auth.resume(SaslArg::Input(b"token")),
            SaslCoroutineState::Complete(Err(SaslGssapiError::OutOfOrder)),
        ));
    }

    #[test]
    fn a_second_start_completes_err() {
        let mut auth = SaslGssapi::new(creds());

        let _ = respond(&mut auth, SaslArg::None);

        assert!(matches!(
            auth.resume(SaslArg::None),
            SaslCoroutineState::Complete(Err(SaslGssapiError::OutOfOrder)),
        ));
    }

    #[test]
    fn the_security_layer_offer_reads_its_four_octets() {
        // NOTE: every layer offered, and a maximum message size of
        // 0x010000, which is the shape a Kerberos server sends.
        let offer = SaslGssapiSecurityLayerOffer::parse(&[7, 1, 0, 0]).expect("a valid offer");

        assert_eq!(
            offer.layers,
            [
                SaslGssapiSecurityLayer::None,
                SaslGssapiSecurityLayer::Integrity,
                SaslGssapiSecurityLayer::Confidentiality,
            ],
        );
        assert_eq!(offer.max_message_size, 0x01_0000);

        let offer = SaslGssapiSecurityLayerOffer::parse(&[1, 0, 0, 0]).expect("a valid offer");

        assert_eq!(offer.layers, [SaslGssapiSecurityLayer::None]);
        assert_eq!(offer.max_message_size, 0);
    }

    #[test]
    fn a_malformed_security_layer_offer_completes_err() {
        assert!(matches!(
            SaslGssapiSecurityLayerOffer::parse(&[1, 0, 0]),
            Err(SaslGssapiError::TruncatedSecurityLayerOffer),
        ));

        assert!(matches!(
            SaslGssapiSecurityLayerOffer::parse(&[]),
            Err(SaslGssapiError::TruncatedSecurityLayerOffer),
        ));

        // NOTE: a bitmask carrying only bits the RFC never defined
        // leaves the client nothing to pick, which is a failure rather
        // than a silent choice of no layer.
        assert!(matches!(
            SaslGssapiSecurityLayerOffer::parse(&[8, 0, 0, 0]),
            Err(SaslGssapiError::UnknownSecurityLayerOffer),
        ));
    }

    #[test]
    fn the_choice_answers_with_the_same_four_octets_and_the_identity() {
        let choice = SaslGssapiSecurityLayerChoice {
            layer: SaslGssapiSecurityLayer::None,
            max_message_size: 0x01_0000,
            authzid: Some("alice".to_string()),
        };

        assert_eq!(choice.to_bytes(), b"\x01\x01\x00\x00alice");

        let choice = SaslGssapiSecurityLayerChoice {
            layer: SaslGssapiSecurityLayer::Confidentiality,
            max_message_size: 0,
            authzid: None,
        };

        assert_eq!(choice.to_bytes(), [4, 0, 0, 0]);
    }

    #[test]
    fn a_size_larger_than_the_format_is_truncated_to_it() {
        // NOTE: three octets cap the size at 16 MiB, and a client
        // asking for more has no way to say so; sending the low three
        // octets of a larger number would announce something smaller
        // than it means.
        let choice = SaslGssapiSecurityLayerChoice {
            layer: SaslGssapiSecurityLayer::Integrity,
            max_message_size: u32::MAX,
            authzid: None,
        };

        assert_eq!(choice.to_bytes(), [2, 0xff, 0xff, 0xff]);
    }

    fn creds() -> SaslGssapiCreds {
        SaslGssapiCreds {
            token: b"first token".to_vec(),
        }
    }

    fn respond(auth: &mut SaslGssapi, arg: SaslArg<'_>) -> Vec<u8> {
        match auth.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }
}
