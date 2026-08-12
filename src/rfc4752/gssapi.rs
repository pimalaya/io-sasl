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
//! knows; it does not verify anything, mutual authentication living
//! inside the tokens; and it does not assemble the security layer
//! negotiation of [RFC 4752 section 3.1], whose four octets and
//! authorization identity the caller wraps and unwraps itself. A
//! consumer wanting full GSSAPI writes that on top; what it does not
//! have to write again is the exchange around it.
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

use alloc::{borrow::ToOwned, vec::Vec};

use log::debug;
use thiserror::Error;

use crate::{coroutine::*, mechanism::SaslMechanism};

/// Failure causes of the GSSAPI exchange.
///
/// One variant, and it is about ordering rather than about content: a
/// relay cannot judge a token it is not equipped to read.
#[derive(Clone, Debug, Error)]
pub enum SaslGssapiError {
    /// The mechanism was resumed out of order: input before the initial
    /// token went out, or a fresh start in the middle of the exchange.
    #[error("SASL GSSAPI failed: resumed out of order")]
    OutOfOrder,
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
    use alloc::vec::Vec;

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
