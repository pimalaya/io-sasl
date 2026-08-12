//! Protocol-agnostic [SASL] credential descriptors.
//!
//! Each variant carries only the bits the mechanism transmits on the
//! wire; protocol-specific framing (`AUTHENTICATE LOGIN`, the SMTP
//! `AUTH` grammar, ...) lives in the consumer crate (io-imap, io-smtp,
//! io-pop3, ...). [`SaslMechanism`] and [`Sasl`] are two views of one
//! closed set, the tag and the tag plus its credentials, so they live
//! together.
//!
//! [SASL]: https://www.rfc-editor.org/rfc/rfc4422

use alloc::{string::String, vec::Vec};

use secrecy::SecretString;

/// Tag identifying a SASL mechanism without its credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SaslMechanism {
    /// The ANONYMOUS mechanism (RFC 4505).
    Anonymous,
    /// The legacy LOGIN mechanism.
    Login,
    /// The PLAIN mechanism (RFC 4616).
    Plain,
    /// The OAUTHBEARER mechanism (RFC 7628).
    OAuthBearer,
    /// The pre-standard Google XOAUTH2 mechanism.
    XOAuth2,
    /// The SCRAM-SHA-256 mechanism (RFC 7677).
    ScramSha256,
}

impl SaslMechanism {
    /// The mechanism name as registered with IANA and written on the
    /// wire.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Anonymous => "ANONYMOUS",
            Self::Login => "LOGIN",
            Self::Plain => "PLAIN",
            Self::OAuthBearer => "OAUTHBEARER",
            Self::XOAuth2 => "XOAUTH2",
            Self::ScramSha256 => "SCRAM-SHA-256",
        }
    }
}

/// SASL credentials for a single authentication mechanism.
#[derive(Clone, Debug)]
pub enum Sasl {
    /// ANONYMOUS credentials.
    Anonymous(SaslAnonymous),
    /// LOGIN credentials.
    Login(SaslLogin),
    /// PLAIN credentials.
    Plain(SaslPlain),
    /// OAUTHBEARER credentials.
    Oauthbearer(SaslOauthbearer),
    /// XOAUTH2 credentials.
    Xoauth2(SaslXoauth2),
    /// SCRAM-SHA-256 credentials.
    ScramSha256(SaslScramSha256),
}

impl From<SaslAnonymous> for Sasl {
    fn from(sasl: SaslAnonymous) -> Self {
        Self::Anonymous(sasl)
    }
}

impl From<SaslLogin> for Sasl {
    fn from(sasl: SaslLogin) -> Self {
        Self::Login(sasl)
    }
}

impl From<SaslPlain> for Sasl {
    fn from(sasl: SaslPlain) -> Self {
        Self::Plain(sasl)
    }
}

impl From<SaslOauthbearer> for Sasl {
    fn from(sasl: SaslOauthbearer) -> Self {
        Self::Oauthbearer(sasl)
    }
}

impl From<SaslXoauth2> for Sasl {
    fn from(sasl: SaslXoauth2) -> Self {
        Self::Xoauth2(sasl)
    }
}

impl From<SaslScramSha256> for Sasl {
    fn from(sasl: SaslScramSha256) -> Self {
        Self::ScramSha256(sasl)
    }
}

/// ANONYMOUS mechanism credentials ([RFC 4505]).
///
/// Carries an optional trace token (typically an email-like string the
/// server can log); no secrets.
///
/// [RFC 4505]: https://www.rfc-editor.org/rfc/rfc4505
#[derive(Clone, Debug)]
pub struct SaslAnonymous {
    /// The optional trace token logged by the server.
    pub message: Option<String>,
}

/// LOGIN mechanism credentials ([draft-murchison-sasl-login]).
///
/// Legacy two-prompt cleartext scheme; also used as the credential
/// shape for protocol-level `LOGIN` commands (e.g. IMAP `LOGIN`,
/// [RFC 3501 section 6.2.3]).
///
/// [draft-murchison-sasl-login]: https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login-00
/// [RFC 3501 section 6.2.3]: https://www.rfc-editor.org/rfc/rfc3501#section-6.2.3
#[derive(Clone, Debug)]
pub struct SaslLogin {
    /// The login username.
    pub username: String,
    /// The login password.
    pub password: SecretString,
}

/// PLAIN mechanism credentials ([RFC 4616]).
///
/// Single-message scheme sending `authzid NUL authcid NUL password`;
/// `authzid` is optional.
///
/// [RFC 4616]: https://www.rfc-editor.org/rfc/rfc4616
#[derive(Clone, Debug)]
pub struct SaslPlain {
    /// The optional authorization identity.
    pub authzid: Option<String>,
    /// The authentication identity.
    pub authcid: String,
    /// The password.
    pub passwd: SecretString,
}

/// OAUTHBEARER mechanism credentials ([RFC 7628]).
///
/// `host` and `port` are sent verbatim in the GS2 header and should
/// match the server being contacted.
///
/// [RFC 7628]: https://www.rfc-editor.org/rfc/rfc7628
#[derive(Clone, Debug)]
pub struct SaslOauthbearer {
    /// The account username.
    pub username: String,
    /// The server host, sent verbatim in the GS2 header.
    pub host: String,
    /// The server port, sent verbatim in the GS2 header.
    pub port: u16,
    /// The OAuth 2.0 access token.
    pub token: SecretString,
}

/// XOAUTH2 mechanism credentials ([Google XOAUTH2]).
///
/// Pre-standard OAuth 2.0 SASL scheme; same shape as OAUTHBEARER minus
/// the GS2 host/port fields. Not IETF-standardised.
///
/// [Google XOAUTH2]: https://developers.google.com/gmail/imap/xoauth2-protocol
#[derive(Clone, Debug)]
pub struct SaslXoauth2 {
    /// The account username.
    pub username: String,
    /// The OAuth 2.0 access token.
    pub token: SecretString,
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
    /// [RFC 5802 section 5.1]: https://www.rfc-editor.org/rfc/rfc5802#section-5.1
    pub nonce: Vec<u8>,
}
