//! The [SASL] vocabulary: the tag naming a mechanism, and the closed
//! set pairing a tag with the credentials of one.
//!
//! The credential structs themselves live with the mechanisms that
//! transmit them, one per mechanism module, since what a mechanism
//! needs is part of that mechanism. This module only gathers them into
//! the one set a consumer matches on. Protocol framing (`AUTHENTICATE
//! LOGIN`, the SMTP `AUTH` grammar, ...) lives in the consumer crate
//! (io-imap, io-smtp, io-pop3, ...).
//!
//! [SASL]: https://www.rfc-editor.org/rfc/rfc4422

use crate::{
    login::SaslLoginCreds, rfc4505::anonymous::SaslAnonymousCreds, rfc4616::plain::SaslPlainCreds,
    rfc7628::oauthbearer::SaslOauthbearerCreds, xoauth2::SaslXoauth2Creds,
};

#[cfg(feature = "scram")]
use crate::rfc7677::scram_sha_256::SaslScramSha256Creds;

/// Tag identifying a SASL mechanism without its credentials.
///
/// The tag stays complete whatever the crate was built with, since a
/// consumer reading a server capability list has to recognise the name
/// of a mechanism it cannot run in order to report it as unsupported.
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
///
/// A mechanism the build left out has no variant here, since its
/// credentials describe an exchange this build cannot run: a consumer
/// mapping a configuration onto the enum reports the missing feature
/// where the user can act on it.
#[derive(Clone, Debug)]
pub enum Sasl {
    /// ANONYMOUS credentials.
    Anonymous(SaslAnonymousCreds),
    /// LOGIN credentials.
    Login(SaslLoginCreds),
    /// PLAIN credentials.
    Plain(SaslPlainCreds),
    /// OAUTHBEARER credentials.
    Oauthbearer(SaslOauthbearerCreds),
    /// XOAUTH2 credentials.
    Xoauth2(SaslXoauth2Creds),
    /// SCRAM-SHA-256 credentials.
    #[cfg(feature = "scram")]
    #[cfg_attr(docsrs, doc(cfg(feature = "scram")))]
    ScramSha256(SaslScramSha256Creds),
}

impl From<SaslAnonymousCreds> for Sasl {
    fn from(sasl: SaslAnonymousCreds) -> Self {
        Self::Anonymous(sasl)
    }
}

impl From<SaslLoginCreds> for Sasl {
    fn from(sasl: SaslLoginCreds) -> Self {
        Self::Login(sasl)
    }
}

impl From<SaslPlainCreds> for Sasl {
    fn from(sasl: SaslPlainCreds) -> Self {
        Self::Plain(sasl)
    }
}

impl From<SaslOauthbearerCreds> for Sasl {
    fn from(sasl: SaslOauthbearerCreds) -> Self {
        Self::Oauthbearer(sasl)
    }
}

impl From<SaslXoauth2Creds> for Sasl {
    fn from(sasl: SaslXoauth2Creds) -> Self {
        Self::Xoauth2(sasl)
    }
}

#[cfg(feature = "scram")]
impl From<SaslScramSha256Creds> for Sasl {
    fn from(sasl: SaslScramSha256Creds) -> Self {
        Self::ScramSha256(sasl)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use secrecy::SecretString;

    use crate::{
        login::SaslLoginCreds, mechanism::*, rfc4505::anonymous::SaslAnonymousCreds,
        rfc4616::plain::SaslPlainCreds, rfc7628::oauthbearer::SaslOauthbearerCreds,
        xoauth2::SaslXoauth2Creds,
    };

    #[cfg(feature = "scram")]
    use crate::rfc7677::scram_sha_256::SaslScramSha256Creds;

    #[test]
    fn every_mechanism_spells_the_name_it_is_registered_under() {
        let mut named = Vec::new();

        for (mechanism, _, name) in vocabulary() {
            assert_eq!(mechanism.as_str(), name, "{mechanism:?}");

            assert!(
                !named.contains(&name),
                "{mechanism:?} answers to a name another mechanism already claims: {name}"
            );

            named.push(name);
        }
    }

    #[test]
    fn every_credential_type_converts_into_its_own_variant() {
        let mut converted = Vec::new();

        for (mechanism, sasl, _) in vocabulary() {
            assert_eq!(variant(&sasl), mechanism, "{mechanism:?}");

            assert!(
                !converted.contains(&mechanism),
                "{mechanism:?} shares its variant with another credential type"
            );

            converted.push(mechanism);
        }
    }

    /// The whole vocabulary: every tag, the credentials converting into
    /// it, and the name of the IANA SASL mechanism registry.
    ///
    /// One table walked twice rather than a test per mechanism, because
    /// the mistake six near-identical arms actually make is not a
    /// missing one, it is two of them landing on the same place, which
    /// only a walk over all of them can see.
    fn vocabulary() -> Vec<(SaslMechanism, Sasl, &'static str)> {
        let mut vocabulary = vec![
            (
                SaslMechanism::Anonymous,
                SaslAnonymousCreds { message: None }.into(),
                "ANONYMOUS",
            ),
            (
                SaslMechanism::Login,
                SaslLoginCreds {
                    username: "alice".into(),
                    password: SecretString::from("pencil"),
                }
                .into(),
                "LOGIN",
            ),
            (
                SaslMechanism::Plain,
                SaslPlainCreds {
                    authzid: None,
                    authcid: "alice".into(),
                    passwd: SecretString::from("pencil"),
                }
                .into(),
                "PLAIN",
            ),
            (
                SaslMechanism::OAuthBearer,
                SaslOauthbearerCreds {
                    username: "alice@localhost".into(),
                    host: "localhost".into(),
                    port: 143,
                    token: SecretString::from("vF9dft4qmT"),
                }
                .into(),
                "OAUTHBEARER",
            ),
            (
                SaslMechanism::XOAuth2,
                SaslXoauth2Creds {
                    username: "alice@localhost".into(),
                    token: SecretString::from("vF9dft4qmT"),
                }
                .into(),
                "XOAUTH2",
            ),
        ];

        vocabulary.extend(scram_vocabulary());
        vocabulary
    }

    #[cfg(feature = "scram")]
    fn scram_vocabulary() -> Vec<(SaslMechanism, Sasl, &'static str)> {
        vec![(
            SaslMechanism::ScramSha256,
            SaslScramSha256Creds {
                username: "alice".into(),
                password: SecretString::from("pencil"),
                nonce: vec![],
            }
            .into(),
            "SCRAM-SHA-256",
        )]
    }

    #[cfg(not(feature = "scram"))]
    fn scram_vocabulary() -> Vec<(SaslMechanism, Sasl, &'static str)> {
        Vec::new()
    }

    /// The tag of the variant a [`Sasl`] settled in.
    ///
    /// The match is what keeps the walk honest: a mechanism added to
    /// the vocabulary stops this module from compiling until it is
    /// given an arm, and the table above is the next thing the author
    /// reads.
    fn variant(sasl: &Sasl) -> SaslMechanism {
        match sasl {
            Sasl::Anonymous(_) => SaslMechanism::Anonymous,
            Sasl::Login(_) => SaslMechanism::Login,
            Sasl::Plain(_) => SaslMechanism::Plain,
            Sasl::Oauthbearer(_) => SaslMechanism::OAuthBearer,
            Sasl::Xoauth2(_) => SaslMechanism::XOAuth2,
            #[cfg(feature = "scram")]
            Sasl::ScramSha256(_) => SaslMechanism::ScramSha256,
        }
    }
}
