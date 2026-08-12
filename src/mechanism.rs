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

#[cfg(feature = "cram-md5")]
use crate::rfc2195::cram_md5::SaslCramMd5Creds;
use crate::{
    login::SaslLoginCreds, rfc4422::external::SaslExternalCreds,
    rfc4505::anonymous::SaslAnonymousCreds, rfc4616::plain::SaslPlainCreds,
    rfc4752::gssapi::SaslGssapiCreds, rfc5801::gs2_krb5::SaslGs2Krb5Creds,
    rfc7628::oauthbearer::SaslOauthbearerCreds, xoauth2::SaslXoauth2Creds,
};

#[cfg(feature = "scram")]
use crate::rfc5802::SaslScramCreds;

/// Tag identifying a SASL mechanism without its credentials.
///
/// The tag stays complete whatever the crate was built with, since a
/// consumer reading a server capability list has to recognise the name
/// of a mechanism it cannot run in order to report it as unsupported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SaslMechanism {
    /// The ANONYMOUS mechanism (RFC 4505).
    Anonymous,
    /// The CRAM-MD5 mechanism (RFC 2195).
    CramMd5,
    /// The EXTERNAL mechanism (RFC 4422 appendix A).
    External,
    /// The GSSAPI mechanism, Kerberos V5 (RFC 4752).
    Gssapi,
    /// The GS2-KRB5 mechanism, Kerberos V5 through the GS2 bridge
    /// (RFC 5801).
    Gs2Krb5,
    /// The GS2-KRB5 mechanism with channel binding (RFC 5801).
    Gs2Krb5Plus,
    /// The legacy LOGIN mechanism.
    Login,
    /// The PLAIN mechanism (RFC 4616).
    Plain,
    /// The OAUTHBEARER mechanism (RFC 7628).
    OAuthBearer,
    /// The pre-standard Google XOAUTH2 mechanism.
    XOAuth2,
    /// The SCRAM-SHA-1 mechanism (RFC 5802).
    ScramSha1,
    /// The SCRAM-SHA-1 mechanism with channel binding (RFC 5802).
    ScramSha1Plus,
    /// The SCRAM-SHA-256 mechanism (RFC 7677).
    ScramSha256,
    /// The SCRAM-SHA-256 mechanism with channel binding (RFC 7677).
    ScramSha256Plus,
    /// The SCRAM-SHA-512 mechanism (draft-melnikov-scram-sha-512).
    ScramSha512,
    /// The SCRAM-SHA-512 mechanism with channel binding
    /// (draft-melnikov-scram-sha-512).
    ScramSha512Plus,
}

impl SaslMechanism {
    /// The mechanism name as registered with IANA and written on the
    /// wire.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Anonymous => "ANONYMOUS",
            Self::CramMd5 => "CRAM-MD5",
            Self::External => "EXTERNAL",
            Self::Gssapi => "GSSAPI",
            Self::Gs2Krb5 => "GS2-KRB5",
            Self::Gs2Krb5Plus => "GS2-KRB5-PLUS",
            Self::Login => "LOGIN",
            Self::Plain => "PLAIN",
            Self::OAuthBearer => "OAUTHBEARER",
            Self::XOAuth2 => "XOAUTH2",
            Self::ScramSha1 => "SCRAM-SHA-1",
            Self::ScramSha1Plus => "SCRAM-SHA-1-PLUS",
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::ScramSha256Plus => "SCRAM-SHA-256-PLUS",
            Self::ScramSha512 => "SCRAM-SHA-512",
            Self::ScramSha512Plus => "SCRAM-SHA-512-PLUS",
        }
    }
}

/// SASL credentials for a single authentication mechanism.
///
/// A mechanism the build left out has no variant here, since its
/// credentials describe an exchange this build cannot run: a consumer
/// mapping a configuration onto the enum reports the missing feature
/// where the user can act on it.
///
/// The `-PLUS` mechanisms have no variant of their own. A SCRAM profile
/// is one exchange registered under two names, and which name it runs
/// under follows from the
/// [`channel_binding`](crate::rfc5802::SaslScramCreds::channel_binding)
/// the credentials carry, so the variant names the profile and the
/// credentials name the binding.
#[derive(Clone, Debug)]
pub enum Sasl {
    /// ANONYMOUS credentials.
    Anonymous(SaslAnonymousCreds),
    /// CRAM-MD5 credentials.
    #[cfg(feature = "cram-md5")]
    #[cfg_attr(docsrs, doc(cfg(feature = "cram-md5")))]
    CramMd5(SaslCramMd5Creds),
    /// EXTERNAL credentials.
    External(SaslExternalCreds),
    /// GSSAPI credentials.
    Gssapi(SaslGssapiCreds),
    /// GS2-KRB5 credentials, plain or `-PLUS`.
    Gs2Krb5(SaslGs2Krb5Creds),
    /// LOGIN credentials.
    Login(SaslLoginCreds),
    /// PLAIN credentials.
    Plain(SaslPlainCreds),
    /// OAUTHBEARER credentials.
    Oauthbearer(SaslOauthbearerCreds),
    /// XOAUTH2 credentials.
    Xoauth2(SaslXoauth2Creds),
    /// SCRAM-SHA-1 credentials, plain or `-PLUS`.
    #[cfg(feature = "scram-sha-1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "scram-sha-1")))]
    ScramSha1(SaslScramCreds),
    /// SCRAM-SHA-256 credentials, plain or `-PLUS`.
    #[cfg(feature = "scram")]
    #[cfg_attr(docsrs, doc(cfg(feature = "scram")))]
    ScramSha256(SaslScramCreds),
    /// SCRAM-SHA-512 credentials, plain or `-PLUS`.
    #[cfg(feature = "scram")]
    #[cfg_attr(docsrs, doc(cfg(feature = "scram")))]
    ScramSha512(SaslScramCreds),
}

impl From<SaslAnonymousCreds> for Sasl {
    fn from(sasl: SaslAnonymousCreds) -> Self {
        Self::Anonymous(sasl)
    }
}

#[cfg(feature = "cram-md5")]
impl From<SaslCramMd5Creds> for Sasl {
    fn from(sasl: SaslCramMd5Creds) -> Self {
        Self::CramMd5(sasl)
    }
}

impl From<SaslExternalCreds> for Sasl {
    fn from(sasl: SaslExternalCreds) -> Self {
        Self::External(sasl)
    }
}

impl From<SaslGssapiCreds> for Sasl {
    fn from(sasl: SaslGssapiCreds) -> Self {
        Self::Gssapi(sasl)
    }
}

impl From<SaslGs2Krb5Creds> for Sasl {
    fn from(sasl: SaslGs2Krb5Creds) -> Self {
        Self::Gs2Krb5(sasl)
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

// NOTE: the three SCRAM profiles share one credential struct, so there
// is no From impl for it: the profile is the caller's choice, and an
// impl would have to guess which of the three variants it meant.

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use secrecy::SecretString;

    use crate::{
        login::SaslLoginCreds,
        mechanism::*,
        rfc4422::external::SaslExternalCreds,
        rfc4505::anonymous::SaslAnonymousCreds,
        rfc4616::plain::SaslPlainCreds,
        rfc4752::gssapi::SaslGssapiCreds,
        rfc5801::{SaslGs2ChannelBinding, gs2_krb5::SaslGs2Krb5Creds},
        rfc7628::oauthbearer::SaslOauthbearerCreds,
        xoauth2::SaslXoauth2Creds,
    };

    #[cfg(feature = "cram-md5")]
    use crate::rfc2195::cram_md5::SaslCramMd5Creds;

    #[cfg(feature = "scram")]
    use crate::rfc5802::SaslScramCreds;

    #[test]
    fn every_mechanism_spells_the_name_it_is_registered_under() {
        let mut named = Vec::new();

        for (mechanism, name) in names() {
            assert_eq!(mechanism.as_str(), name, "{mechanism:?}");

            assert!(
                !named.contains(&name),
                "{mechanism:?} answers to a name another mechanism already claims: {name}"
            );

            named.push(name);
        }
    }

    #[test]
    fn every_credential_type_lands_in_its_own_variant() {
        let mut occupied = Vec::new();

        for (mechanism, sasl) in vocabulary() {
            assert_eq!(variant(&sasl), mechanism, "{mechanism:?}");

            assert!(
                !occupied.contains(&mechanism),
                "{mechanism:?} shares its variant with another credential type"
            );

            occupied.push(mechanism);
        }
    }

    /// Every tag against the name it is registered under with IANA.
    ///
    /// One table walked rather than a test per mechanism, because the
    /// mistake a dozen near-identical arms actually make is not a
    /// missing one, it is two of them landing on the same place, which
    /// only a walk over all of them can see. The table is whole
    /// whatever the build enables, since so is the tag.
    fn names() -> [(SaslMechanism, &'static str); 16] {
        [
            (SaslMechanism::Anonymous, "ANONYMOUS"),
            (SaslMechanism::CramMd5, "CRAM-MD5"),
            (SaslMechanism::External, "EXTERNAL"),
            (SaslMechanism::Gssapi, "GSSAPI"),
            (SaslMechanism::Gs2Krb5, "GS2-KRB5"),
            (SaslMechanism::Gs2Krb5Plus, "GS2-KRB5-PLUS"),
            (SaslMechanism::Login, "LOGIN"),
            (SaslMechanism::Plain, "PLAIN"),
            (SaslMechanism::OAuthBearer, "OAUTHBEARER"),
            (SaslMechanism::XOAuth2, "XOAUTH2"),
            (SaslMechanism::ScramSha1, "SCRAM-SHA-1"),
            (SaslMechanism::ScramSha1Plus, "SCRAM-SHA-1-PLUS"),
            (SaslMechanism::ScramSha256, "SCRAM-SHA-256"),
            (SaslMechanism::ScramSha256Plus, "SCRAM-SHA-256-PLUS"),
            (SaslMechanism::ScramSha512, "SCRAM-SHA-512"),
            (SaslMechanism::ScramSha512Plus, "SCRAM-SHA-512-PLUS"),
        ]
    }

    /// Every mechanism this build carries credentials for, paired with
    /// the [`Sasl`] those credentials belong in.
    ///
    /// The `-PLUS` names are absent by construction: they share their
    /// profile's variant and differ only by the channel binding the
    /// credentials carry.
    fn vocabulary() -> Vec<(SaslMechanism, Sasl)> {
        let mut vocabulary = vec![
            (
                SaslMechanism::Anonymous,
                SaslAnonymousCreds { message: None }.into(),
            ),
            (
                SaslMechanism::External,
                SaslExternalCreds { authzid: None }.into(),
            ),
            #[cfg(feature = "cram-md5")]
            (
                SaslMechanism::CramMd5,
                SaslCramMd5Creds {
                    username: "alice".into(),
                    secret: SecretString::from("pencil"),
                }
                .into(),
            ),
            (
                SaslMechanism::Gssapi,
                SaslGssapiCreds {
                    token: b"token".to_vec(),
                }
                .into(),
            ),
            (
                SaslMechanism::Gs2Krb5,
                SaslGs2Krb5Creds {
                    token: b"token".to_vec(),
                    authzid: None,
                    channel_binding: SaslGs2ChannelBinding::Unsupported,
                }
                .into(),
            ),
            (
                SaslMechanism::Login,
                SaslLoginCreds {
                    username: "alice".into(),
                    password: SecretString::from("pencil"),
                }
                .into(),
            ),
            (
                SaslMechanism::Plain,
                SaslPlainCreds {
                    authzid: None,
                    authcid: "alice".into(),
                    passwd: SecretString::from("pencil"),
                }
                .into(),
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
            ),
            (
                SaslMechanism::XOAuth2,
                SaslXoauth2Creds {
                    username: "alice@localhost".into(),
                    token: SecretString::from("vF9dft4qmT"),
                }
                .into(),
            ),
        ];

        vocabulary.extend(scram_vocabulary());
        vocabulary
    }

    #[cfg(feature = "scram")]
    fn scram_vocabulary() -> Vec<(SaslMechanism, Sasl)> {
        let mut vocabulary = vec![
            (SaslMechanism::ScramSha256, Sasl::ScramSha256(scram_creds())),
            (SaslMechanism::ScramSha512, Sasl::ScramSha512(scram_creds())),
        ];

        #[cfg(feature = "scram-sha-1")]
        vocabulary.push((SaslMechanism::ScramSha1, Sasl::ScramSha1(scram_creds())));

        vocabulary
    }

    #[cfg(not(feature = "scram"))]
    fn scram_vocabulary() -> Vec<(SaslMechanism, Sasl)> {
        Vec::new()
    }

    #[cfg(feature = "scram")]
    fn scram_creds() -> SaslScramCreds {
        SaslScramCreds {
            username: "alice".into(),
            password: SecretString::from("pencil"),
            nonce: vec![],
            channel_binding: SaslGs2ChannelBinding::Unsupported,
        }
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
            #[cfg(feature = "cram-md5")]
            Sasl::CramMd5(_) => SaslMechanism::CramMd5,
            Sasl::External(_) => SaslMechanism::External,
            Sasl::Gssapi(_) => SaslMechanism::Gssapi,
            Sasl::Gs2Krb5(_) => SaslMechanism::Gs2Krb5,
            Sasl::Login(_) => SaslMechanism::Login,
            Sasl::Plain(_) => SaslMechanism::Plain,
            Sasl::Oauthbearer(_) => SaslMechanism::OAuthBearer,
            Sasl::Xoauth2(_) => SaslMechanism::XOAuth2,
            #[cfg(feature = "scram-sha-1")]
            Sasl::ScramSha1(_) => SaslMechanism::ScramSha1,
            #[cfg(feature = "scram")]
            Sasl::ScramSha256(_) => SaslMechanism::ScramSha256,
            #[cfg(feature = "scram")]
            Sasl::ScramSha512(_) => SaslMechanism::ScramSha512,
        }
    }
}
