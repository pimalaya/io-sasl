//! Credentials for every mechanism the build carries, shared by the two
//! command surface files so that the sweep each of them runs walks the
//! same set.
//!
//! The values are the ones the mechanism tests use where a
//! specification publishes them, since nothing here asserts on a
//! payload: what these drive is the surface, and a mechanism reached
//! through the wrong method names itself wrong whatever its credentials
//! were.

#[cfg(feature = "cram-md5")]
use io_sasl::rfc2195::cram_md5::SaslCramMd5Creds;
use io_sasl::{
    login::SaslLoginCreds,
    rfc4422::external::SaslExternalCreds,
    rfc4505::anonymous::SaslAnonymousCreds,
    rfc4616::plain::SaslPlainCreds,
    rfc4752::gssapi::SaslGssapiCreds,
    rfc5801::{SaslGs2ChannelBinding, gs2_krb5::SaslGs2Krb5Creds},
    rfc7628::oauthbearer::SaslOauthbearerCreds,
    xoauth2::SaslXoauth2Creds,
};
use secrecy::SecretString;

#[cfg(feature = "scram")]
use io_sasl::rfc5802::SaslScramCreds;

pub fn anonymous() -> SaslAnonymousCreds {
    SaslAnonymousCreds {
        message: Some("alice@localhost".into()),
    }
}

#[cfg(feature = "cram-md5")]
pub fn cram_md5() -> SaslCramMd5Creds {
    SaslCramMd5Creds {
        username: "alice".into(),
        secret: SecretString::from("pencil"),
    }
}

pub fn external() -> SaslExternalCreds {
    SaslExternalCreds {
        authzid: Some("alice@localhost".into()),
    }
}

pub fn gssapi() -> SaslGssapiCreds {
    SaslGssapiCreds {
        token: b"first token".to_vec(),
    }
}

pub fn gs2_krb5() -> SaslGs2Krb5Creds {
    SaslGs2Krb5Creds {
        token: b"first token".to_vec(),
        authzid: None,
        channel_binding: SaslGs2ChannelBinding::Unsupported,
    }
}

pub fn login() -> SaslLoginCreds {
    SaslLoginCreds {
        username: "alice".into(),
        password: SecretString::from("pencil"),
    }
}

pub fn plain() -> SaslPlainCreds {
    SaslPlainCreds {
        authzid: None,
        authcid: "alice".into(),
        passwd: SecretString::from("pencil"),
    }
}

pub fn oauthbearer() -> SaslOauthbearerCreds {
    SaslOauthbearerCreds {
        username: "alice@localhost".into(),
        host: "localhost".into(),
        port: 143,
        token: SecretString::from("vF9dft4qmT"),
    }
}

pub fn xoauth2() -> SaslXoauth2Creds {
    SaslXoauth2Creds {
        username: "alice@localhost".into(),
        token: SecretString::from("vF9dft4qmT"),
    }
}

#[cfg(feature = "scram")]
pub fn scram() -> SaslScramCreds {
    SaslScramCreds {
        username: "alice".into(),
        password: SecretString::from("pencil"),
        nonce: b"rOprNGfwEbeRWgbNEkqO".to_vec(),
        channel_binding: SaslGs2ChannelBinding::Unsupported,
    }
}
