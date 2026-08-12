//! A sweep over the tag every mechanism coroutine answers with.
//!
//! The mechanisms live one per module and each names itself from one
//! closed enum declared elsewhere, so nothing inside a module can check
//! that the two agree: the arm is written once, next to a dozen copies
//! of itself, and read again only by a protocol crate. That is what
//! makes a crossed arm here worse than a wrong payload. The mechanism
//! tag is the word io-imap and io-smtp put on the wire, so a SCRAM
//! coroutine answering with the PLAIN tag sends AUTHENTICATE PLAIN and
//! then runs a SCRAM exchange inside it, and the exchange that follows
//! is wrong from its first byte with nothing in either crate to say so.
//!
//! So every mechanism is walked whole, each against the module it lives
//! in and against all the others, and the SCRAM profiles twice, since a
//! profile reports one name or its `-PLUS` twin depending on the
//! credentials it was built from. The point is not the coverage number;
//! it is that a typo in an arm nobody exercises has somewhere to fail.

use io_sasl::{
    coroutine::*,
    login::{SaslLogin, SaslLoginCreds},
    mechanism::SaslMechanism,
    rfc4422::external::{SaslExternal, SaslExternalCreds},
    rfc4505::anonymous::{SaslAnonymous, SaslAnonymousCreds},
    rfc4616::plain::{SaslPlain, SaslPlainCreds},
    rfc7628::oauthbearer::{SaslOauthbearer, SaslOauthbearerCreds},
    xoauth2::{SaslXoauth2, SaslXoauth2Creds},
};
use secrecy::SecretString;

#[cfg(feature = "scram")]
use io_sasl::{
    rfc5802::{SaslScramChannelBinding, SaslScramChannelBindingKind, SaslScramCreds},
    rfc7677::scram_sha_256::SaslScramSha256,
    scram_sha_512::SaslScramSha512,
};

#[cfg(feature = "scram-sha-1")]
use io_sasl::rfc5802::scram_sha_1::SaslScramSha1;

#[test]
fn every_coroutine_answers_with_the_tag_of_the_module_it_lives_in() {
    let mut answered = Vec::new();

    for (module, reported) in walk() {
        assert_eq!(
            reported, module,
            "the {module:?} mechanism names itself {reported:?} on the wire"
        );

        assert!(
            !answered.contains(&reported),
            "{module:?} answers with a tag another mechanism already answers with"
        );

        answered.push(reported);
    }
}

/// Every mechanism paired with the tag its coroutine reports: the
/// module it lives in on the left, what it calls itself on the right.
fn walk() -> Vec<(SaslMechanism, SaslMechanism)> {
    let anonymous = SaslAnonymous::new(SaslAnonymousCreds { message: None });
    let login = SaslLogin::new(SaslLoginCreds {
        username: "alice".into(),
        password: SecretString::from("pencil"),
    });
    let plain = SaslPlain::new(SaslPlainCreds {
        authzid: None,
        authcid: "alice".into(),
        passwd: SecretString::from("pencil"),
    });
    let oauthbearer = SaslOauthbearer::new(SaslOauthbearerCreds {
        username: "alice@localhost".into(),
        host: "localhost".into(),
        port: 143,
        token: SecretString::from("vF9dft4qmT"),
    });
    let xoauth2 = SaslXoauth2::new(SaslXoauth2Creds {
        username: "alice@localhost".into(),
        token: SecretString::from("vF9dft4qmT"),
    });
    let external = SaslExternal::new(SaslExternalCreds { authzid: None });

    let mut walk = vec![
        (SaslMechanism::Anonymous, anonymous.mechanism()),
        (SaslMechanism::External, external.mechanism()),
        (SaslMechanism::Login, login.mechanism()),
        (SaslMechanism::Plain, plain.mechanism()),
        (SaslMechanism::OAuthBearer, oauthbearer.mechanism()),
        (SaslMechanism::XOAuth2, xoauth2.mechanism()),
    ];

    walk.extend(scram());
    walk
}

/// The SCRAM profiles, each walked twice.
///
/// A profile is one coroutine registered under two names, so the tag it
/// reports depends on the credentials it was built from rather than on
/// its type alone. That is one more way for an arm to be crossed, and
/// the only place it can be caught is here.
#[cfg(feature = "scram")]
fn scram() -> Vec<(SaslMechanism, SaslMechanism)> {
    let sha256 = SaslScramSha256::new(scram_creds(SaslScramChannelBinding::Unsupported));
    let sha256_plus = SaslScramSha256::new(scram_creds(bound()));
    let sha512 = SaslScramSha512::new(scram_creds(SaslScramChannelBinding::Unsupported));
    let sha512_plus = SaslScramSha512::new(scram_creds(bound()));

    let mut walk = vec![
        (SaslMechanism::ScramSha256, sha256.mechanism()),
        (SaslMechanism::ScramSha256Plus, sha256_plus.mechanism()),
        (SaslMechanism::ScramSha512, sha512.mechanism()),
        (SaslMechanism::ScramSha512Plus, sha512_plus.mechanism()),
    ];

    walk.extend(scram_sha_1());
    walk
}

#[cfg(not(feature = "scram"))]
fn scram() -> Vec<(SaslMechanism, SaslMechanism)> {
    Vec::new()
}

#[cfg(feature = "scram-sha-1")]
fn scram_sha_1() -> Vec<(SaslMechanism, SaslMechanism)> {
    let sha1 = SaslScramSha1::new(scram_creds(SaslScramChannelBinding::Unsupported));
    let sha1_plus = SaslScramSha1::new(scram_creds(bound()));

    vec![
        (SaslMechanism::ScramSha1, sha1.mechanism()),
        (SaslMechanism::ScramSha1Plus, sha1_plus.mechanism()),
    ]
}

#[cfg(all(feature = "scram", not(feature = "scram-sha-1")))]
fn scram_sha_1() -> Vec<(SaslMechanism, SaslMechanism)> {
    Vec::new()
}

#[cfg(feature = "scram")]
fn bound() -> SaslScramChannelBinding {
    SaslScramChannelBinding::Bound {
        kind: SaslScramChannelBindingKind::TlsExporter,
        data: b"binding".to_vec(),
    }
}

#[cfg(feature = "scram")]
fn scram_creds(channel_binding: SaslScramChannelBinding) -> SaslScramCreds {
    SaslScramCreds {
        username: "alice".into(),
        password: SecretString::from("pencil"),
        nonce: b"rOprNGfwEbeRWgbNEkqO".to_vec(),
        channel_binding,
    }
}
