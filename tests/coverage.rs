//! A sweep over the tag every mechanism coroutine answers with.
//!
//! The six mechanisms live in six modules and each names itself from
//! one closed enum declared in a seventh, so nothing inside a module
//! can check that the two agree: the arm is written once, next to five
//! copies of itself, and read again only by a protocol crate. That is
//! what makes a crossed arm here worse than a wrong payload. The
//! mechanism tag is the word io-imap and io-smtp put on the wire, so a
//! SCRAM coroutine answering with the PLAIN tag sends AUTHENTICATE
//! PLAIN and then runs a SCRAM exchange inside it, and the exchange
//! that follows is wrong from its first byte with nothing in either
//! crate to say so.
//!
//! So the six are walked whole, each against the module it lives in and
//! against the other five. The point is not the coverage number; it is
//! that a typo in an arm nobody exercises has somewhere to fail.

use io_sasl::{
    coroutine::*,
    login::SaslAuthLogin,
    mechanism::{SaslAnonymous, SaslLogin, SaslMechanism, SaslOauthbearer, SaslPlain, SaslXoauth2},
    rfc4505::anonymous::SaslAuthAnonymous,
    rfc4616::plain::SaslAuthPlain,
    rfc7628::oauthbearer::SaslAuthOauthbearer,
    xoauth2::SaslAuthXoauth2,
};
use secrecy::SecretString;

#[cfg(feature = "scram")]
use io_sasl::{mechanism::SaslScramSha256, rfc7677::scram_sha_256::SaslAuthScramSha256};

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
    let anonymous = SaslAuthAnonymous::new(SaslAnonymous { message: None });
    let login = SaslAuthLogin::new(SaslLogin {
        username: "alice".into(),
        password: SecretString::from("pencil"),
    });
    let plain = SaslAuthPlain::new(SaslPlain {
        authzid: None,
        authcid: "alice".into(),
        passwd: SecretString::from("pencil"),
    });
    let oauthbearer = SaslAuthOauthbearer::new(SaslOauthbearer {
        username: "alice@localhost".into(),
        host: "localhost".into(),
        port: 143,
        token: SecretString::from("vF9dft4qmT"),
    });
    let xoauth2 = SaslAuthXoauth2::new(SaslXoauth2 {
        username: "alice@localhost".into(),
        token: SecretString::from("vF9dft4qmT"),
    });

    let mut walk = vec![
        (SaslMechanism::Anonymous, anonymous.mechanism()),
        (SaslMechanism::Login, login.mechanism()),
        (SaslMechanism::Plain, plain.mechanism()),
        (SaslMechanism::OAuthBearer, oauthbearer.mechanism()),
        (SaslMechanism::XOAuth2, xoauth2.mechanism()),
    ];

    walk.extend(scram());
    walk
}

#[cfg(feature = "scram")]
fn scram() -> Vec<(SaslMechanism, SaslMechanism)> {
    let scram = SaslAuthScramSha256::new(SaslScramSha256 {
        username: "alice".into(),
        password: SecretString::from("pencil"),
        nonce: b"rOprNGfwEbeRWgbNEkqO".to_vec(),
    });

    vec![(SaslMechanism::ScramSha256, scram.mechanism())]
}

#[cfg(not(feature = "scram"))]
fn scram() -> Vec<(SaslMechanism, SaslMechanism)> {
    Vec::new()
}
