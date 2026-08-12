//! The coroutine contract, driven the way a protocol crate drives it.
//!
//! The unit tests pin each mechanism's payloads against its own
//! specification, one mechanism at a time. What they cannot pin is the
//! part io-imap and io-smtp actually depend on: that all six mechanisms
//! behave identically at the edges of an exchange, so a single generic
//! driver can carry every one of them. So everything here goes through
//! the public API only, and every test is a property over the whole
//! mechanism set rather than a statement about one member of it, which
//! is what makes a seventh mechanism getting an edge wrong fail here
//! instead of in a protocol crate.
//!
//! Three of those properties are load-bearing. Every mechanism answers
//! the first resume with a response, which is what lets a protocol
//! decide whether to inline it as an initial response. Every mechanism
//! completes on `PeerFinished`, and SCRAM-SHA-256 completes `Err` on it
//! unless the server signature was verified, which is what stops mutual
//! authentication from being skipped by omission. And a challenge
//! arriving after a mechanism has said its last word fails everywhere,
//! rather than being answered or mistaken for a success.

use core::fmt::Display;

use io_sasl::{
    coroutine::*,
    login::{SaslLogin, SaslLoginCreds},
    mechanism::SaslMechanism,
    rfc4505::anonymous::{SaslAnonymous, SaslAnonymousCreds},
    rfc4616::plain::{SaslPlain, SaslPlainCreds},
    rfc7628::oauthbearer::{SaslOauthbearer, SaslOauthbearerCreds},
    xoauth2::{SaslXoauth2, SaslXoauth2Creds},
};
use secrecy::SecretString;

#[cfg(feature = "scram")]
use io_sasl::rfc7677::scram_sha_256::{
    SaslScramSha256, SaslScramSha256Creds, SaslScramSha256Error,
};

#[test]
fn every_mechanism_answers_start_with_an_initial_response() {
    for mut mechanism in mechanisms() {
        let name = mechanism.tag().as_str();

        // NOTE: none of the six is server-first, and a protocol crate
        // relies on that when it decides about SASL-IR: a mechanism
        // answering AwaitChallenge here would need the command sent
        // without an initial response.
        match mechanism.step(SaslResume::Start) {
            SaslCoroutineState::Yielded(SaslYield::Respond(_)) => {}
            state => panic!("{name} has no initial response: {state:?}"),
        }
    }
}

#[test]
fn every_exchange_yields_the_payloads_its_specification_defines() {
    for (mut mechanism, script) in exchanges() {
        let name = mechanism.tag().as_str();

        for (arg, expected) in script {
            let step = mechanism.step(arg);

            match (&step, &expected) {
                (
                    SaslCoroutineState::Yielded(SaslYield::Respond(payload)),
                    Expect::Responds(bytes),
                ) => {
                    assert_eq!(payload, bytes, "{name} sent an unexpected payload");
                }
                (SaslCoroutineState::Complete(Ok(())), Expect::CompletesOk) => {}
                _ => panic!("{name} was expected to {expected:?}, got {step:?}"),
            }
        }
    }
}

#[test]
fn peer_finished_completes_ok_unless_the_server_is_still_unproven() {
    for mut mechanism in mechanisms() {
        let tag = mechanism.tag();
        let name = tag.as_str();

        let _ = mechanism.step(SaslResume::Start);

        match mechanism.step(SaslResume::PeerFinished) {
            SaslCoroutineState::Complete(Ok(())) => {
                assert!(
                    !authenticates_the_server(tag),
                    "{name} accepted an exchange that ended before it verified the server"
                );
            }
            SaslCoroutineState::Complete(Err(err)) => {
                assert!(
                    authenticates_the_server(tag),
                    "{name} refused an exchange it had nothing left to verify: {err}"
                );
            }
            state => panic!("{name} did not complete on PeerFinished: {state:?}"),
        }
    }
}

#[cfg(feature = "scram")]
#[test]
fn scram_refuses_every_exchange_ending_before_the_server_proved_itself() {
    // NOTE: the three points at which a peer can end the exchange
    // early, taken as a prefix length: nothing sent yet, the
    // client-first-message sent, and the client-final-message sent but
    // the server-final-message never fed back. The last one is the case
    // both duplicated implementations got wrong.
    for sent in 0..3 {
        let mut auth = SaslScramSha256::new(scram_creds());

        let prefix = [SaslResume::Start, SaslResume::Challenge(SERVER_FIRST)];

        for arg in prefix.into_iter().take(sent) {
            let _ = auth.resume(arg);
        }

        let completed = auth.resume(SaslResume::PeerFinished);
        let refused = matches!(
            completed,
            SaslCoroutineState::Complete(Err(SaslScramSha256Error::ServerSignatureNotVerified)),
        );

        assert!(
            refused,
            "scram-sha-256 accepted an exchange ended after {sent} of its own messages: {completed:?}"
        );
    }
}

#[test]
fn an_extra_challenge_after_the_exchange_completes_unexpected_challenge() {
    for (mut mechanism, script) in exchanges() {
        let name = mechanism.tag().as_str();

        for (arg, _) in script {
            let _ = mechanism.step(arg);
        }

        // NOTE: OAUTHBEARER and XOAUTH2 read a challenge arriving after
        // their payload as the server's error JSON, and owe it one
        // acknowledgement before they can fail, so the refusal is
        // allowed a few steps. What may never happen is a second
        // success, or an endless conversation.
        let mut failure = None;

        for _ in 0..EXTRA_CHALLENGES {
            match mechanism.step(SaslResume::Challenge(b"{}")) {
                SaslCoroutineState::Yielded(_) => continue,
                SaslCoroutineState::Complete(Ok(())) => {
                    panic!("{name} answered a stray challenge with success")
                }
                SaslCoroutineState::Complete(Err(err)) => {
                    failure = Some(err);
                    break;
                }
            }
        }

        let err = failure.unwrap_or_else(|| panic!("{name} never refused the stray challenges"));

        assert!(
            err.contains("unexpected challenge"),
            "{name} refused the stray challenge for another reason: {err}"
        );
    }
}

/// How many stray challenges a mechanism may absorb before it is
/// expected to have failed.
const EXTRA_CHALLENGES: usize = 3;

/// One mechanism paired with the exchange it is expected to run.
type Exchange = (Box<dyn SaslExchange>, Vec<(SaslResume<'static>, Expect)>);

/// What a scripted step expects back from the mechanism.
#[derive(Debug)]
enum Expect {
    /// Yield exactly these bytes as the next response.
    Responds(&'static [u8]),
    /// Complete the exchange successfully.
    CompletesOk,
}

/// One mechanism driven through the object-safe half of its contract.
///
/// The six mechanisms have six unrelated error types, so a table over
/// all of them cannot name a single [`SaslCoroutine`]. Rendering the
/// error to its message erases the difference, and the message is what
/// a protocol crate surfaces anyway.
trait SaslExchange {
    /// The mechanism tag, used to name the mechanism in failures.
    fn tag(&self) -> SaslMechanism;

    /// Advances the exchange, keeping the failure as its message.
    fn step(&mut self, arg: SaslResume<'_>) -> SaslCoroutineState<SaslYield, Result<(), String>>;
}

impl<M> SaslExchange for M
where
    M: SaslCoroutine,
    M::Error: Display,
{
    fn tag(&self) -> SaslMechanism {
        self.mechanism()
    }

    fn step(&mut self, arg: SaslResume<'_>) -> SaslCoroutineState<SaslYield, Result<(), String>> {
        match self.resume(arg) {
            SaslCoroutineState::Yielded(yielded) => SaslCoroutineState::Yielded(yielded),
            SaslCoroutineState::Complete(completed) => {
                SaslCoroutineState::Complete(completed.map_err(|err| err.to_string()))
            }
        }
    }
}

/// Whether the mechanism proves the server as well as itself, and so
/// has something to lose when an exchange ends early.
///
/// The match is exhaustive on purpose: a mechanism added to the
/// vocabulary has to answer this question before the properties above
/// can run.
fn authenticates_the_server(mechanism: SaslMechanism) -> bool {
    match mechanism {
        SaslMechanism::Anonymous => false,
        SaslMechanism::Login => false,
        SaslMechanism::Plain => false,
        SaslMechanism::OAuthBearer => false,
        SaslMechanism::XOAuth2 => false,
        SaslMechanism::ScramSha256 => true,
    }
}

fn mechanisms() -> impl Iterator<Item = Box<dyn SaslExchange>> {
    exchanges().into_iter().map(|(mechanism, _)| mechanism)
}

fn exchanges() -> Vec<Exchange> {
    let anonymous = SaslAnonymousCreds {
        message: Some("alice@localhost".into()),
    };
    let login = SaslLoginCreds {
        username: "alice".into(),
        password: SecretString::from("pencil"),
    };
    let plain = SaslPlainCreds {
        authzid: None,
        authcid: "alice".into(),
        passwd: SecretString::from("pencil"),
    };
    let oauthbearer = SaslOauthbearerCreds {
        username: "user@example.com".into(),
        host: "server.example.com".into(),
        port: 143,
        token: SecretString::from("vF9dft4qmT"),
    };
    let xoauth2 = SaslXoauth2Creds {
        username: "someuser@example.com".into(),
        token: SecretString::from("vF9dft4qmT"),
    };

    let mut exchanges: Vec<Exchange> = vec![
        (
            Box::new(SaslAnonymous::new(anonymous)),
            vec![
                (SaslResume::Start, Expect::Responds(b"alice@localhost")),
                (SaslResume::PeerFinished, Expect::CompletesOk),
            ],
        ),
        (
            Box::new(SaslLogin::new(login)),
            vec![
                (SaslResume::Start, Expect::Responds(b"alice")),
                (
                    SaslResume::Challenge(b"Password:"),
                    Expect::Responds(b"pencil"),
                ),
                (SaslResume::PeerFinished, Expect::CompletesOk),
            ],
        ),
        (
            Box::new(SaslPlain::new(plain)),
            vec![
                (SaslResume::Start, Expect::Responds(b"\0alice\0pencil")),
                (SaslResume::PeerFinished, Expect::CompletesOk),
            ],
        ),
        (
            Box::new(SaslOauthbearer::new(oauthbearer)),
            vec![
                (
                    SaslResume::Start,
                    Expect::Responds(
                        b"n,a=user@example.com,\x01host=server.example.com\x01port=143\x01auth=Bearer vF9dft4qmT\x01\x01",
                    ),
                ),
                (SaslResume::PeerFinished, Expect::CompletesOk),
            ],
        ),
        (
            Box::new(SaslXoauth2::new(xoauth2)),
            vec![
                (
                    SaslResume::Start,
                    Expect::Responds(b"user=someuser@example.com\x01auth=Bearer vF9dft4qmT\x01\x01"),
                ),
                (SaslResume::PeerFinished, Expect::CompletesOk),
            ],
        ),
    ];

    exchanges.extend(scram_exchange());
    exchanges
}

// NOTE: the exchange published in RFC 7677 section 3, for the user
// "user" with the password "pencil".
#[cfg(feature = "scram")]
const CLIENT_NONCE: &[u8] = b"rOprNGfwEbeRWgbNEkqO";
#[cfg(feature = "scram")]
const CLIENT_FIRST: &[u8] = b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
#[cfg(feature = "scram")]
const SERVER_FIRST: &[u8] =
    b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
#[cfg(feature = "scram")]
const CLIENT_FINAL: &[u8] = b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
#[cfg(feature = "scram")]
const SERVER_FINAL: &[u8] = b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

#[cfg(feature = "scram")]
fn scram_exchange() -> Vec<Exchange> {
    vec![(
        Box::new(SaslScramSha256::new(scram_creds())),
        vec![
            (SaslResume::Start, Expect::Responds(CLIENT_FIRST)),
            (
                SaslResume::Challenge(SERVER_FIRST),
                Expect::Responds(CLIENT_FINAL),
            ),
            (SaslResume::Challenge(SERVER_FINAL), Expect::Responds(b"")),
            (SaslResume::PeerFinished, Expect::CompletesOk),
        ],
    )]
}

#[cfg(not(feature = "scram"))]
fn scram_exchange() -> Vec<Exchange> {
    Vec::new()
}

#[cfg(feature = "scram")]
fn scram_creds() -> SaslScramSha256Creds {
    SaslScramSha256Creds {
        username: "user".into(),
        password: SecretString::from("pencil"),
        nonce: CLIENT_NONCE.to_vec(),
    }
}
