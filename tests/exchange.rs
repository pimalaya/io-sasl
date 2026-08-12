//! The coroutine contract, driven the way a protocol crate drives it.
//!
//! The unit tests pin each mechanism's payloads against its own
//! specification, one mechanism at a time. What they cannot pin is the
//! part io-imap and io-smtp actually depend on: that every mechanism
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
//! completes on `PeerFinished`, and a SCRAM profile completes `Err` on it
//! unless the server signature was verified, which is what stops mutual
//! authentication from being skipped by omission. And a challenge
//! arriving after a mechanism has said its last word fails everywhere,
//! rather than being answered or mistaken for a success.

use core::fmt::Display;

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
    rfc5802::{
        SaslScramChannelBinding, SaslScramChannelBindingKind, SaslScramCreds, SaslScramError,
    },
    rfc7677::scram_sha_256::SaslScramSha256,
    scram_sha_512::SaslScramSha512,
};

#[cfg(feature = "scram-sha-1")]
use io_sasl::rfc5802::scram_sha_1::SaslScramSha1;

#[test]
fn every_mechanism_answers_start_with_an_initial_response() {
    for mut mechanism in mechanisms() {
        let name = mechanism.tag().as_str();

        // NOTE: none of the six is server-first, and a protocol crate
        // relies on that when it decides about SASL-IR: a mechanism
        // answering WantsChallenge here would need the command sent
        // without an initial response.
        match mechanism.step(SaslArg::None) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(_)) => {}
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
                    SaslCoroutineState::Yielded(SaslYield::WantsWrite(payload)),
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

        let _ = mechanism.step(SaslArg::None);

        match mechanism.step(SaslArg::Done) {
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
        let mut auth = SaslScramSha256::new(scram_creds(
            CLIENT_NONCE,
            SaslScramChannelBinding::Unsupported,
        ));

        let prefix = [SaslArg::None, SaslArg::Challenge(SERVER_FIRST)];

        for arg in prefix.into_iter().take(sent) {
            let _ = auth.resume(arg);
        }

        let completed = auth.resume(SaslArg::Done);
        let refused = matches!(
            completed,
            SaslCoroutineState::Complete(Err(SaslScramError::ServerSignatureNotVerified)),
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
            match mechanism.step(SaslArg::Challenge(b"{}")) {
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
type Exchange = (Box<dyn SaslExchange>, Vec<(SaslArg<'static>, Expect)>);

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
/// The mechanisms have unrelated error types, so a table over
/// all of them cannot name a single [`SaslCoroutine`]. Rendering the
/// error to its message erases the difference, and the message is what
/// a protocol crate surfaces anyway.
trait SaslExchange {
    /// The mechanism tag, used to name the mechanism in failures.
    fn tag(&self) -> SaslMechanism;

    /// Advances the exchange, keeping the failure as its message.
    fn step(&mut self, arg: SaslArg<'_>) -> SaslCoroutineState<SaslYield, Result<(), String>>;
}

impl<M> SaslExchange for M
where
    M: SaslCoroutine,
    M::Error: Display,
{
    fn tag(&self) -> SaslMechanism {
        self.mechanism()
    }

    fn step(&mut self, arg: SaslArg<'_>) -> SaslCoroutineState<SaslYield, Result<(), String>> {
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
        SaslMechanism::External => false,
        SaslMechanism::Login => false,
        SaslMechanism::Plain => false,
        SaslMechanism::OAuthBearer => false,
        SaslMechanism::XOAuth2 => false,
        SaslMechanism::ScramSha1 => true,
        SaslMechanism::ScramSha1Plus => true,
        SaslMechanism::ScramSha256 => true,
        SaslMechanism::ScramSha256Plus => true,
        SaslMechanism::ScramSha512 => true,
        SaslMechanism::ScramSha512Plus => true,
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
    let external = SaslExternalCreds {
        authzid: Some("alice@localhost".into()),
    };

    let mut exchanges: Vec<Exchange> = vec![
        (
            Box::new(SaslAnonymous::new(anonymous)),
            vec![
                (SaslArg::None, Expect::Responds(b"alice@localhost")),
                (SaslArg::Done, Expect::CompletesOk),
            ],
        ),
        (
            Box::new(SaslExternal::new(external)),
            vec![
                (SaslArg::None, Expect::Responds(b"alice@localhost")),
                (SaslArg::Done, Expect::CompletesOk),
            ],
        ),
        (
            Box::new(SaslLogin::new(login)),
            vec![
                (SaslArg::None, Expect::Responds(b"alice")),
                (
                    SaslArg::Challenge(b"Password:"),
                    Expect::Responds(b"pencil"),
                ),
                (SaslArg::Done, Expect::CompletesOk),
            ],
        ),
        (
            Box::new(SaslPlain::new(plain)),
            vec![
                (SaslArg::None, Expect::Responds(b"\0alice\0pencil")),
                (SaslArg::Done, Expect::CompletesOk),
            ],
        ),
        (
            Box::new(SaslOauthbearer::new(oauthbearer)),
            vec![
                (
                    SaslArg::None,
                    Expect::Responds(
                        b"n,a=user@example.com,\x01host=server.example.com\x01port=143\x01auth=Bearer vF9dft4qmT\x01\x01",
                    ),
                ),
                (SaslArg::Done, Expect::CompletesOk),
            ],
        ),
        (
            Box::new(SaslXoauth2::new(xoauth2)),
            vec![
                (
                    SaslArg::None,
                    Expect::Responds(b"user=someuser@example.com\x01auth=Bearer vF9dft4qmT\x01\x01"),
                ),
                (SaslArg::Done, Expect::CompletesOk),
            ],
        ),
    ];

    exchanges.extend(scram_exchange());
    exchanges
}

// NOTE: the exchange published in RFC 7677 section 3, for the user
// "user" with the password "pencil". The SHA-512 and -PLUS answers to
// it were derived from the RFC 5802 algorithm outside this crate, since
// no specification publishes either.
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
const SHA512_CLIENT_FINAL: &[u8] = b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=gMGXRcevScNtxZ6/8lQYpGtnsNAc3mGcmNomv+xnoOMw+3R2xNJdMNnzMlTN8PPC6wdp6dybEmDYXYTxwnYPJQ==";
#[cfg(feature = "scram")]
const SHA512_SERVER_FINAL: &[u8] =
    b"v=ZQnYEgWQMFmmsM8aQMF0nDDCy/AgCzkwk8CmMZYcMg0vSVlKDanekLtifDSeVGT4+5ZxXnJq199RVG2rR7N7Zw==";

#[cfg(feature = "scram")]
const BOUND_CLIENT_FIRST: &[u8] = b"p=tls-exporter,,n=user,r=rOprNGfwEbeRWgbNEkqO";
#[cfg(feature = "scram")]
const BOUND_CLIENT_FINAL: &[u8] = b"c=cD10bHMtZXhwb3J0ZXIsLAABAgMEBQYH,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=QAd7eifevIt6X/f2Cv9W4HLXcFLw7OayX8dQ2scckyI=";
#[cfg(feature = "scram")]
const BOUND_SERVER_FINAL: &[u8] = b"v=8dbpxwe4DaC4ESpY8u6aAvFeP2ks9+LClF/ADCxyWOE=";

// NOTE: the exchange published in RFC 5802 section 5, the only one the
// SHA-1 profile has of its own.
#[cfg(feature = "scram-sha-1")]
const SHA1_CLIENT_NONCE: &[u8] = b"fyko+d2lbbFgONRv9qkxdawL";
#[cfg(feature = "scram-sha-1")]
const SHA1_CLIENT_FIRST: &[u8] = b"n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL";
#[cfg(feature = "scram-sha-1")]
const SHA1_SERVER_FIRST: &[u8] =
    b"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";
#[cfg(feature = "scram-sha-1")]
const SHA1_CLIENT_FINAL: &[u8] =
    b"c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=";
#[cfg(feature = "scram-sha-1")]
const SHA1_SERVER_FINAL: &[u8] = b"v=rmF9pqV8S7suAoZWja4dJRkFsKQ=";

#[cfg(feature = "scram")]
fn scram_exchange() -> Vec<Exchange> {
    let bound = SaslScramChannelBinding::Bound {
        kind: SaslScramChannelBindingKind::TlsExporter,
        data: (0..8).collect(),
    };

    let mut exchanges: Vec<Exchange> = vec![
        (
            Box::new(SaslScramSha256::new(scram_creds(
                CLIENT_NONCE,
                SaslScramChannelBinding::Unsupported,
            ))),
            scram_script(CLIENT_FIRST, SERVER_FIRST, CLIENT_FINAL, SERVER_FINAL),
        ),
        (
            Box::new(SaslScramSha512::new(scram_creds(
                CLIENT_NONCE,
                SaslScramChannelBinding::Unsupported,
            ))),
            scram_script(
                CLIENT_FIRST,
                SERVER_FIRST,
                SHA512_CLIENT_FINAL,
                SHA512_SERVER_FINAL,
            ),
        ),
        // NOTE: the -PLUS name is not a mechanism of its own here, it is
        // the same coroutine with a binding in its credentials, so the
        // properties above cover it only if a bound exchange is in the
        // table too.
        (
            Box::new(SaslScramSha256::new(scram_creds(CLIENT_NONCE, bound))),
            scram_script(
                BOUND_CLIENT_FIRST,
                SERVER_FIRST,
                BOUND_CLIENT_FINAL,
                BOUND_SERVER_FINAL,
            ),
        ),
    ];

    exchanges.extend(scram_sha_1_exchange());
    exchanges
}

#[cfg(not(feature = "scram"))]
fn scram_exchange() -> Vec<Exchange> {
    Vec::new()
}

#[cfg(feature = "scram-sha-1")]
fn scram_sha_1_exchange() -> Vec<Exchange> {
    vec![(
        Box::new(SaslScramSha1::new(scram_creds(
            SHA1_CLIENT_NONCE,
            SaslScramChannelBinding::Unsupported,
        ))),
        scram_script(
            SHA1_CLIENT_FIRST,
            SHA1_SERVER_FIRST,
            SHA1_CLIENT_FINAL,
            SHA1_SERVER_FINAL,
        ),
    )]
}

#[cfg(all(feature = "scram", not(feature = "scram-sha-1")))]
fn scram_sha_1_exchange() -> Vec<Exchange> {
    Vec::new()
}

/// The four steps every SCRAM profile runs, which differ only in the
/// bytes each digest produces.
#[cfg(feature = "scram")]
fn scram_script(
    client_first: &'static [u8],
    server_first: &'static [u8],
    client_final: &'static [u8],
    server_final: &'static [u8],
) -> Vec<(SaslArg<'static>, Expect)> {
    vec![
        (SaslArg::None, Expect::Responds(client_first)),
        (
            SaslArg::Challenge(server_first),
            Expect::Responds(client_final),
        ),
        (SaslArg::Challenge(server_final), Expect::Responds(b"")),
        (SaslArg::Done, Expect::CompletesOk),
    ]
}

#[cfg(feature = "scram")]
fn scram_creds(nonce: &[u8], channel_binding: SaslScramChannelBinding) -> SaslScramCreds {
    SaslScramCreds {
        username: "user".into(),
        password: SecretString::from("pencil"),
        nonce: nonce.to_vec(),
        channel_binding,
    }
}
