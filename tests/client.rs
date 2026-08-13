#![cfg(feature = "client")]

//! The blocking command surface, implemented the way a protocol crate
//! implements it: one `run` over a transport the driver does not own.
//!
//! What the doctest on the trait shows once, this file states as the
//! three claims the surface rests on. A default body runs the whole
//! exchange, so a protocol crate calling `login` writes no loop of its
//! own. A mechanism failure reaches the caller through the driver's own
//! error type, which is what the `From` bound on each default body buys.
//! And the driver's own failures travel the same channel, which is why
//! the error is an associated type here rather than one this crate owns:
//! both kinds live in the type the implementation already has.
//!
//! The fourth is a sweep rather than a claim about one method, for the
//! reason the vocabulary sweep exists: what a dozen near-identical
//! one-line bodies get wrong is not a missing one, it is two of them
//! reaching the same mechanism, and only walking all of them can see
//! it.

mod common;

use std::{collections::VecDeque, error::Error};

use io_sasl::{
    client::std::SaslClient,
    coroutine::{SaslArg, SaslCoroutine, SaslCoroutineState, SaslYield},
    login::{SaslLoginCreds, SaslLoginError},
    mechanism::SaslMechanism,
};
use secrecy::SecretString;

/// Runs one surface method against a fresh sweep driver, and reports
/// the mechanism it reached.
///
/// A macro rather than a function, since a closure handing back a
/// value borrowed from the driver it was given has no signature that
/// spells out, and the async twin of this file would need another one
/// still.
macro_rules! ran {
    ($method:ident($creds:expr)) => {{
        let mut sweep = Sweep::default();

        sweep.$method($creds).unwrap();
        sweep.name.expect("the method ran no mechanism at all")
    }};
}

#[test]
fn default_body_runs_the_whole_exchange() {
    let mut responses = Vec::new();
    let mut peer = peer(
        &mut responses,
        [Reply::Challenge(b"Password:"), Reply::Success],
    );

    peer.login(creds()).unwrap();

    assert_eq!(peer.name, Some(SaslMechanism::Login));
    assert_eq!(responses, [b"alice".to_vec(), b"pencil".to_vec()]);
}

#[test]
fn mechanism_failure_reaches_the_caller_through_its_own_error() {
    let replies = [
        Reply::Challenge(b"Password:"),
        Reply::Challenge(b"Password:"),
    ];

    let mut responses = Vec::new();
    let mut peer = peer(&mut responses, replies);

    let err = peer.login(creds()).unwrap_err();

    assert!(matches!(
        err,
        PeerError::Login(SaslLoginError::UnexpectedChallenge),
    ));
}

#[test]
fn driver_failure_travels_the_same_channel() {
    let mut responses = Vec::new();
    let mut peer = peer(&mut responses, []);

    let err = peer.login(creds()).unwrap_err();

    assert!(matches!(err, PeerError::Disconnected));
}

#[test]
fn every_surface_method_runs_the_mechanism_it_names() {
    assert_eq!(
        ran!(anonymous(common::anonymous())),
        SaslMechanism::Anonymous,
    );

    #[cfg(feature = "cram-md5")]
    assert_eq!(ran!(cram_md5(common::cram_md5())), SaslMechanism::CramMd5,);

    assert_eq!(ran!(external(common::external())), SaslMechanism::External,);

    assert_eq!(ran!(gssapi(common::gssapi())), SaslMechanism::Gssapi,);

    assert_eq!(ran!(gs2_krb5(common::gs2_krb5())), SaslMechanism::Gs2Krb5,);

    assert_eq!(ran!(login(common::login())), SaslMechanism::Login);
    assert_eq!(ran!(plain(common::plain())), SaslMechanism::Plain);

    assert_eq!(
        ran!(oauthbearer(common::oauthbearer())),
        SaslMechanism::OAuthBearer,
    );

    assert_eq!(ran!(xoauth2(common::xoauth2())), SaslMechanism::XOAuth2,);

    #[cfg(feature = "scram-sha-1")]
    assert_eq!(ran!(scram_sha_1(common::scram())), SaslMechanism::ScramSha1,);

    #[cfg(feature = "scram")]
    assert_eq!(
        ran!(scram_sha_256(common::scram())),
        SaslMechanism::ScramSha256,
    );

    #[cfg(feature = "scram")]
    assert_eq!(
        ran!(scram_sha_512(common::scram())),
        SaslMechanism::ScramSha512,
    );
}

// --- utils

/// What the peer says after a response: another challenge, or the
/// success reply that ends the exchange.
enum Reply {
    Challenge(&'static [u8]),
    Success,
}

/// What the driver reports: the mechanism's failures, and its own.
#[derive(Debug)]
enum PeerError {
    Login(SaslLoginError),
    Disconnected,
}

impl From<SaslLoginError> for PeerError {
    fn from(err: SaslLoginError) -> Self {
        Self::Login(err)
    }
}

/// A driver owning no transport: it borrows the buffer it writes to for
/// the exchange, standing in for the socket a protocol crate frames its
/// commands over.
struct Peer<'a> {
    replies: VecDeque<Reply>,
    responses: &'a mut Vec<Vec<u8>>,
    /// The mechanism the exchange opened with, which a protocol crate
    /// writes into its authentication command.
    name: Option<SaslMechanism>,
}

impl SaslClient for Peer<'_> {
    type Error = PeerError;

    fn run<C>(&mut self, mut mechanism: C) -> Result<(), Self::Error>
    where
        C: SaslCoroutine,
        Self::Error: From<C::Error>,
    {
        self.name = Some(mechanism.mechanism());

        let mut arg = SaslArg::None;

        loop {
            match mechanism.resume(arg) {
                SaslCoroutineState::Complete(result) => break Ok(result?),
                SaslCoroutineState::Yielded(SaslYield::WantsWrite(response)) => {
                    self.responses.push(response);
                }
                SaslCoroutineState::Yielded(SaslYield::WantsRead) => {}
            }

            arg = match self.replies.pop_front() {
                Some(Reply::Challenge(challenge)) => SaslArg::Input(challenge),
                Some(Reply::Success) => SaslArg::Done,
                None => break Err(PeerError::Disconnected),
            };
        }
    }
}

fn peer<'a>(responses: &'a mut Vec<Vec<u8>>, replies: impl IntoIterator<Item = Reply>) -> Peer<'a> {
    Peer {
        replies: replies.into_iter().collect(),
        responses,
        name: None,
    }
}

fn creds() -> SaslLoginCreds {
    SaslLoginCreds {
        username: "alice".into(),
        password: SecretString::from("pencil"),
    }
}

/// The mechanism a surface method reached, which is all the sweep asks
/// for: naming it is what a driver does before it writes anything, so a
/// method landing on the wrong coroutine is caught before any payload
/// is computed.
///
/// The failure type is a boxed error rather than an enum of twelve, the
/// standard library already converting every mechanism failure into
/// one, which is also the shortest demonstration that the `From` bound
/// each method carries costs a driver nothing it does not already have.
#[derive(Default)]
struct Sweep {
    name: Option<SaslMechanism>,
}

impl SaslClient for Sweep {
    type Error = Box<dyn Error>;

    fn run<C>(&mut self, mechanism: C) -> Result<(), Self::Error>
    where
        C: SaslCoroutine,
        Self::Error: From<C::Error>,
    {
        self.name = Some(mechanism.mechanism());
        Ok(())
    }
}
