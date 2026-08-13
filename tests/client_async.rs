#![cfg(feature = "client")]

//! The async command surface, and the one property it exists to keep.
//!
//! The exchange itself is the blocking file's, moved inside an async
//! block: what is worth testing twice is not the loop but the bound
//! around it. A plain `async fn` in a trait cannot promise its future is
//! `Send`, so this file would stop compiling if the explicit `impl
//! Future<..> + Send` return type or the `Send` supertrait were dropped
//! from `SaslClientAsync`, and `spawn` is what would break for the
//! consumer. The executor here is deliberately the smallest one that
//! exists, since the transport being faked, nothing ever pends.
//!
//! The sweep is the blocking file's too, and it is here for the same
//! reason it is there: the twelve bodies of one trait can reach the
//! wrong mechanism independently of the twelve of the other.

mod common;

use std::{
    collections::VecDeque,
    error::Error,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use io_sasl::{
    client::r#async::SaslClientAsync,
    coroutine::{SaslArg, SaslCoroutine, SaslCoroutineState, SaslYield},
    login::{SaslLoginCreds, SaslLoginError},
    mechanism::SaslMechanism,
};
use secrecy::SecretString;

/// Runs one surface method against a fresh sweep driver, awaits it, and
/// reports the mechanism it reached. The blocking twin of this file
/// carries the same macro, and for the same reason.
macro_rules! ran {
    ($method:ident($creds:expr)) => {{
        let mut sweep = Sweep::default();

        block_on(sweep.$method($creds)).unwrap();
        sweep.name.expect("the method ran no mechanism at all")
    }};
}

#[test]
fn default_body_runs_the_whole_exchange() {
    let mut peer = Peer {
        challenges: VecDeque::from([b"Password:".as_slice()]),
        responses: Vec::new(),
    };

    block_on(spawnable(peer.login(creds()))).unwrap();

    assert_eq!(peer.responses, [b"alice".to_vec(), b"pencil".to_vec()]);
}

#[test]
fn mechanism_failure_reaches_the_caller_through_its_own_error() {
    let challenges = [b"Password:".as_slice(), b"Password:".as_slice()];

    let mut peer = Peer {
        challenges: VecDeque::from(challenges),
        responses: Vec::new(),
    };

    let err = block_on(spawnable(peer.login(creds()))).unwrap_err();

    assert!(matches!(err, SaslLoginError::UnexpectedChallenge));
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

/// A driver whose only failure is the mechanism's, so the conversion
/// every default body asks for is the reflexive one.
struct Peer {
    challenges: VecDeque<&'static [u8]>,
    responses: Vec<Vec<u8>>,
}

impl SaslClientAsync for Peer {
    type Error = SaslLoginError;

    // NOTE: clippy suggests collapsing this into `async fn`, which is
    // precisely the shape the trait exists to avoid: an `async fn`
    // cannot state that its future is Send, so the assertions below
    // would stop compiling. Every implementation writes it out the long
    // way.
    #[allow(clippy::manual_async_fn)]
    fn run<C>(&mut self, mut mechanism: C) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        C: SaslCoroutine + Send,
        Self::Error: From<C::Error>,
    {
        async move {
            let mut arg = SaslArg::None;

            loop {
                match mechanism.resume(arg) {
                    SaslCoroutineState::Complete(result) => break Ok(result?),
                    SaslCoroutineState::Yielded(SaslYield::WantsWrite(response)) => {
                        self.responses.push(response);
                    }
                    SaslCoroutineState::Yielded(SaslYield::WantsRead) => {}
                }

                // NOTE: a real driver awaits its socket here, which is
                // what makes the Send proof non-trivial: the mechanism
                // is held across the await point.
                arg = match self.challenges.pop_front() {
                    Some(challenge) => SaslArg::Input(challenge),
                    None => SaslArg::Done,
                };
            }
        }
    }
}

/// Stands in for `tokio::spawn`, whose bound is what the trait's `Send`
/// declarations exist to satisfy.
fn spawnable<F: Future + Send>(future: F) -> F {
    future
}

/// The whole executor a faked transport needs: nothing ever pends, so
/// the first poll is the last one.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());

    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            break output;
        }
    }
}

fn creds() -> SaslLoginCreds {
    SaslLoginCreds {
        username: "alice".into(),
        password: SecretString::from("pencil"),
    }
}

/// The mechanism a surface method reached, the async twin of the sweep
/// driver in tests/client.rs, down to the boxed failure type.
#[derive(Default)]
struct Sweep {
    name: Option<SaslMechanism>,
}

impl SaslClientAsync for Sweep {
    type Error = Box<dyn Error + Send + Sync>;

    #[allow(clippy::manual_async_fn)]
    fn run<C>(&mut self, mechanism: C) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        C: SaslCoroutine + Send,
        Self::Error: From<C::Error>,
    {
        async move {
            self.name = Some(mechanism.mechanism());
            Ok(())
        }
    }
}
