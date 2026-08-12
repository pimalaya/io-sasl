#![no_main]

//! Coverage-guided fuzz target for the six mechanisms. One oracle,
//! applied uniformly: whatever a peer says, at whatever point it says
//! it, a mechanism must answer or fail, never panic.
//!
//! Both shapes of the question are asked. A single arbitrary challenge
//! goes to a mechanism that has not started yet, which is the
//! out-of-order case a hostile or broken server produces, and then a
//! whole sequence of challenges goes to a mechanism driven from its
//! initial response, which is the case a protocol crate produces. The
//! credentials are fuzzed too, since they reach the wire: a username
//! carrying the very separators SCRAM-SHA-256 escapes is only
//! interesting if the target is allowed to generate one.

use core::str::from_utf8;

use arbitrary::Arbitrary;
use io_sasl::{
    coroutine::*,
    login::SaslAuthLogin,
    mechanism::{
        SaslAnonymous, SaslLogin, SaslOauthbearer, SaslPlain, SaslScramSha256, SaslXoauth2,
    },
    rfc4505::anonymous::SaslAuthAnonymous,
    rfc4616::plain::SaslAuthPlain,
    rfc7628::oauthbearer::SaslAuthOauthbearer,
    rfc7677::scram_sha_256::SaslAuthScramSha256,
    xoauth2::SaslAuthXoauth2,
};
use libfuzzer_sys::fuzz_target;
use secrecy::SecretString;

/// The largest SCRAM-SHA-256 iteration count the target derives.
///
/// NOTE: the count comes from the server and RFC 5802 puts no ceiling
/// on it, so a fuzzed `i=4000000000` is a legitimate message that
/// simply takes minutes of PBKDF2. That is a cost question for the
/// consumer rather than a memory-safety one, and libFuzzer would report
/// it as a timeout, so those challenges are skipped.
const MAX_ITERATIONS: u32 = 1024;

/// The credentials and the peer's side of an exchange.
#[derive(Arbitrary, Debug)]
struct Exchange {
    username: String,
    password: String,
    token: String,
    host: String,
    port: u16,
    nonce: Vec<u8>,
    challenges: Vec<Vec<u8>>,
    peer_finishes: bool,
}

fuzz_target!(|exchange: Exchange| {
    let first = exchange.challenges.first().cloned().unwrap_or_default();

    // A peer challenging a mechanism that has said nothing yet.
    unstarted(SaslAuthAnonymous::new(exchange.anonymous()), &first);
    unstarted(SaslAuthLogin::new(exchange.login()), &first);
    unstarted(SaslAuthPlain::new(exchange.plain()), &first);
    unstarted(SaslAuthOauthbearer::new(exchange.oauthbearer()), &first);
    unstarted(SaslAuthXoauth2::new(exchange.xoauth2()), &first);

    if affordable(&first) {
        unstarted(SaslAuthScramSha256::new(exchange.scram()), &first);
    }

    // The same peer answering a mechanism driven from its initial
    // response, as a protocol crate drives it.
    exchange.drive(SaslAuthAnonymous::new(exchange.anonymous()));
    exchange.drive(SaslAuthLogin::new(exchange.login()));
    exchange.drive(SaslAuthPlain::new(exchange.plain()));
    exchange.drive(SaslAuthOauthbearer::new(exchange.oauthbearer()));
    exchange.drive(SaslAuthXoauth2::new(exchange.xoauth2()));

    if exchange.challenges.iter().all(|c| affordable(c)) {
        exchange.drive(SaslAuthScramSha256::new(exchange.scram()));
    }
});

impl Exchange {
    /// Runs the mechanism from its initial response through every
    /// challenge, stopping where a protocol crate stops.
    fn drive(&self, mut mechanism: impl SaslCoroutine) {
        if let SaslCoroutineState::Complete(_) = mechanism.resume(SaslResume::Start) {
            return;
        }

        for challenge in &self.challenges {
            let step = mechanism.resume(SaslResume::Challenge(challenge));

            if let SaslCoroutineState::Complete(_) = step {
                return;
            }
        }

        if self.peer_finishes {
            let _ = mechanism.resume(SaslResume::PeerFinished);
        }
    }

    fn anonymous(&self) -> SaslAnonymous {
        SaslAnonymous {
            message: Some(self.username.clone()),
        }
    }

    fn login(&self) -> SaslLogin {
        SaslLogin {
            username: self.username.clone(),
            password: SecretString::from(self.password.clone()),
        }
    }

    fn plain(&self) -> SaslPlain {
        SaslPlain {
            authzid: None,
            authcid: self.username.clone(),
            passwd: SecretString::from(self.password.clone()),
        }
    }

    fn oauthbearer(&self) -> SaslOauthbearer {
        SaslOauthbearer {
            username: self.username.clone(),
            host: self.host.clone(),
            port: self.port,
            token: SecretString::from(self.token.clone()),
        }
    }

    fn xoauth2(&self) -> SaslXoauth2 {
        SaslXoauth2 {
            username: self.username.clone(),
            token: SecretString::from(self.token.clone()),
        }
    }

    fn scram(&self) -> SaslScramSha256 {
        SaslScramSha256 {
            username: self.username.clone(),
            password: SecretString::from(self.password.clone()),
            nonce: self.nonce.clone(),
        }
    }
}

/// Challenges a mechanism that was never resumed with `Start`.
fn unstarted(mut mechanism: impl SaslCoroutine, challenge: &[u8]) {
    let _ = mechanism.resume(SaslResume::Challenge(challenge));
}

/// Whether a challenge is cheap enough to feed SCRAM-SHA-256.
fn affordable(challenge: &[u8]) -> bool {
    let Ok(challenge) = from_utf8(challenge) else {
        return true;
    };

    challenge
        .split(',')
        .filter_map(|field| field.strip_prefix("i="))
        .filter_map(|iterations| iterations.parse::<u32>().ok())
        .all(|iterations| iterations <= MAX_ITERATIONS)
}
