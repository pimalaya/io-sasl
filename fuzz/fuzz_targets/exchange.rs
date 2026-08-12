#![no_main]

//! Coverage-guided fuzz target for every mechanism. One oracle,
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
    login::{SaslLogin, SaslLoginCreds},
    rfc4422::external::{SaslExternal, SaslExternalCreds},
    rfc4505::anonymous::{SaslAnonymous, SaslAnonymousCreds},
    rfc4752::gssapi::{SaslGssapi, SaslGssapiCreds},
    rfc4616::plain::{SaslPlain, SaslPlainCreds},
    rfc5802::{
        SaslScramChannelBinding, SaslScramChannelBindingKind, SaslScramCreds,
        scram_sha_1::SaslScramSha1,
    },
    rfc7628::oauthbearer::{SaslOauthbearer, SaslOauthbearerCreds},
    rfc7677::scram_sha_256::SaslScramSha256,
    scram_sha_512::SaslScramSha512,
    xoauth2::{SaslXoauth2, SaslXoauth2Creds},
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
    binding: Vec<u8>,
    challenges: Vec<Vec<u8>>,
    peer_finishes: bool,
}

fuzz_target!(|exchange: Exchange| {
    let first = exchange.challenges.first().cloned().unwrap_or_default();

    // A peer challenging a mechanism that has said nothing yet.
    unstarted(SaslAnonymous::new(exchange.anonymous()), &first);
    unstarted(SaslExternal::new(exchange.external()), &first);
    unstarted(SaslGssapi::new(exchange.gssapi()), &first);
    unstarted(SaslLogin::new(exchange.login()), &first);
    unstarted(SaslPlain::new(exchange.plain()), &first);
    unstarted(SaslOauthbearer::new(exchange.oauthbearer()), &first);
    unstarted(SaslXoauth2::new(exchange.xoauth2()), &first);

    if affordable(&first) {
        unstarted(SaslScramSha1::new(exchange.scram(false)), &first);
        unstarted(SaslScramSha256::new(exchange.scram(false)), &first);
        unstarted(SaslScramSha512::new(exchange.scram(false)), &first);
    }

    // The same peer answering a mechanism driven from its initial
    // response, as a protocol crate drives it.
    exchange.drive(SaslAnonymous::new(exchange.anonymous()));
    exchange.drive(SaslExternal::new(exchange.external()));
    exchange.drive(SaslGssapi::new(exchange.gssapi()));
    exchange.drive(SaslLogin::new(exchange.login()));
    exchange.drive(SaslPlain::new(exchange.plain()));
    exchange.drive(SaslOauthbearer::new(exchange.oauthbearer()));
    exchange.drive(SaslXoauth2::new(exchange.xoauth2()));

    if exchange.challenges.iter().all(|c| affordable(c)) {
        // NOTE: every profile is driven both plain and bound, since the
        // binding reaches the wire twice, in the GS2 header and in the
        // c= field of a message the proof is computed over.
        exchange.drive(SaslScramSha1::new(exchange.scram(false)));
        exchange.drive(SaslScramSha1::new(exchange.scram(true)));
        exchange.drive(SaslScramSha256::new(exchange.scram(false)));
        exchange.drive(SaslScramSha256::new(exchange.scram(true)));
        exchange.drive(SaslScramSha512::new(exchange.scram(false)));
        exchange.drive(SaslScramSha512::new(exchange.scram(true)));
    }
});

impl Exchange {
    /// Runs the mechanism from its initial response through every
    /// challenge, stopping where a protocol crate stops.
    fn drive(&self, mut mechanism: impl SaslCoroutine) {
        if let SaslCoroutineState::Complete(_) = mechanism.resume(SaslArg::None) {
            return;
        }

        for challenge in &self.challenges {
            let step = mechanism.resume(SaslArg::Input(challenge));

            if let SaslCoroutineState::Complete(_) = step {
                return;
            }
        }

        if self.peer_finishes {
            let _ = mechanism.resume(SaslArg::Done);
        }
    }

    fn anonymous(&self) -> SaslAnonymousCreds {
        SaslAnonymousCreds {
            message: Some(self.username.clone()),
        }
    }

    fn login(&self) -> SaslLoginCreds {
        SaslLoginCreds {
            username: self.username.clone(),
            password: SecretString::from(self.password.clone()),
        }
    }

    fn plain(&self) -> SaslPlainCreds {
        SaslPlainCreds {
            authzid: None,
            authcid: self.username.clone(),
            passwd: SecretString::from(self.password.clone()),
        }
    }

    fn oauthbearer(&self) -> SaslOauthbearerCreds {
        SaslOauthbearerCreds {
            username: self.username.clone(),
            host: self.host.clone(),
            port: self.port,
            token: SecretString::from(self.token.clone()),
        }
    }

    fn xoauth2(&self) -> SaslXoauth2Creds {
        SaslXoauth2Creds {
            username: self.username.clone(),
            token: SecretString::from(self.token.clone()),
        }
    }

    fn gssapi(&self) -> SaslGssapiCreds {
        SaslGssapiCreds {
            token: self.token.clone().into_bytes(),
        }
    }

    fn external(&self) -> SaslExternalCreds {
        SaslExternalCreds {
            authzid: Some(self.username.clone()),
        }
    }

    fn scram(&self, bound: bool) -> SaslScramCreds {
        let channel_binding = if bound {
            SaslScramChannelBinding::Bound {
                kind: SaslScramChannelBindingKind::TlsExporter,
                data: self.binding.clone(),
            }
        } else {
            SaslScramChannelBinding::Unsupported
        };

        SaslScramCreds {
            username: self.username.clone(),
            password: SecretString::from(self.password.clone()),
            nonce: self.nonce.clone(),
            channel_binding,
        }
    }
}

/// Challenges a mechanism that was never resumed with `Start`.
fn unstarted(mut mechanism: impl SaslCoroutine, challenge: &[u8]) {
    let _ = mechanism.resume(SaslArg::Input(challenge));
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
