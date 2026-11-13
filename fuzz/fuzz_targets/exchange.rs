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

use arbitrary::Arbitrary;
use io_sasl::{
    coroutine::*,
    login::{SaslLogin, SaslLoginCreds},
    rfc2195::cram_md5::{SaslCramMd5, SaslCramMd5Creds},
    rfc4422::external::{SaslExternal, SaslExternalCreds},
    rfc4505::anonymous::{SaslAnonymous, SaslAnonymousCreds},
    rfc4616::plain::{SaslPlain, SaslPlainCreds},
    rfc4752::gssapi::{SaslGssapi, SaslGssapiCreds},
    rfc5801::{
        SaslGs2ChannelBinding, SaslGs2ChannelBindingKind,
        gs2_krb5::{SaslGs2Krb5, SaslGs2Krb5Creds},
    },
    rfc5802::{
        SASL_SCRAM_MIN_NONCE_LEN, SaslScramCreds, SaslScramOptions, scram_sha_1::SaslScramSha1,
    },
    rfc7628::oauthbearer::{SaslOauthbearer, SaslOauthbearerCreds},
    rfc7677::scram_sha_256::SaslScramSha256,
    scram_sha_512::SaslScramSha512,
    xoauth2::{SaslXoauth2, SaslXoauth2Creds},
};
use libfuzzer_sys::fuzz_target;
use secrecy::SecretString;

/// The largest SCRAM iteration count the target derives.
///
/// NOTE: it is handed to the mechanisms as their ceiling, so a fuzzed
/// `i=4000000000` is refused rather than derived, and a ceiling that
/// stopped holding would show as a libFuzzer timeout.
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
    unstarted(SaslCramMd5::new(exchange.cram_md5()), &first);
    unstarted(SaslGs2Krb5::new(exchange.gs2_krb5()), &first);
    unstarted(SaslLogin::new(exchange.login()), &first);
    unstarted(SaslPlain::new(exchange.plain()), &first);
    unstarted(SaslOauthbearer::new(exchange.oauthbearer()), &first);
    unstarted(SaslXoauth2::new(exchange.xoauth2()), &first);

    unstarted(SaslScramSha1::new(exchange.scram(false), bounds()), &first);
    unstarted(
        SaslScramSha256::new(exchange.scram(false), bounds()),
        &first,
    );
    unstarted(
        SaslScramSha512::new(exchange.scram(false), bounds()),
        &first,
    );

    // The same peer answering a mechanism driven from its initial
    // response, as a protocol crate drives it.
    exchange.drive(SaslAnonymous::new(exchange.anonymous()));
    exchange.drive(SaslExternal::new(exchange.external()));
    exchange.drive(SaslGssapi::new(exchange.gssapi()));
    exchange.drive(SaslCramMd5::new(exchange.cram_md5()));
    exchange.drive(SaslGs2Krb5::new(exchange.gs2_krb5()));
    exchange.drive(SaslLogin::new(exchange.login()));
    exchange.drive(SaslPlain::new(exchange.plain()));
    exchange.drive(SaslOauthbearer::new(exchange.oauthbearer()));
    exchange.drive(SaslXoauth2::new(exchange.xoauth2()));

    // NOTE: every profile is driven both plain and bound, since the
    // binding reaches the wire twice, in the GS2 header and in the
    // c= field of a message the proof is computed over.
    exchange.drive(SaslScramSha1::new(exchange.scram(false), bounds()));
    exchange.drive(SaslScramSha1::new(exchange.scram(true), bounds()));
    exchange.drive(SaslScramSha256::new(exchange.scram(false), bounds()));
    exchange.drive(SaslScramSha256::new(exchange.scram(true), bounds()));
    exchange.drive(SaslScramSha512::new(exchange.scram(false), bounds()));
    exchange.drive(SaslScramSha512::new(exchange.scram(true), bounds()));

    // The nonce as fuzzed, which the mechanism refuses unless it is one.
    let raw = SaslScramCreds {
        nonce: exchange.nonce.clone(),
        ..exchange.scram(false)
    };

    exchange.drive(SaslScramSha256::new(raw, bounds()));
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

    fn cram_md5(&self) -> SaslCramMd5Creds {
        SaslCramMd5Creds {
            username: self.username.clone(),
            secret: SecretString::from(self.password.clone()),
        }
    }

    fn gs2_krb5(&self) -> SaslGs2Krb5Creds {
        SaslGs2Krb5Creds {
            token: self.token.clone().into_bytes(),
            authzid: Some(self.username.clone()),
            channel_binding: SaslGs2ChannelBinding::Bound {
                kind: SaslGs2ChannelBindingKind::TlsExporter,
                data: self.binding.clone(),
            },
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
            SaslGs2ChannelBinding::Bound {
                kind: SaslGs2ChannelBindingKind::TlsExporter,
                data: self.binding.clone(),
            }
        } else {
            SaslGs2ChannelBinding::Unsupported
        };

        // NOTE: the fuzzed bytes are folded onto the nonce alphabet and
        // padded, or nearly every exchange would end at its first step.
        let printable = |byte: &u8| match b'!' + byte % 94 {
            b',' => b'.',
            byte => byte,
        };

        let mut nonce: Vec<u8> = self.nonce.iter().map(printable).collect();
        nonce.resize(nonce.len().max(SASL_SCRAM_MIN_NONCE_LEN), b'A');

        SaslScramCreds {
            username: self.username.clone(),
            password: SecretString::from(self.password.clone()),
            nonce,
            channel_binding,
        }
    }
}

/// Challenges a mechanism that was never resumed with `Start`.
fn unstarted(mut mechanism: impl SaslCoroutine, challenge: &[u8]) {
    let _ = mechanism.resume(SaslArg::Input(challenge));
}

/// The iteration bounds every SCRAM profile is driven with.
fn bounds() -> SaslScramOptions {
    SaslScramOptions {
        min_iterations: Some(1),
        max_iterations: Some(MAX_ITERATIONS),
    }
}
