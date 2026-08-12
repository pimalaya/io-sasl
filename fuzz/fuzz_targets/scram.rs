#![no_main]

//! Coverage-guided fuzz target for SCRAM-SHA-256, the mechanism this
//! crate exists for. Two oracles: driving it never panics, and it never
//! reports success unless it was fed a server-final-message whose
//! signature is the one RFC 5802 computes.
//!
//! The second oracle is the point. The two implementations io-sasl
//! replaces both accepted an exchange the server never proved: one
//! verified only when the reply happened to parse, the other took a
//! tagged OK carrying the server-final-message as success on its own.
//! Neither bug is visible from a mechanism's own state machine, so the
//! target derives the salted password, the server key and the server
//! signature itself, from the RFC 5802 primitives and from the bytes it
//! watched the mechanism send. Acceptance is then checked against an
//! answer computed outside the thing being checked.
//!
//! Everything the peer says is fuzzed, including the server-first
//! message the signature is derived over, so the harness parses the
//! salt and the iteration count out of whatever it fed rather than out
//! of what it meant to feed.

use core::str::from_utf8;

use arbitrary::Arbitrary;
use base64::{Engine, engine::general_purpose::STANDARD as base64};
use hmac::{Hmac, KeyInit, Mac};
use io_sasl::{
    coroutine::*,
    rfc5802::{SaslScramChannelBinding, SaslScramCreds, SaslScramError},
    rfc7677::scram_sha_256::SaslScramSha256,
};
use libfuzzer_sys::fuzz_target;
use pbkdf2::pbkdf2_hmac;
use secrecy::SecretString;
use sha2::Sha256;

/// The largest iteration count the target derives.
///
/// NOTE: the count comes from the server and RFC 5802 puts no ceiling
/// on it, so a fuzzed `i=4000000000` is a legitimate message that
/// simply takes minutes of PBKDF2. That is a cost question for the
/// consumer rather than a memory-safety one, and libFuzzer would report
/// it as a timeout, so those challenges end the run instead.
const MAX_ITERATIONS: u32 = 1024;

/// The credentials and the server's side of an exchange.
#[derive(Arbitrary, Debug)]
struct Exchange {
    username: String,
    password: String,
    nonce: Vec<u8>,
    steps: Vec<Step>,
}

/// What the server says next.
#[derive(Arbitrary, Debug)]
enum Step {
    /// Arbitrary bytes where a server message belongs.
    Raw(Vec<u8>),
    /// A well-formed server-first-message the harness assembles, so
    /// that the exchange can reach its interesting half at all.
    ServerFirst {
        /// The server's own half of the nonce.
        extension: String,
        /// The salt the client derives its password with.
        salt: Vec<u8>,
        /// The iteration count, kept small so the target stays fast.
        iterations: u8,
    },
    /// The server-final-message carrying the signature the harness
    /// computed itself, which is the only one that may be accepted.
    ServerFinal,
    /// The peer ended the exchange.
    PeerFinished,
}

fuzz_target!(|exchange: Exchange| {
    exchange.run();
});

impl Exchange {
    /// Drives the mechanism through the scripted server messages,
    /// checking every acceptance against the harness's own arithmetic.
    fn run(&self) {
        // NOTE: the oracle recomputes the signature over the GS2 header
        // it watched go out, so an unbound exchange is what keeps that
        // arithmetic independent of the binding this crate assembles.
        let creds = SaslScramCreds {
            username: self.username.clone(),
            password: SecretString::from(self.password.clone()),
            nonce: self.nonce.clone(),
            channel_binding: SaslScramChannelBinding::Unsupported,
        };

        let mut auth = SaslScramSha256::new(creds);

        let started = auth.resume(SaslArg::Start);

        let SaslCoroutineState::Yielded(SaslYield::WantsWrite(client_first)) = started else {
            panic!("SCRAM-SHA-256 answered Start with {started:?} instead of a response");
        };

        let mut oracle = Oracle::new(&self.password, &client_first);

        for step in &self.steps {
            let challenge = match step {
                Step::Raw(bytes) => bytes.clone(),
                Step::ServerFirst {
                    extension,
                    salt,
                    iterations,
                } => oracle.server_first(extension, salt, *iterations),
                Step::ServerFinal => oracle.server_final(),
                Step::PeerFinished => {
                    match auth.resume(SaslArg::PeerFinished) {
                        SaslCoroutineState::Complete(completed) => oracle.completed(completed),
                        state => panic!("PeerFinished did not end the exchange: {state:?}"),
                    }

                    return;
                }
            };

            if !affordable(&challenge) {
                return;
            }

            match auth.resume(SaslArg::Challenge(&challenge)) {
                SaslCoroutineState::Yielded(SaslYield::WantsWrite(payload)) => {
                    oracle.responded(&challenge, &payload)
                }
                SaslCoroutineState::Yielded(SaslYield::WantsChallenge) => {}
                SaslCoroutineState::Complete(completed) => {
                    oracle.completed(completed);
                    return;
                }
            }
        }
    }
}

/// The exchange as the harness sees it from outside the mechanism.
struct Oracle {
    password: String,
    client_first_bare: String,
    client_nonce: String,
    server_final: Option<Vec<u8>>,
    verified: bool,
}

impl Oracle {
    /// Reads the client-first-message the mechanism just sent, which is
    /// where the authentication message and the client nonce come from.
    fn new(password: &str, client_first: &[u8]) -> Self {
        let client_first = from_utf8(client_first).expect("the client-first-message is UTF-8");
        let bare = client_first.strip_prefix("n,,").expect(
            "the client-first-message carries the GS2 header of a client without channel binding",
        );

        // NOTE: the escaped username carries no comma, so the first
        // ",r=" is the nonce separator even when the nonce itself
        // carries commas.
        let (_, nonce) = bare
            .split_once(",r=")
            .expect("the client-first-message carries a nonce");

        Self {
            password: password.to_string(),
            client_first_bare: bare.to_string(),
            client_nonce: nonce.to_string(),
            server_final: None,
            verified: false,
        }
    }

    /// Assembles a server-first-message extending the client nonce, so
    /// the exchange can get past its first step.
    fn server_first(&self, extension: &str, salt: &[u8], iterations: u8) -> Vec<u8> {
        let nonce = &self.client_nonce;
        let salt = base64.encode(salt);
        let iterations = u32::from(iterations);

        format!("r={nonce}{extension},s={salt},i={iterations}").into_bytes()
    }

    /// The one server-final-message the mechanism may accept, or an
    /// empty challenge while there is nothing to sign yet.
    fn server_final(&self) -> Vec<u8> {
        self.server_final.clone().unwrap_or_default()
    }

    /// Watches a response, which is where both oracles are decided.
    ///
    /// A non-empty response is the client-final-message, and everything
    /// the server signature is computed over is known once it is out:
    /// the harness derives that signature and remembers the only
    /// server-final-message that may be accepted. An empty response is
    /// the acknowledgement the mechanism sends after verifying, so the
    /// challenge that earned it has to be exactly that message.
    fn responded(&mut self, challenge: &[u8], payload: &[u8]) {
        if payload.is_empty() {
            assert_eq!(
                Some(challenge),
                self.server_final.as_deref(),
                "the mechanism verified a server signature that is not the one RFC 5802 computes",
            );

            self.verified = true;
            return;
        }

        self.server_final = self
            .server_signature(challenge, payload)
            .map(|signature| format!("v={signature}").into_bytes());
    }

    /// Checks the terminal step: success means the server proved
    /// itself, and the harness has to have watched it happen.
    fn completed(&self, completed: Result<(), SaslScramError>) {
        if completed.is_err() {
            return;
        }

        assert!(
            self.verified,
            "the mechanism completed an exchange in which no server signature was ever verified",
        );
    }

    /// Derives the server signature of RFC 5802 section 3 from the
    /// server-first-message that was fed and the client-final-message
    /// that came back.
    fn server_signature(&self, server_first: &[u8], client_final: &[u8]) -> Option<String> {
        let server_first = from_utf8(server_first).ok()?;
        let client_final = from_utf8(client_final).ok()?;
        let (without_proof, _) = client_final.rsplit_once(",p=")?;

        let mut salt = None;
        let mut iterations = None;

        // NOTE: last field wins, matching the mechanism's own parse;
        // the values are read back out of the message that was fed
        // rather than out of the step that built it, since a Raw step
        // can carry a server-first-message too.
        for field in server_first.split(',') {
            if let Some(s) = field.strip_prefix("s=") {
                salt = base64.decode(s).ok();
            } else if let Some(i) = field.strip_prefix("i=") {
                iterations = i.parse::<u32>().ok();
            }
        }

        let client_first_bare = &self.client_first_bare;
        let auth_message = format!("{client_first_bare},{server_first},{without_proof}");

        let mut salted_password = [0u8; 32];
        let password = self.password.as_bytes();
        pbkdf2_hmac::<Sha256>(password, &salt?, iterations?, &mut salted_password);

        let server_key = hmac_sha256(&salted_password, b"Server Key");

        Some(base64.encode(hmac_sha256(&server_key, auth_message.as_bytes())))
    }
}

/// Whether a challenge is cheap enough to feed.
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

/// HMAC-SHA-256 as RFC 5802 uses it: `HMAC(key, data)`.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
