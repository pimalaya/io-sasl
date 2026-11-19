#![no_main]

//! Coverage-guided fuzz target for the server side. Whatever a client
//! sends, in whatever order, an exchange answers or fails, never
//! panics, and never succeeds without a positive verdict on the
//! credentials it yielded.

use arbitrary::Arbitrary;
use io_sasl::server::*;
use libfuzzer_sys::fuzz_target;

/// One step of a client and caller driving the exchange.
#[derive(Arbitrary, Debug)]
enum Step {
    None,
    Response(Vec<u8>),
    Cancel,
    Verdict(bool),
}

/// The mechanism, the initial response and the steps that follow.
#[derive(Arbitrary, Debug)]
struct Exchange {
    login: bool,
    initial_response: Option<Vec<u8>>,
    steps: Vec<Step>,
}

fuzz_target!(|exchange: Exchange| {
    let mechanism = if exchange.login {
        SaslServerMechanism::Login
    } else {
        SaslServerMechanism::Plain
    };

    let mut server = SaslServer::new(mechanism, exchange.initial_response);
    let mut verified = false;
    let mut state = server.resume(SaslServerArg::None);

    for step in exchange.steps {
        let arg = match step {
            Step::None => SaslServerArg::None,
            Step::Response(bytes) => SaslServerArg::Response(bytes),
            Step::Cancel => SaslServerArg::Cancel,
            Step::Verdict(verdict) => SaslServerArg::Verdict(verdict),
        };

        let accepting = matches!(arg, SaslServerArg::Verdict(true));
        let pending = matches!(state, SaslServerState::Verify(_));

        state = server.resume(arg);

        if let SaslServerState::Success { .. } = state {
            assert!(pending && accepting, "success without a positive verdict");
            assert!(!verified, "success twice");
            verified = true;
        }
    }
});
