//! The blocking half of the command surface.

#[cfg(feature = "cram-md5")]
use crate::rfc2195::cram_md5::{SaslCramMd5, SaslCramMd5Creds};
use crate::{
    coroutine::SaslCoroutine,
    login::{SaslLogin, SaslLoginCreds},
    rfc4422::external::{SaslExternal, SaslExternalCreds},
    rfc4505::anonymous::{SaslAnonymous, SaslAnonymousCreds},
    rfc4616::plain::{SaslPlain, SaslPlainCreds},
    rfc4752::gssapi::{SaslGssapi, SaslGssapiCreds},
    rfc5801::gs2_krb5::{SaslGs2Krb5, SaslGs2Krb5Creds},
    rfc7628::oauthbearer::{SaslOauthbearer, SaslOauthbearerCreds},
    xoauth2::{SaslXoauth2, SaslXoauth2Creds},
};

#[cfg(feature = "scram-sha-1")]
use crate::rfc5802::scram_sha_1::SaslScramSha1;
#[cfg(feature = "scram")]
use crate::scram_sha_512::SaslScramSha512;
#[cfg(feature = "scram")]
use crate::{rfc5802::SaslScramCreds, rfc7677::scram_sha_256::SaslScramSha256};

/// Blocking SASL command surface: implement [`run`] and inherit every
/// mechanism.
///
/// The implementation is whatever holds the transport for the duration
/// of the exchange, which for a protocol crate is usually its own
/// client or a short-lived borrow of one. What [`run`] owes each
/// mechanism is the loop around it:
///
/// - open the exchange with the name [`SaslCoroutine::mechanism`]
///   reports, framed by the protocol (`AUTHENTICATE <name>`, `AUTH
///   <name>`, ...);
/// - resume first with [`SaslArg::None`], then always with the answer
///   to the previous yield;
/// - on [`SaslYield::WantsWrite`], base64-encode the payload, frame it
///   and write it, then read what the peer says next;
/// - on [`SaslYield::WantsRead`], read straight away;
/// - resume with [`SaslArg::Input`] carrying the decoded challenge, or
///   with [`SaslArg::Done`] once the peer's own success reply ended the
///   exchange;
/// - on [`SaslCoroutineState::Complete`], return, converting a
///   mechanism failure through `From`.
///
/// The failure type is the implementation's own rather than this
/// crate's. A crate-owned error would need a boxed variant for the
/// framing errors of whoever drives it, and that driver would then
/// unbox its own errors on the way out. Each default body asks instead
/// for the one conversion it needs, so an implementation pays only for
/// the mechanisms it calls.
///
/// The trait is not dyn-compatible, [`run`] being generic. A caller
/// choosing a mechanism at runtime matches on [`Sasl`] and calls the
/// method its variant lands on; the closed set is where that dynamism
/// belongs.
///
/// [`run`]: Self::run
/// [`Sasl`]: crate::mechanism::Sasl
/// [`SaslArg::None`]: crate::coroutine::SaslArg::None
/// [`SaslArg::Input`]: crate::coroutine::SaslArg::Input
/// [`SaslArg::Done`]: crate::coroutine::SaslArg::Done
/// [`SaslYield::WantsWrite`]: crate::coroutine::SaslYield::WantsWrite
/// [`SaslYield::WantsRead`]: crate::coroutine::SaslYield::WantsRead
/// [`SaslCoroutineState::Complete`]: crate::coroutine::SaslCoroutineState::Complete
///
/// # Example
///
/// A driver over a scripted peer, standing in for the socket a protocol
/// crate frames its exchange over:
///
/// ```rust
/// use std::collections::VecDeque;
///
/// use io_sasl::{
///     client::std::SaslClient,
///     coroutine::{SaslArg, SaslCoroutine, SaslCoroutineState, SaslYield},
///     login::{SaslLoginCreds, SaslLoginError},
/// };
/// use secrecy::SecretString;
///
/// /// What the peer says after a response.
/// enum Reply {
///     Challenge(&'static [u8]),
///     Success,
/// }
///
/// /// What a driver reports: the mechanism's failures, and its own.
/// #[derive(Debug)]
/// enum PeerError {
///     Login(SaslLoginError),
///     Disconnected,
/// }
///
/// impl From<SaslLoginError> for PeerError {
///     fn from(err: SaslLoginError) -> Self {
///         Self::Login(err)
///     }
/// }
///
/// /// A driver owning no transport: it borrows what it writes to for
/// /// the exchange, and gives it back afterwards.
/// struct Peer<'a> {
///     replies: VecDeque<Reply>,
///     responses: &'a mut Vec<Vec<u8>>,
/// }
///
/// impl SaslClient for Peer<'_> {
///     type Error = PeerError;
///
///     fn run<C>(&mut self, mut mechanism: C) -> Result<(), Self::Error>
///     where
///         C: SaslCoroutine,
///         Self::Error: From<C::Error>,
///     {
///         // The name the exchange opens with, which a real driver
///         // writes inside its own command grammar.
///         let _name = mechanism.mechanism().as_str();
///         let mut arg = SaslArg::None;
///
///         loop {
///             match mechanism.resume(arg) {
///                 SaslCoroutineState::Complete(result) => break Ok(result?),
///                 SaslCoroutineState::Yielded(SaslYield::WantsWrite(response)) => {
///                     // A real driver base64-encodes and frames.
///                     self.responses.push(response);
///                 }
///                 SaslCoroutineState::Yielded(SaslYield::WantsRead) => {}
///             }
///
///             arg = match self.replies.pop_front() {
///                 Some(Reply::Challenge(challenge)) => SaslArg::Input(challenge),
///                 Some(Reply::Success) => SaslArg::Done,
///                 None => break Err(PeerError::Disconnected),
///             };
///         }
///     }
/// }
///
/// let mut responses = Vec::new();
///
/// let mut peer = Peer {
///     replies: VecDeque::from([Reply::Challenge(b"Password:"), Reply::Success]),
///     responses: &mut responses,
/// };
///
/// peer.login(SaslLoginCreds {
///     username: "alice".into(),
///     password: SecretString::from("pencil"),
/// })
/// .unwrap();
///
/// assert_eq!(responses, [b"alice".to_vec(), b"pencil".to_vec()]);
/// ```
pub trait SaslClient {
    /// The failure type the implementation reports, carrying its own
    /// framing errors and, through `From`, the failures of the
    /// mechanisms it runs.
    type Error;

    /// Runs one authentication exchange to completion, answering the
    /// mechanism's reads and writes against the transport.
    fn run<C>(&mut self, mechanism: C) -> Result<(), Self::Error>
    where
        C: SaslCoroutine,
        Self::Error: From<C::Error>;

    /// `ANONYMOUS`: the optional trace token identifying an
    /// unauthenticated user.
    fn anonymous(&mut self, creds: SaslAnonymousCreds) -> Result<(), Self::Error>
    where
        Self::Error: From<<SaslAnonymous as SaslCoroutine>::Error>,
    {
        self.run(SaslAnonymous::new(creds))
    }

    /// `CRAM-MD5`: the keyed digest answering the server's challenge.
    /// The one server-first mechanism, so the command goes out bare.
    #[cfg(feature = "cram-md5")]
    #[cfg_attr(docsrs, doc(cfg(feature = "cram-md5")))]
    fn cram_md5(&mut self, creds: SaslCramMd5Creds) -> Result<(), Self::Error>
    where
        Self::Error: From<<SaslCramMd5 as SaslCoroutine>::Error>,
    {
        self.run(SaslCramMd5::new(creds))
    }

    /// `EXTERNAL`: the optional authorization identity, the outer
    /// channel being what authenticates.
    fn external(&mut self, creds: SaslExternalCreds) -> Result<(), Self::Error>
    where
        Self::Error: From<<SaslExternal as SaslCoroutine>::Error>,
    {
        self.run(SaslExternal::new(creds))
    }

    /// `GSSAPI`: the Kerberos tokens, relayed. The caller advances its
    /// own security context between resumes.
    fn gssapi(&mut self, creds: SaslGssapiCreds) -> Result<(), Self::Error>
    where
        Self::Error: From<<SaslGssapi as SaslCoroutine>::Error>,
    {
        self.run(SaslGssapi::new(creds))
    }

    /// `GS2-KRB5`, or `-PLUS` when the credentials carry a channel
    /// binding: the GS2 header, then the Kerberos tokens, relayed.
    fn gs2_krb5(&mut self, creds: SaslGs2Krb5Creds) -> Result<(), Self::Error>
    where
        Self::Error: From<<SaslGs2Krb5 as SaslCoroutine>::Error>,
    {
        self.run(SaslGs2Krb5::new(creds))
    }

    /// `LOGIN`: the username, then the password, each answering a
    /// cleartext prompt. Channel must be TLS-protected.
    fn login(&mut self, creds: SaslLoginCreds) -> Result<(), Self::Error>
    where
        Self::Error: From<<SaslLogin as SaslCoroutine>::Error>,
    {
        self.run(SaslLogin::new(creds))
    }

    /// `PLAIN`: the NUL-separated authorization identity,
    /// authentication identity and password. Channel must be
    /// TLS-protected.
    fn plain(&mut self, creds: SaslPlainCreds) -> Result<(), Self::Error>
    where
        Self::Error: From<<SaslPlain as SaslCoroutine>::Error>,
    {
        self.run(SaslPlain::new(creds))
    }

    /// `OAUTHBEARER`: the bearer token message, and the acknowledgement
    /// a rejected token needs before the failure can be reported.
    fn oauthbearer(&mut self, creds: SaslOauthbearerCreds) -> Result<(), Self::Error>
    where
        Self::Error: From<<SaslOauthbearer as SaslCoroutine>::Error>,
    {
        self.run(SaslOauthbearer::new(creds))
    }

    /// `XOAUTH2`: the username and bearer token, and the
    /// acknowledgement a rejected token needs.
    fn xoauth2(&mut self, creds: SaslXoauth2Creds) -> Result<(), Self::Error>
    where
        Self::Error: From<<SaslXoauth2 as SaslCoroutine>::Error>,
    {
        self.run(SaslXoauth2::new(creds))
    }

    /// `SCRAM-SHA-1`, or `-PLUS` when the credentials carry a channel
    /// binding. The legacy profile of the family.
    #[cfg(feature = "scram-sha-1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "scram-sha-1")))]
    fn scram_sha_1(&mut self, creds: SaslScramCreds) -> Result<(), Self::Error>
    where
        Self::Error: From<<SaslScramSha1 as SaslCoroutine>::Error>,
    {
        self.run(SaslScramSha1::new(creds))
    }

    /// `SCRAM-SHA-256`, or `-PLUS` when the credentials carry a channel
    /// binding. The exchange ends only once the server proved itself.
    #[cfg(feature = "scram")]
    #[cfg_attr(docsrs, doc(cfg(feature = "scram")))]
    fn scram_sha_256(&mut self, creds: SaslScramCreds) -> Result<(), Self::Error>
    where
        Self::Error: From<<SaslScramSha256 as SaslCoroutine>::Error>,
    {
        self.run(SaslScramSha256::new(creds))
    }

    /// `SCRAM-SHA-512`, or `-PLUS` when the credentials carry a channel
    /// binding. The exchange ends only once the server proved itself.
    #[cfg(feature = "scram")]
    #[cfg_attr(docsrs, doc(cfg(feature = "scram")))]
    fn scram_sha_512(&mut self, creds: SaslScramCreds) -> Result<(), Self::Error>
    where
        Self::Error: From<<SaslScramSha512 as SaslCoroutine>::Error>,
    {
        self.run(SaslScramSha512::new(creds))
    }
}
