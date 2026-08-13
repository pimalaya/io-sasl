//! The async half of the command surface.

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

/// Async SASL command surface, the [`SaslClient`] twin for a driver
/// whose transport is a future.
///
/// Everything [`SaslClient`] documents applies here, plus the `Send`
/// bounds. They are load-bearing rather than defensive: a plain `async
/// fn` in a trait cannot promise that the future it returns is `Send`,
/// so anything built from the default bodies would fail to compile
/// under `tokio::spawn`, which is the first thing a worker-spawning
/// consumer reaches for. Declaring the return type explicitly as `impl
/// Future<..> + Send`, with `Send` as a supertrait so `&mut Self`
/// carries through, keeps the defaults spawnable.
///
/// [`SaslClient`] deliberately carries no such bound. A blocking call
/// returns a value, so there is no future whose auto-traits need
/// pinning down, and requiring `Send` there would exclude a perfectly
/// good driver built on a thread-affine transport.
///
/// [`SaslClient`]: crate::client::std::SaslClient
///
/// # Example
///
/// The same loop inside an async block, with a driver whose only
/// failure is the mechanism's, so the conversion the default body asks
/// for is the reflexive one:
///
/// ```rust
/// use std::collections::VecDeque;
///
/// use io_sasl::{
///     client::r#async::SaslClientAsync,
///     coroutine::{SaslArg, SaslCoroutine, SaslCoroutineState, SaslYield},
///     login::{SaslLoginCreds, SaslLoginError},
/// };
/// use secrecy::SecretString;
///
/// struct Peer<'a> {
///     challenges: VecDeque<&'static [u8]>,
///     responses: &'a mut Vec<Vec<u8>>,
/// }
///
/// impl SaslClientAsync for Peer<'_> {
///     type Error = SaslLoginError;
///
///     // NOTE: clippy suggests collapsing this into `async fn`, which
///     // is the shape the trait exists to avoid: an `async fn` cannot
///     // state that its future is Send.
///     #[allow(clippy::manual_async_fn)]
///     fn run<C>(
///         &mut self,
///         mut mechanism: C,
///     ) -> impl Future<Output = Result<(), Self::Error>> + Send
///     where
///         C: SaslCoroutine + Send,
///         Self::Error: From<C::Error>,
///     {
///         async move {
///             let mut arg = SaslArg::None;
///
///             loop {
///                 match mechanism.resume(arg) {
///                     SaslCoroutineState::Complete(result) => break Ok(result?),
///                     SaslCoroutineState::Yielded(SaslYield::WantsWrite(response)) => {
///                         self.responses.push(response);
///                     }
///                     SaslCoroutineState::Yielded(SaslYield::WantsRead) => {}
///                 }
///
///                 // A real driver awaits its socket here, and tells a
///                 // challenge from the success reply that ends the
///                 // exchange.
///                 arg = match self.challenges.pop_front() {
///                     Some(challenge) => SaslArg::Input(challenge),
///                     None => SaslArg::Done,
///                 };
///             }
///         }
///     }
/// }
///
/// /// Stands in for `tokio::spawn`, which is what the `Send` bounds
/// /// exist for.
/// fn spawnable<F: Future + Send>(future: F) -> F {
///     future
/// }
///
/// let mut responses = Vec::new();
///
/// let mut peer = Peer {
///     challenges: VecDeque::from([b"Password:".as_slice()]),
///     responses: &mut responses,
/// };
///
/// // A runtime is what awaits the exchange. What is asserted here is
/// // that one can: a future that is not `Send` cannot be spawned.
/// let _exchange = spawnable(peer.login(SaslLoginCreds {
///     username: "alice".into(),
///     password: SecretString::from("pencil"),
/// }));
/// ```
pub trait SaslClientAsync: Send {
    /// The failure type the implementation reports, carrying its own
    /// framing errors and, through `From`, the failures of the
    /// mechanisms it runs.
    type Error;

    /// Runs one authentication exchange to completion, answering the
    /// mechanism's reads and writes against the transport.
    fn run<C>(&mut self, mechanism: C) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        C: SaslCoroutine + Send,
        Self::Error: From<C::Error>;

    /// `ANONYMOUS`: the optional trace token identifying an
    /// unauthenticated user.
    fn anonymous(
        &mut self,
        creds: SaslAnonymousCreds,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        Self::Error: From<<SaslAnonymous as SaslCoroutine>::Error>,
    {
        self.run(SaslAnonymous::new(creds))
    }

    /// `CRAM-MD5`: the keyed digest answering the server's challenge.
    /// The one server-first mechanism, so the command goes out bare.
    #[cfg(feature = "cram-md5")]
    #[cfg_attr(docsrs, doc(cfg(feature = "cram-md5")))]
    fn cram_md5(
        &mut self,
        creds: SaslCramMd5Creds,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        Self::Error: From<<SaslCramMd5 as SaslCoroutine>::Error>,
    {
        self.run(SaslCramMd5::new(creds))
    }

    /// `EXTERNAL`: the optional authorization identity, the outer
    /// channel being what authenticates.
    fn external(
        &mut self,
        creds: SaslExternalCreds,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        Self::Error: From<<SaslExternal as SaslCoroutine>::Error>,
    {
        self.run(SaslExternal::new(creds))
    }

    /// `GSSAPI`: the Kerberos tokens, relayed. The caller advances its
    /// own security context between resumes.
    fn gssapi(
        &mut self,
        creds: SaslGssapiCreds,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        Self::Error: From<<SaslGssapi as SaslCoroutine>::Error>,
    {
        self.run(SaslGssapi::new(creds))
    }

    /// `GS2-KRB5`, or `-PLUS` when the credentials carry a channel
    /// binding: the GS2 header, then the Kerberos tokens, relayed.
    fn gs2_krb5(
        &mut self,
        creds: SaslGs2Krb5Creds,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        Self::Error: From<<SaslGs2Krb5 as SaslCoroutine>::Error>,
    {
        self.run(SaslGs2Krb5::new(creds))
    }

    /// `LOGIN`: the username, then the password, each answering a
    /// cleartext prompt. Channel must be TLS-protected.
    fn login(
        &mut self,
        creds: SaslLoginCreds,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        Self::Error: From<<SaslLogin as SaslCoroutine>::Error>,
    {
        self.run(SaslLogin::new(creds))
    }

    /// `PLAIN`: the NUL-separated authorization identity,
    /// authentication identity and password. Channel must be
    /// TLS-protected.
    fn plain(
        &mut self,
        creds: SaslPlainCreds,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        Self::Error: From<<SaslPlain as SaslCoroutine>::Error>,
    {
        self.run(SaslPlain::new(creds))
    }

    /// `OAUTHBEARER`: the bearer token message, and the acknowledgement
    /// a rejected token needs before the failure can be reported.
    fn oauthbearer(
        &mut self,
        creds: SaslOauthbearerCreds,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        Self::Error: From<<SaslOauthbearer as SaslCoroutine>::Error>,
    {
        self.run(SaslOauthbearer::new(creds))
    }

    /// `XOAUTH2`: the username and bearer token, and the
    /// acknowledgement a rejected token needs.
    fn xoauth2(
        &mut self,
        creds: SaslXoauth2Creds,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        Self::Error: From<<SaslXoauth2 as SaslCoroutine>::Error>,
    {
        self.run(SaslXoauth2::new(creds))
    }

    /// `SCRAM-SHA-1`, or `-PLUS` when the credentials carry a channel
    /// binding. The legacy profile of the family.
    #[cfg(feature = "scram-sha-1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "scram-sha-1")))]
    fn scram_sha_1(
        &mut self,
        creds: SaslScramCreds,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        Self::Error: From<<SaslScramSha1 as SaslCoroutine>::Error>,
    {
        self.run(SaslScramSha1::new(creds))
    }

    /// `SCRAM-SHA-256`, or `-PLUS` when the credentials carry a channel
    /// binding. The exchange ends only once the server proved itself.
    #[cfg(feature = "scram")]
    #[cfg_attr(docsrs, doc(cfg(feature = "scram")))]
    fn scram_sha_256(
        &mut self,
        creds: SaslScramCreds,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        Self::Error: From<<SaslScramSha256 as SaslCoroutine>::Error>,
    {
        self.run(SaslScramSha256::new(creds))
    }

    /// `SCRAM-SHA-512`, or `-PLUS` when the credentials carry a channel
    /// binding. The exchange ends only once the server proved itself.
    #[cfg(feature = "scram")]
    #[cfg_attr(docsrs, doc(cfg(feature = "scram")))]
    fn scram_sha_512(
        &mut self,
        creds: SaslScramCreds,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        Self::Error: From<<SaslScramSha512 as SaslCoroutine>::Error>,
    {
        self.run(SaslScramSha512::new(creds))
    }
}
