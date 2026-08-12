//! The GS2 bridge ([RFC 5801]), which is two things at once.
//!
//! It carries GSS-API mechanisms into SASL under `GS2-` names, which is
//! what [`gs2_krb5`] is, and it defines the header those mechanisms
//! prefix to their first token. That header is the piece SCRAM borrowed
//! wholesale, so [`SaslGs2ChannelBinding`] lives here rather than with
//! either mechanism: it names the three cases a client can be in, and
//! writing it down once is what keeps a `-PLUS` exchange saying the
//! same thing in both families.
//!
//! ## The three cases
//!
//! The flag opening the header answers one question, whether the
//! exchange is bound to the channel underneath it, and the third case
//! is the one implementations forget. A client that supports binding
//! and sees no `-PLUS` name advertised sends `y`, not `n`, so a server
//! that does support binding can tell that its offer was stripped in
//! flight and abort ([RFC 5802 section 6]). Answering `n` there makes
//! the downgrade invisible to both ends.
//!
//! ## What stays with the caller
//!
//! The binding material itself, since extracting it means asking a TLS
//! session what it exported, and which kind was extracted, since only
//! the caller knows. This crate assembles the header around it.
//!
//! [RFC 5801]: https://www.rfc-editor.org/rfc/rfc5801
//! [RFC 5802 section 6]: https://www.rfc-editor.org/rfc/rfc5802#section-6

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

pub mod gs2_krb5;

/// The channel binding an exchange runs with, which is also what picks
/// between a mechanism's plain and `-PLUS` names.
#[derive(Clone, Debug, Default)]
pub enum SaslGs2ChannelBinding {
    /// The client does not support channel binding, the `n` flag.
    #[default]
    Unsupported,
    /// The client supports channel binding but the server never
    /// advertised the `-PLUS` name, the `y` flag.
    Unused,
    /// Channel binding is in use, the `p` flag.
    Bound {
        /// Which binding the data was extracted from.
        kind: SaslGs2ChannelBindingKind,
        /// The binding material, extracted from the TLS session by the
        /// caller.
        data: Vec<u8>,
    },
}

impl SaslGs2ChannelBinding {
    /// Whether the exchange is bound, and so runs under the `-PLUS`
    /// name of its mechanism.
    pub fn is_bound(&self) -> bool {
        matches!(self, Self::Bound { .. })
    }

    /// The GS2 header opening the exchange: the flag, then the
    /// authorization identity when there is one, both comma-terminated.
    ///
    /// The identity is escaped as [RFC 5801 section 4] asks, `=` as
    /// `=3D` and `,` as `=2C`, so that the commas framing the header
    /// stay unambiguous.
    ///
    /// [RFC 5801 section 4]: https://www.rfc-editor.org/rfc/rfc5801#section-4
    pub fn header(&self, authzid: Option<&str>) -> String {
        let flag = match self {
            Self::Unsupported => "n".to_string(),
            Self::Unused => "y".to_string(),
            Self::Bound { kind, .. } => {
                let kind = kind.as_str();
                format!("p={kind}")
            }
        };

        let authzid = match authzid {
            None => String::new(),
            Some(authzid) => {
                let escaped = escape(authzid);
                format!("a={escaped}")
            }
        };

        format!("{flag},{authzid},")
    }

    /// The bytes a mechanism repeats the header over: the header
    /// itself, followed by the binding material when there is any.
    ///
    /// SCRAM base64-encodes this into its `c=` field, so that the flag
    /// the server read arrives again inside a message the client proof
    /// is computed over and cannot have been rewritten in between.
    pub fn cbind_input(&self, authzid: Option<&str>) -> Vec<u8> {
        let mut input = self.header(authzid).into_bytes();

        if let Self::Bound { data, .. } = self {
            input.extend_from_slice(data);
        }

        input
    }
}

/// The channel bindings a TLS connection can offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SaslGs2ChannelBindingKind {
    /// The TLS 1.3 exporter binding ([RFC 9266]), the only one defined
    /// for that version and the one to prefer where both exist.
    ///
    /// [RFC 9266]: https://www.rfc-editor.org/rfc/rfc9266
    TlsExporter,
    /// The finished-message binding of TLS 1.2 and below ([RFC 5929
    /// section 3]).
    ///
    /// [RFC 5929 section 3]: https://www.rfc-editor.org/rfc/rfc5929#section-3
    TlsUnique,
    /// The server-certificate binding ([RFC 5929 section 4]), which
    /// survives a terminating proxy holding the same certificate.
    ///
    /// [RFC 5929 section 4]: https://www.rfc-editor.org/rfc/rfc5929#section-4
    TlsServerEndPoint,
}

impl SaslGs2ChannelBindingKind {
    /// The binding name as registered with IANA and written in the GS2
    /// header.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TlsExporter => "tls-exporter",
            Self::TlsUnique => "tls-unique",
            Self::TlsServerEndPoint => "tls-server-end-point",
        }
    }
}

/// Escapes the separators a GS2 header and a SCRAM message frame their
/// fields with.
pub(crate) fn escape(name: &str) -> String {
    let mut escaped = String::with_capacity(name.len());

    for c in name.chars() {
        match c {
            '=' => escaped.push_str("=3D"),
            ',' => escaped.push_str("=2C"),
            c => escaped.push(c),
        }
    }

    escaped
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use crate::rfc5801::*;

    #[test]
    fn every_flag_opens_the_header_the_rfc_spells() {
        let bound = SaslGs2ChannelBinding::Bound {
            kind: SaslGs2ChannelBindingKind::TlsExporter,
            data: vec![],
        };

        assert_eq!(SaslGs2ChannelBinding::Unsupported.header(None), "n,,");
        assert_eq!(SaslGs2ChannelBinding::Unused.header(None), "y,,");
        assert_eq!(bound.header(None), "p=tls-exporter,,");
    }

    #[test]
    fn the_authorization_identity_is_escaped() {
        let header = SaslGs2ChannelBinding::Unsupported.header(Some("a=b,c"));

        assert_eq!(header, "n,a=a=3Db=2Cc,");
    }

    #[test]
    fn the_binding_material_follows_the_header_it_is_repeated_over() {
        let bound = SaslGs2ChannelBinding::Bound {
            kind: SaslGs2ChannelBindingKind::TlsUnique,
            data: vec![0, 1, 2],
        };

        assert_eq!(bound.cbind_input(None), b"p=tls-unique,,\0\x01\x02");

        // NOTE: an unbound exchange repeats the header alone, which is
        // what makes c=biws the constant every SCRAM implementation
        // hard-codes.
        let unbound = SaslGs2ChannelBinding::Unsupported.cbind_input(None);

        assert_eq!(unbound, b"n,,");
    }

    #[test]
    fn only_a_bound_exchange_runs_under_the_plus_name() {
        let bound = SaslGs2ChannelBinding::Bound {
            kind: SaslGs2ChannelBindingKind::TlsServerEndPoint,
            data: vec![],
        };

        assert!(!SaslGs2ChannelBinding::Unsupported.is_bound());
        assert!(!SaslGs2ChannelBinding::Unused.is_bound());
        assert!(bound.is_bound());
    }

    #[test]
    fn every_binding_kind_spells_the_name_it_is_registered_under() {
        let kinds = [
            (SaslGs2ChannelBindingKind::TlsExporter, "tls-exporter"),
            (SaslGs2ChannelBindingKind::TlsUnique, "tls-unique"),
            (
                SaslGs2ChannelBindingKind::TlsServerEndPoint,
                "tls-server-end-point",
            ),
        ];

        for (kind, name) in kinds {
            assert_eq!(kind.as_str(), name, "{kind:?}");
        }
    }
}
