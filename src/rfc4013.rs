//! SASLprep ([RFC 4013]), the string preparation PLAIN and SCRAM ask
//! for.
//!
//! Two ends of an exchange have to agree on the bytes a password is
//! before they can agree on a hash of it. A server preparing what it
//! stores and a client sending what the user typed will differ on any
//! password carrying a non-breaking space, a soft hyphen, a fullwidth
//! character or a decomposed accent, and the failure looks like a wrong
//! password with nothing to point at. So [RFC 4616] and [RFC 5802] both
//! say the client prepares, and this module is what they mean.
//!
//! ## What preparation does
//!
//! Three steps, in order. Non-ASCII spaces become an ASCII space, the
//! characters [RFC 3454] appendix B.1 calls commonly mapped to nothing
//! are removed, and the result is normalized to NFKC, which is what
//! folds a decomposed accent and a fullwidth digit onto the forms a
//! server stores. What comes out is then checked for the code points the
//! profile prohibits.
//!
//! ## What it deliberately leaves out
//!
//! Two of the checks RFC 3454 lists are not made here, and neither
//! changes the bytes a client sends. The bidirectional rule of section
//! 6 rejects strings mixing right-to-left and left-to-right in
//! forbidden ways, and the unassigned code points of appendix A.1 are
//! prohibited in stored strings. Both need Unicode tables far larger
//! than the mapping does, both reject rather than transform, and a
//! server enforcing them will reject the same string anyway. Their
//! absence is a smaller string checker, never a different password.
//!
//! [RFC 3454]: https://www.rfc-editor.org/rfc/rfc3454
//! [RFC 4013]: https://www.rfc-editor.org/rfc/rfc4013
//! [RFC 4616]: https://www.rfc-editor.org/rfc/rfc4616
//! [RFC 5802]: https://www.rfc-editor.org/rfc/rfc5802

use alloc::string::String;

use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

/// Failure causes of the preparation.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SaslPrepError {
    /// The string carries a code point the profile prohibits, listed
    /// with the character that broke it.
    #[error("SASLprep failed: prohibited character U+{:04X}", u32::from(*.0))]
    ProhibitedCharacter(char),
}

/// Prepares a username or a password as [RFC 4013] asks, mapping,
/// normalizing and then checking what came out.
///
/// [RFC 4013]: https://www.rfc-editor.org/rfc/rfc4013
pub fn saslprep(input: &str) -> Result<String, SaslPrepError> {
    // NOTE: spaces are mapped before the removals, which is the order
    // every implementation settled on and the one that matters for
    // U+200B, a character both tables claim. Mapping it to a space
    // rather than deleting it keeps a word boundary the user typed.
    let mapped = input
        .chars()
        .map(|c| match is_non_ascii_space(c) {
            true => ' ',
            false => c,
        })
        .filter(|c| !is_mapped_to_nothing(*c));

    let prepared: String = mapped.nfkc().collect();

    match prepared.chars().find(|c| is_prohibited(*c)) {
        Some(prohibited) => Err(SaslPrepError::ProhibitedCharacter(prohibited)),
        None => Ok(prepared),
    }
}

/// The non-ASCII spaces of [RFC 3454] appendix C.1.2, which become an
/// ASCII space.
///
/// [RFC 3454]: https://www.rfc-editor.org/rfc/rfc3454
fn is_non_ascii_space(c: char) -> bool {
    matches!(
        c,
        '\u{00a0}' | '\u{1680}' | '\u{2000}'..='\u{200b}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
    )
}

/// The characters [RFC 3454] appendix B.1 maps to nothing, joiners and
/// selectors a user cannot see and a server will not store.
///
/// [RFC 3454]: https://www.rfc-editor.org/rfc/rfc3454
fn is_mapped_to_nothing(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{1806}'
            | '\u{180b}'..='\u{180d}'
            | '\u{200b}'..='\u{200d}'
            | '\u{2060}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
    )
}

/// The code points the profile prohibits in its output, gathering the
/// tables of [RFC 4013] section 2.3 that are ranges rather than lists.
///
/// [RFC 4013]: https://www.rfc-editor.org/rfc/rfc4013
fn is_prohibited(c: char) -> bool {
    // NOTE: C.5, the surrogate codes, is absent on purpose: a Rust char
    // cannot hold one, so the check would be unreachable.
    is_control(c)
        || is_private_use(c)
        || is_non_character(c)
        || is_inappropriate(c)
        || is_change_display(c)
        || is_tagging(c)
}

/// The ASCII and non-ASCII controls of appendices C.2.1 and C.2.2.
fn is_control(c: char) -> bool {
    matches!(
        c,
        '\u{0000}'..='\u{001f}'
            | '\u{007f}'..='\u{009f}'
            | '\u{06dd}'
            | '\u{070f}'
            | '\u{180e}'
            | '\u{200c}'
            | '\u{200d}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{2060}'..='\u{2063}'
            | '\u{206a}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffc}'
            | '\u{1d173}'..='\u{1d17a}'
    )
}

/// The private use areas of appendix C.3.
fn is_private_use(c: char) -> bool {
    matches!(
        c,
        '\u{e000}'..='\u{f8ff}' | '\u{f0000}'..='\u{ffffd}' | '\u{100000}'..='\u{10fffd}'
    )
}

/// The non-character code points of appendix C.4.
fn is_non_character(c: char) -> bool {
    let code = u32::from(c);

    matches!(c, '\u{fdd0}'..='\u{fdef}') || matches!(code & 0xfffe, 0xfffe)
}

/// The code points inappropriate for plain text or for canonical
/// representation, appendices C.6 and C.7.
fn is_inappropriate(c: char) -> bool {
    matches!(c, '\u{fff9}'..='\u{fffd}' | '\u{2ff0}'..='\u{2ffb}')
}

/// The characters changing display properties or deprecated, appendix
/// C.8.
fn is_change_display(c: char) -> bool {
    matches!(
        c,
        '\u{0340}' | '\u{0341}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{206a}'..='\u{206f}'
    )
}

/// The tagging characters of appendix C.9.
fn is_tagging(c: char) -> bool {
    matches!(c, '\u{e0001}' | '\u{e0020}'..='\u{e007f}')
}

#[cfg(test)]
mod tests {
    use crate::rfc4013::*;

    #[test]
    fn the_rfc_4013_examples_prepare_the_way_it_says() {
        // NOTE: the four examples of RFC 4013 section 3, which are the
        // only ones the profile publishes: a soft hyphen disappears
        // from a password, a non-ASCII space becomes an ASCII one, a
        // fullwidth string folds onto its ASCII form, and a prohibited
        // character is refused.
        assert_eq!(saslprep("I\u{00ad}X").unwrap(), "IX");
        assert_eq!(saslprep("user").unwrap(), "user");
        assert_eq!(saslprep("USER").unwrap(), "USER");
        assert_eq!(saslprep("\u{00aa}").unwrap(), "a");
        assert_eq!(saslprep("\u{2168}").unwrap(), "IX");
        assert_eq!(
            saslprep("\u{0007}"),
            Err(SaslPrepError::ProhibitedCharacter('\u{0007}')),
        );
    }

    #[test]
    fn a_non_ascii_space_becomes_the_ascii_one() {
        assert_eq!(saslprep("a\u{00a0}b").unwrap(), "a b");
        assert_eq!(saslprep("a\u{3000}b").unwrap(), "a b");

        // NOTE: U+200B sits in both tables, and the space mapping wins,
        // so the word boundary survives instead of vanishing.
        assert_eq!(saslprep("a\u{200b}b").unwrap(), "a b");
    }

    #[test]
    fn a_decomposed_accent_folds_onto_its_composed_form() {
        // NOTE: this is the interoperability failure the whole module
        // exists for: two spellings of the same password hash to two
        // different things unless both ends normalize.
        assert_eq!(saslprep("e\u{0301}").unwrap(), "\u{00e9}");
        assert_eq!(saslprep("\u{00e9}").unwrap(), "\u{00e9}");
    }

    #[test]
    fn every_prohibited_class_is_refused() {
        let prohibited = [
            ('\u{0000}', "an ASCII control"),
            ('\u{0085}', "a non-ASCII control"),
            ('\u{e000}', "a private use character"),
            ('\u{fdd0}', "a non-character"),
            ('\u{fffe}', "a plane-final non-character"),
            ('\u{2ff0}', "an ideographic description character"),
            ('\u{202a}', "a display-changing character"),
            ('\u{e0001}', "a tagging character"),
        ];

        for (c, what) in prohibited {
            let mut input = String::from("pencil");
            input.push(c);

            assert_eq!(
                saslprep(&input),
                Err(SaslPrepError::ProhibitedCharacter(c)),
                "{what} was accepted",
            );
        }
    }

    #[test]
    fn a_character_normalization_removes_is_never_reached_by_the_prohibition() {
        // NOTE: U+0340 is prohibited by appendix C.8 and cannot survive
        // NFKC, which folds it onto U+0300. The order the profile
        // specifies, normalize then check, is what makes this a
        // preparation rather than a refusal, and checking first would
        // reject a password the server accepts.
        assert_eq!(saslprep("e\u{0340}").unwrap(), "\u{00e8}");
    }

    #[test]
    fn an_invisible_character_leaves_nothing_behind() {
        assert_eq!(saslprep("pen\u{00ad}cil").unwrap(), "pencil");
        assert_eq!(saslprep("pen\u{fe00}cil").unwrap(), "pencil");
    }
}
