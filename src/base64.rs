//! Base64 for the ecosystem: RFC 4648 standard padded and URL-safe unpadded profiles.
//!
//! ## The decision (ledger #1857)
//!
//! Three hand-rolled RFC 4648 encoders had grown in the ecosystem (ikigai-personal's
//! CalDAV `basic_auth`, ikigai-meeting's Zoom token request, the cli's OSC 52
//! clipboard). Each was correct, and each was a place where a fix would land once and
//! be missed twice. So the ecosystem has ONE base64, decided here:
//!
//! - **The vetted [`base64`](https://crates.io/crates/base64) crate, not a fourth
//!   implementation.** It is the most widely used Rust implementation, has no
//!   dependencies of its own, builds for wasm32, and is ALREADY in the graph of the
//!   repos that adopt this helper (ikigai-cli depends on `base64 = "0.22"` for its
//!   layer files, and ikigai-gonk resolves 0.22.1), so pinning the same 0.22 line here
//!   adds no second copy to those builds. A standard is implemented once, by the
//!   people who maintain it; our part is choosing the profile and pinning it with
//!   vectors.
//! - **This module is a small face over it**, so a module that does not
//!   otherwise depend on `base64` does not need to, and so the profile is chosen in
//!   one place: the STANDARD alphabet (`+` and `/`), padding required on decode,
//!   canonical only (RFC 4648 §3.5: nonzero pad bits are refused), and no whitespace
//!   or other non-alphabet character accepted (§3.3: "MUST reject"). No type of the
//!   `base64` crate appears in this API, so the implementation behind it can change
//!   without a breaking release.
//! - **URL-safe (§5), without padding**, is exposed through [`encode_url`] and
//!   [`decode_url`] for signatures, PKCE, DPoP and JWS (ledger #1869). This profile
//!   uses `-` and `_`, refuses all padding, and requires canonical zero trailing bits.
//!   The standard profile remains unchanged.
//!
//! The vectors are `tests/vectors/auth_vectors.json`, hand-written from RFC 4648 §10;
//! the Python and Deno faces pin a byte-identical copy.

use std::fmt;

use ::base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ::base64::{DecodeError, Engine as _};

/// Encode `bytes` as RFC 4648 §4 base64: standard alphabet, padded with `=` to a
/// multiple of four characters.
///
/// ```
/// // RFC 4648 §10's test vectors.
/// assert_eq!(ikigai_http::base64::encode(""), "");
/// assert_eq!(ikigai_http::base64::encode("f"), "Zg==");
/// assert_eq!(ikigai_http::base64::encode("fo"), "Zm8=");
/// assert_eq!(ikigai_http::base64::encode("foobar"), "Zm9vYmFy");
/// // The standard alphabet: 62 is `+` and 63 is `/` (not URL-safe `-` and `_`).
/// assert_eq!(ikigai_http::base64::encode([0xfb, 0xff]), "+/8=");
/// ```
pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    STANDARD.encode(bytes)
}

/// Decode canonical RFC 4648 §4 base64: the standard alphabet, padding required, pad
/// bits zero, and nothing else in the input (no whitespace, no line breaks).
///
/// The error never carries the input or any byte of it, since what is being decoded is
/// often a credential (the token68 of a `Basic` header).
///
/// ```
/// assert_eq!(ikigai_http::base64::decode("Zm9vYg==").unwrap(), b"foob");
/// // Unpadded, non-alphabet and non-canonical input is refused, all with one code.
/// for bad in ["Zm9vYg", "Zm9v Yg==", "Zm9vYh=="] {
///     let err = ikigai_http::base64::decode(bad).unwrap_err();
///     assert_eq!(err.code(), "base64-invalid");
/// }
/// ```
pub fn decode(text: impl AsRef<[u8]>) -> Result<Vec<u8>, Base64Error> {
    STANDARD.decode(text).map_err(|e| decode_error(e, false))
}

/// Encode RFC 4648 §5 base64url using `-` and `_`, without `=` padding.
///
/// ```
/// assert_eq!(ikigai_http::base64::encode_url("f"), "Zg");
/// assert_eq!(ikigai_http::base64::encode_url([0xfb, 0xff]), "-_8");
/// ```
pub fn encode_url(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode canonical, unpadded RFC 4648 §5 base64url.
///
/// Rejects padding, standard-alphabet `+` and `/`, whitespace, invalid lengths,
/// and nonzero unused bits in the last symbol. Errors never carry input bytes.
///
/// ```
/// assert_eq!(ikigai_http::base64::decode_url("-_8").unwrap(), [0xfb, 0xff]);
/// for bad in ["Zg==", "+/8", "Z g", "A", "Zh", "Zm9"] {
///     assert_eq!(ikigai_http::base64::decode_url(bad).unwrap_err().code(), "base64-invalid");
/// }
/// ```
pub fn decode_url(text: impl AsRef<[u8]>) -> Result<Vec<u8>, Base64Error> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|e| decode_error(e, true))
}

fn decode_error(error: DecodeError, url_safe: bool) -> Base64Error {
    Base64Error {
        url_safe,
        kind: match error {
            DecodeError::InvalidByte(..) => Kind::Symbol,
            DecodeError::InvalidLength(_) => Kind::Length,
            DecodeError::InvalidLastSymbol(..) => Kind::PadBits,
            DecodeError::InvalidPadding => Kind::Padding,
        },
    }
}

/// Input that is not canonical base64 for the requested profile. Carries the reason only:
/// never the input, a byte of it, or an offset into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Base64Error {
    kind: Kind,
    url_safe: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Symbol,
    Length,
    PadBits,
    Padding,
}

impl Base64Error {
    /// The stable code the shared vectors pin: `base64-invalid` for every refusal.
    /// The reason in [`Display`](fmt::Display) is for people; it is not pinned, since
    /// which reason a malformed input earns is implementation detail that other
    /// languages' decoders classify differently.
    ///
    /// ```
    /// let err = ikigai_http::base64::decode("Zg=").unwrap_err();
    /// assert_eq!(err.code(), "base64-invalid");
    /// ```
    pub fn code(&self) -> &'static str {
        "base64-invalid"
    }
}

impl fmt::Display for Base64Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.url_safe {
            let why = match self.kind {
                Kind::Symbol => "a character outside the URL-safe alphabet, or misplaced padding",
                Kind::Length => "a length that no unpadded encoding has",
                Kind::PadBits => "nonzero unused bits in the last symbol (RFC 4648 §3.5)",
                Kind::Padding => "padding is not allowed",
            };
            return write!(
                f,
                "not canonical base64url (RFC 4648 §5, URL-safe alphabet, unpadded): {why}"
            );
        }
        let why = match self.kind {
            Kind::Symbol => "a character outside the standard alphabet, or `=` before the end",
            Kind::Length => "a length that no padded encoding has",
            Kind::PadBits => "nonzero pad bits in the last symbol (RFC 4648 §3.5)",
            Kind::Padding => "missing or wrong `=` padding",
        };
        write!(
            f,
            "not canonical base64 (RFC 4648 §4, standard alphabet, padded): {why}"
        )
    }
}

impl std::error::Error for Base64Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_decode_error_never_echoes_its_input() {
        let secret = "c2VjcmV0!!";
        for err in [decode(secret).unwrap_err(), decode_url(secret).unwrap_err()] {
            let shown = format!("{err} {err:?}");
            assert!(!shown.contains("c2VjcmV0"), "the error echoed its input");
            assert!(!shown.contains('!'), "the error echoed the offending byte");
        }
    }
}
