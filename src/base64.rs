//! One base64 for the ecosystem: RFC 4648 §4, the standard alphabet, with padding.
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
//! - **This module is a two-function face over it**, so a module that does not
//!   otherwise depend on `base64` does not need to, and so the profile is chosen in
//!   one place: the STANDARD alphabet (`+` and `/`), padding required on decode,
//!   canonical only (RFC 4648 §3.5: nonzero pad bits are refused), and no whitespace
//!   or other non-alphabet character accepted (§3.3: "MUST reject"). No type of the
//!   `base64` crate appears in this API, so the implementation behind it can change
//!   without a breaking release.
//! - **URL-safe (§5) is not exposed** because nothing needs it yet. PKCE, DPoP and JWS
//!   will (base64url without padding); add it here, with vectors, when the first of
//!   them lands.
//!
//! The vectors are `tests/vectors/auth_vectors.json`, hand-written from RFC 4648 §10;
//! the Python and Deno faces pin a byte-identical copy.

use std::fmt;

use ::base64::engine::general_purpose::STANDARD;
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
    STANDARD.decode(text).map_err(|e| Base64Error {
        kind: match e {
            DecodeError::InvalidByte(..) => Kind::Symbol,
            DecodeError::InvalidLength(_) => Kind::Length,
            DecodeError::InvalidLastSymbol(..) => Kind::PadBits,
            DecodeError::InvalidPadding => Kind::Padding,
        },
    })
}

/// Input that is not canonical standard-alphabet base64. Carries the reason only:
/// never the input, a byte of it, or an offset into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Base64Error {
    kind: Kind,
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
        let err = decode(secret).unwrap_err();
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains("c2VjcmV0"), "the error echoed its input");
        assert!(!shown.contains('!'), "the error echoed the offending byte");
    }
}
