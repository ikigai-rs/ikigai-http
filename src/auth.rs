//! `Authorization` header values: build `Basic` (RFC 7617) and `Bearer` (RFC 6750)
//! credentials, and recognize the scheme of an incoming value (RFC 9110 §11).
//!
//! The ecosystem's one implementation (ledger #1857): a module that sends or reads an
//! `Authorization` header calls these rather than formatting `"Basic "` and base64 by
//! hand. Shared vectors in `tests/vectors/auth_vectors.json`, hand-written from the
//! RFCs, pin the behavior; the Python and Deno faces pin a byte-identical copy, so
//! the refusal codes ([`AuthError::code`]) are part of the contract.
//!
//! **No credential leaves through a side door.** An [`Authorization`] is a credential,
//! so its `Debug` names the scheme and redacts the rest, and it has no `Display`: the
//! value is reached only through [`Authorization::as_str`] or
//! [`Authorization::into_string`], at the one place it goes into a header. An
//! [`AuthError`] names which rule was broken and never carries the user id, the
//! password or the token.
//!
//! Where credentials come from is not this module's business: a caller reads them from
//! `ikigai-secret` by name at call time and hands them here.

use std::fmt;

/// A built `Authorization` header value, such as `Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==`.
///
/// It is a credential: `Debug` shows only the scheme, and there is no `Display`.
///
/// ```
/// let auth = ikigai_http::auth::basic("Aladdin", "open sesame").unwrap();
/// assert_eq!(format!("{auth:?}"), "Authorization(Basic <redacted>)");
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Authorization {
    scheme: Known,
    value: String,
}

/// The schemes this module BUILDS. ([`Scheme`] is the wider set it recognizes.)
#[derive(Clone, Copy, PartialEq, Eq)]
enum Known {
    Basic,
    Bearer,
}

impl Known {
    fn name(self) -> &'static str {
        match self {
            Known::Basic => "Basic",
            Known::Bearer => "Bearer",
        }
    }
}

impl Authorization {
    fn new(scheme: Known, credentials: &str) -> Self {
        let name = scheme.name();
        let mut value = String::with_capacity(name.len() + 1 + credentials.len());
        value.push_str(name);
        value.push(' ');
        value.push_str(credentials);
        Authorization { scheme, value }
    }

    /// The whole header value, scheme included: what goes after `Authorization: `.
    ///
    /// ```
    /// let auth = ikigai_http::auth::bearer("mF_9.B5f-4.1JqM").unwrap();
    /// assert_eq!(auth.as_str(), "Bearer mF_9.B5f-4.1JqM");
    /// ```
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// The whole header value as an owned `String`, for a header list that owns its
    /// values.
    ///
    /// ```
    /// let auth = ikigai_http::auth::basic("Aladdin", "open sesame").unwrap();
    /// let headers = vec![("Authorization".to_string(), auth.into_string())];
    /// assert_eq!(headers[0].1, "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    /// ```
    pub fn into_string(self) -> String {
        self.value
    }

    /// The credentials alone, after the scheme and its space: the token68 of a `Basic`
    /// value, the token of a `Bearer` one. A caller that scrubs secrets out of error
    /// text scrubs this as well as the raw password, since it is the password in
    /// another encoding.
    ///
    /// ```
    /// let auth = ikigai_http::auth::basic("Aladdin", "open sesame").unwrap();
    /// assert_eq!(auth.credentials(), "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    /// ```
    pub fn credentials(&self) -> &str {
        &self.value[self.scheme.name().len() + 1..]
    }

    /// The scheme this value was built in.
    ///
    /// ```
    /// use ikigai_http::auth::{bearer, Scheme};
    /// assert_eq!(bearer("abc").unwrap().scheme(), Scheme::Bearer);
    /// ```
    pub fn scheme(&self) -> Scheme<'static> {
        match self.scheme {
            Known::Basic => Scheme::Basic,
            Known::Bearer => Scheme::Bearer,
        }
    }
}

impl fmt::Debug for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Authorization({} <redacted>)", self.scheme.name())
    }
}

/// Build a `Basic` credential (RFC 7617 §2): base64 of `user-id ":" password`, both
/// encoded as UTF-8 (the `charset="UTF-8"` of §2.1, the only encoding this module
/// sends).
///
/// Refused, in this order, so every face reports the same code for the same input:
/// 1. a user id containing `:` ([`AuthError::UserIdColon`]): the first colon
///    separates user id from password, so such a user id cannot be encoded (§2);
/// 2. a control character in the user id, then in the password
///    ([`AuthError::ControlCharacter`]): §2 forbids RFC 5234's `CTL` (U+0000–U+001F
///    and U+007F), and the PRECIS profiles §2.1 names for UTF-8 (RFC 7613) disallow
///    every Unicode control character, so U+0080–U+009F are refused too.
///
/// An empty user id or password is legal (`*TEXT`). No normalization is applied: the
/// characters given are the characters encoded, so a caller that needs RFC 7613's
/// NFC form normalizes first.
///
/// ```
/// use ikigai_http::auth::{basic, AuthError, Field};
///
/// // RFC 7617 §2's example, and §2.1's UTF-8 one (U+00A3 POUND SIGN).
/// assert_eq!(
///     basic("Aladdin", "open sesame").unwrap().as_str(),
///     "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
/// );
/// assert_eq!(basic("test", "123\u{a3}").unwrap().as_str(), "Basic dGVzdDoxMjPCow==");
///
/// assert_eq!(basic("Ala:ddin", "x"), Err(AuthError::UserIdColon));
/// let refused = basic("Aladdin", "open\nsesame").unwrap_err();
/// assert_eq!(refused, AuthError::ControlCharacter(Field::Password));
/// // The refusal names the rule, never the password.
/// assert!(!refused.to_string().contains("sesame"));
/// ```
pub fn basic(user: &str, password: &str) -> Result<Authorization, AuthError> {
    if user.contains(':') {
        return Err(AuthError::UserIdColon);
    }
    if user.chars().any(char::is_control) {
        return Err(AuthError::ControlCharacter(Field::UserId));
    }
    if password.chars().any(char::is_control) {
        return Err(AuthError::ControlCharacter(Field::Password));
    }
    let mut user_pass = String::with_capacity(user.len() + 1 + password.len());
    user_pass.push_str(user);
    user_pass.push(':');
    user_pass.push_str(password);
    Ok(Authorization::new(
        Known::Basic,
        &crate::base64::encode(user_pass.as_bytes()),
    ))
}

/// Build a `Bearer` credential (RFC 6750 §2.1). The token must match `b64token`:
/// one or more of `A–Z a–z 0–9 - . _ ~ + /`, then any number of `=`. Anything else (an
/// empty token, a space, a quote, a comma, `=` before the end, any non-ASCII character)
/// is refused with [`AuthError::BearerToken`], since it would not survive as one
/// header token.
///
/// The token is opaque: it is not decoded or otherwise interpreted.
///
/// ```
/// use ikigai_http::auth::{bearer, AuthError};
///
/// // RFC 6750 §2.1's example.
/// assert_eq!(bearer("mF_9.B5f-4.1JqM").unwrap().as_str(), "Bearer mF_9.B5f-4.1JqM");
/// assert_eq!(bearer("abc==").unwrap().as_str(), "Bearer abc==");
/// for bad in ["", "a b", "=abc", "a=b", "tok\"en"] {
///     assert_eq!(bearer(bad).unwrap_err(), AuthError::BearerToken);
/// }
/// ```
pub fn bearer(token: &str) -> Result<Authorization, AuthError> {
    let body = token.trim_end_matches('=');
    let b64token = !body.is_empty()
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b));
    if !b64token {
        return Err(AuthError::BearerToken);
    }
    Ok(Authorization::new(Known::Bearer, token))
}

/// An authentication scheme, as [`scheme`] recognizes it. Scheme names are
/// case-insensitive (RFC 9110 §11.1), so `Basic`, `basic` and `BASIC` are all
/// [`Scheme::Basic`].
///
/// Non-exhaustive: a later minor release may give a scheme its own variant (`Digest`,
/// `DPoP`), and a value in that scheme then stops arriving as [`Scheme::Other`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scheme<'a> {
    /// `Basic` (RFC 7617).
    Basic,
    /// `Bearer` (RFC 6750).
    Bearer,
    /// Any other syntactically valid scheme, spelled as it arrived.
    Other(&'a str),
}

impl Scheme<'_> {
    /// The scheme's name: the registered spelling for a known scheme, the spelling
    /// that arrived for [`Scheme::Other`].
    ///
    /// ```
    /// use ikigai_http::auth::scheme;
    /// assert_eq!(scheme("BASIC x").unwrap().0.name(), "Basic");
    /// assert_eq!(scheme("digest x").unwrap().0.name(), "digest");
    /// ```
    pub fn name(&self) -> &str {
        match self {
            Scheme::Basic => "Basic",
            Scheme::Bearer => "Bearer",
            Scheme::Other(name) => name,
        }
    }
}

/// Split an incoming `Authorization` (or `Proxy-Authorization`) value into its scheme
/// and the credentials after it (RFC 9110 §11.4: `auth-scheme [ 1*SP ( token68 /
/// #auth-param ) ]`).
///
/// Leading and trailing whitespace is trimmed (it is field-value padding, not part of
/// the value), and spaces or tabs between scheme and credentials are skipped. The
/// credentials come back as they arrived, unvalidated and possibly empty (`"Bearer"`
/// alone is the scheme with no token): what they must look like is each scheme's
/// business. `None` when there is no scheme, or the scheme is not an RFC 9110 `token`.
///
/// ```
/// use ikigai_http::auth::{scheme, Scheme};
///
/// assert_eq!(
///     scheme("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
///     Some((Scheme::Basic, "QWxhZGRpbjpvcGVuIHNlc2FtZQ==")),
/// );
/// assert_eq!(scheme("bearer   tok "), Some((Scheme::Bearer, "tok")));
/// assert_eq!(scheme("Bearer"), Some((Scheme::Bearer, "")));
/// assert_eq!(scheme("Digest a=b"), Some((Scheme::Other("Digest"), "a=b")));
/// assert_eq!(scheme(""), None);
/// assert_eq!(scheme("B@sic x"), None);
/// ```
pub fn scheme(value: &str) -> Option<(Scheme<'_>, &str)> {
    let value = value.trim_matches([' ', '\t']);
    let end = value.find([' ', '\t']).unwrap_or(value.len());
    let (name, rest) = value.split_at(end);
    if name.is_empty() || !name.bytes().all(is_tchar) {
        return None;
    }
    let scheme = if name.eq_ignore_ascii_case("basic") {
        Scheme::Basic
    } else if name.eq_ignore_ascii_case("bearer") {
        Scheme::Bearer
    } else {
        Scheme::Other(name)
    };
    Some((scheme, rest.trim_start_matches([' ', '\t'])))
}

/// RFC 9110 §5.6.2 `tchar`.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Which half of a `Basic` credential broke a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    /// The user id.
    UserId,
    /// The password.
    Password,
}

/// A credential this module refuses to build. It names the rule, never the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthError {
    /// A `Basic` user id containing `:` (RFC 7617 §2).
    UserIdColon,
    /// A control character in a `Basic` user id or password (RFC 7617 §2).
    ControlCharacter(Field),
    /// A `Bearer` token that is not an RFC 6750 §2.1 `b64token`.
    BearerToken,
}

impl AuthError {
    /// The stable code the shared vectors pin, identical in every face:
    /// `basic-user-id-colon`, `basic-user-id-control`, `basic-password-control` or
    /// `bearer-token-syntax`.
    ///
    /// ```
    /// let err = ikigai_http::auth::basic("a:b", "c").unwrap_err();
    /// assert_eq!(err.code(), "basic-user-id-colon");
    /// ```
    pub fn code(&self) -> &'static str {
        match self {
            AuthError::UserIdColon => "basic-user-id-colon",
            AuthError::ControlCharacter(Field::UserId) => "basic-user-id-control",
            AuthError::ControlCharacter(Field::Password) => "basic-password-control",
            AuthError::BearerToken => "bearer-token-syntax",
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AuthError::UserIdColon => {
                "a Basic user id must not contain `:` (RFC 7617 §2): the first colon \
                 separates it from the password"
            }
            AuthError::ControlCharacter(Field::UserId) => {
                "a Basic user id must not contain a control character (RFC 7617 §2)"
            }
            AuthError::ControlCharacter(Field::Password) => {
                "a Basic password must not contain a control character (RFC 7617 §2)"
            }
            AuthError::BearerToken => {
                "a Bearer token must be an RFC 6750 §2.1 b64token: one or more of \
                 A-Z a-z 0-9 - . _ ~ + /, then any number of `=`"
            }
        })
    }
}

impl std::error::Error for AuthError {}
