//! Runs every case in `tests/vectors/auth_vectors.json`, the shared Authorization and
//! base64 vectors (ledger #1857). The file is hand-written from the RFCs; the Python
//! and Deno faces pin a byte-identical copy, so a case that fails here is a case
//! where this face disagrees with the standard, not with itself.
//!
//! Failure messages name the CASE, never a credential: a refused password must not
//! reach test output either.

use ikigai_http::auth::{self, Scheme};
use ikigai_http::base64;
use serde_json::Value;

const VECTORS: &str = include_str!("vectors/auth_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("auth_vectors.json is valid JSON")
}

fn cases<'a>(v: &'a Value, key: &str) -> &'a Vec<Value> {
    let cases = v[key]
        .as_array()
        .unwrap_or_else(|| panic!("`{key}` is an array"));
    assert!(!cases.is_empty(), "`{key}` has cases");
    cases
}

fn s<'a>(case: &'a Value, key: &str) -> &'a str {
    case[key]
        .as_str()
        .unwrap_or_else(|| panic!("case {} has a string `{key}`", case["name"]))
}

#[test]
fn the_file_is_ascii_with_lf_line_endings() {
    // Byte-identical copies elsewhere: no CR (the .gitattributes `eol=lf` holds), and
    // non-ASCII only as \u escapes, so no editor or platform re-encodes it.
    assert!(!VECTORS.contains('\r'), "auth_vectors.json has a CR");
    assert!(VECTORS.is_ascii(), "auth_vectors.json is not ASCII");
    assert_eq!(vectors()["version"], 1);
}

#[test]
fn basic_builds_every_rfc_value() {
    let v = vectors();
    for case in cases(&v, "basic") {
        let name = s(case, "name");
        let auth = auth::basic(s(case, "user"), s(case, "password"))
            .unwrap_or_else(|e| panic!("{name}: refused with {}", e.code()));
        assert!(auth.as_str() == s(case, "expect"), "{name}: wrong value");
        assert_eq!(auth.scheme(), Scheme::Basic, "{name}");
        assert!(
            auth.credentials() == &s(case, "expect")["Basic ".len()..],
            "{name}: credentials() is not the token68"
        );
    }
}

#[test]
fn basic_refuses_with_the_pinned_code_and_never_echoes_the_password() {
    let v = vectors();
    for case in cases(&v, "basic_refusals") {
        let name = s(case, "name");
        let (user, password) = (s(case, "user"), s(case, "password"));
        let Err(err) = auth::basic(user, password) else {
            panic!("{name}: built a value it should refuse");
        };
        assert_eq!(err.code(), s(case, "error"), "{name}");
        let shown = format!("{err} {err:?}");
        if !password.is_empty() {
            assert!(
                !shown.contains(password),
                "{name}: the error shows the password"
            );
        }
        if !user.is_empty() {
            assert!(!shown.contains(user), "{name}: the error shows the user id");
        }
    }
}

#[test]
fn bearer_accepts_every_b64token() {
    let v = vectors();
    for case in cases(&v, "bearer") {
        let name = s(case, "name");
        let auth = auth::bearer(s(case, "token"))
            .unwrap_or_else(|e| panic!("{name}: refused with {}", e.code()));
        assert!(auth.as_str() == s(case, "expect"), "{name}: wrong value");
        assert!(auth.credentials() == s(case, "token"), "{name}");
        assert_eq!(auth.scheme(), Scheme::Bearer, "{name}");
    }
}

#[test]
fn bearer_refuses_everything_else_without_echoing_it() {
    let v = vectors();
    for case in cases(&v, "bearer_refusals") {
        let name = s(case, "name");
        let token = s(case, "token");
        let Err(err) = auth::bearer(token) else {
            panic!("{name}: built a value it should refuse");
        };
        assert_eq!(err.code(), s(case, "error"), "{name}");
        if token.trim().len() > 2 {
            assert!(!format!("{err} {err:?}").contains(token.trim()), "{name}");
        }
    }
}

#[test]
fn scheme_splits_every_value() {
    let v = vectors();
    for case in cases(&v, "scheme") {
        let name = s(case, "name");
        let got = auth::scheme(s(case, "value"));
        let expect = &case["expect"];
        if expect.is_null() {
            assert!(
                got.is_none(),
                "{name}: recognized a scheme in a malformed value"
            );
            continue;
        }
        let (scheme, credentials) = got.unwrap_or_else(|| panic!("{name}: no scheme"));
        let kind = match scheme {
            Scheme::Basic => "basic",
            Scheme::Bearer => "bearer",
            Scheme::Other(_) => "other",
            _ => "unknown",
        };
        assert_eq!(kind, s(expect, "scheme"), "{name}");
        assert_eq!(scheme.name(), s(expect, "name"), "{name}");
        assert_eq!(credentials, s(expect, "credentials"), "{name}");
    }
}

fn bytes_of(case: &Value) -> Vec<u8> {
    match case.get("hex") {
        Some(hex) => {
            let hex = hex.as_str().expect("hex is a string");
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digits"))
                .collect()
        }
        None => s(case, "text").as_bytes().to_vec(),
    }
}

#[test]
fn base64_round_trips_every_rfc_vector() {
    let v = vectors();
    for case in cases(&v, "base64") {
        let name = s(case, "name");
        let bytes = bytes_of(case);
        assert_eq!(base64::encode(&bytes), s(case, "encoded"), "{name}: encode");
        assert_eq!(
            base64::decode(s(case, "encoded")).ok(),
            Some(bytes),
            "{name}: decode"
        );
    }
}

#[test]
fn base64_refuses_every_noncanonical_input() {
    let v = vectors();
    for case in cases(&v, "base64_refusals") {
        let name = s(case, "name");
        let err = base64::decode(s(case, "encoded"))
            .err()
            .unwrap_or_else(|| panic!("{name}: decoded input it should refuse"));
        assert_eq!(err.code(), s(case, "error"), "{name}");
    }
}

#[test]
fn a_built_credential_never_shows_in_debug() {
    let basic = auth::basic("Aladdin", "open sesame").unwrap();
    let shown = format!("{basic:?}");
    assert_eq!(shown, "Authorization(Basic <redacted>)");
    assert!(!shown.contains(basic.credentials()));
    let bearer = auth::bearer("mF_9.B5f-4.1JqM").unwrap();
    assert_eq!(format!("{bearer:?}"), "Authorization(Bearer <redacted>)");
}
