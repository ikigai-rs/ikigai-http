//! **The one table** from an origin's HTTP answer to an ikigai [`Error`] (0.3.0, ledger
//! #1546, #200, #297). Every module that talks HTTP through an [`HttpTransport`]
//! (ikigai-http's own endpoints, ikigai-llm, ikigai-meeting) calls these functions
//! rather than keeping a copy, so an origin's 429 means the same thing everywhere: the
//! table used to be copied into ikigai-llm, and the copy had already drifted (it typed
//! 401, 403 and 404 as `Endpoint` where this crate said `Denied` and `NotFound`).
//!
//! The variant is the decision; its [`class`](Error::class), which core owns, says who
//! may repeat it. Nothing here keeps a class table of its own.
//!
//! | origin status | [`Error`] | class |
//! | --- | --- | --- |
//! | 2xx, 3xx | none: not an error (304 is metadata-only at the endpoint) | |
//! | 404, 410 | [`NotFound`](Error::NotFound) | permanent |
//! | 401, 403 | [`Refused`](Error::Refused) | refused |
//! | 408, 504 | [`Timeout`](Error::Timeout) | transient |
//! | 409, 412 | [`Conflict`](Error::Conflict) | permanent |
//! | 413, 414, 431 | [`OverBudget`](Error::OverBudget) | over-budget |
//! | 429 | [`RetryAfter`](Error::RetryAfter), delay from `Retry-After` when it parses | retry-after |
//! | 501 | [`Unsupported`](Error::Unsupported) with no verb | permanent |
//! | 502 | [`Unavailable`](Error::Unavailable) | transient |
//! | 503 with a usable `Retry-After` | [`RetryAfter`](Error::RetryAfter) with that delay | retry-after |
//! | 503 without one | [`Unavailable`](Error::Unavailable) | transient |
//! | 500, and every other 5xx | [`Endpoint`](Error::Endpoint) | unknown |
//! | any other status | [`Endpoint`](Error::Endpoint) | unknown |
//!
//! Why each row that a reader might question:
//!
//! - **401/403 is `Refused`, not `Denied`.** `Denied` is the capability floor's word: OUR
//!   grant did not cover the call. An origin's 401/403 refused the credential this
//!   endpoint presented, and only the credential's holder can renew it; the two have
//!   different retry rules, which is what a class exists to carry.
//! - **500 is `Endpoint` (unknown), not transient.** An origin's 500 reports its own
//!   failure, and is no promise that asking again helps; our own `Endpoint` is permanent
//!   for the same reason. 505 and the other unnamed 5xx follow it. 502 and a 503 are the
//!   statuses that DO say "a dependency is down now", so they stay transient.
//! - **A 503 is `RetryAfter` only with a delay.** RFC 9110 §10.2.3 gives 503 the same
//!   `Retry-After` header with the same meaning as 429; a 503 without one (or with one
//!   that does not parse) is the ordinary transient `Unavailable`.
//! - **A 429 is `RetryAfter` even without a delay** (`delay: None`, "not now"): it is a
//!   rate limit whatever the header says, and an immediate re-issue goes straight back
//!   into it.
//!
//! ```
//! use std::time::Duration;
//! use ikigai_core::{Error, FailureClass, Time};
//! use ikigai_http::status::{response_error, retry_after, status_error};
//! use ikigai_http::HttpResponse;
//!
//! // The shape a caller sees for each decision the table makes.
//! assert!(status_error(200, None, "HTTP 200").is_none());
//! let refused = status_error(403, None, "HTTP 403").unwrap();
//! assert!(matches!(refused, Error::Refused(_)));
//! assert_eq!(refused.class(), FailureClass::Refused);
//! assert_eq!(refused.to_string(), "refused: HTTP 403");
//! assert_eq!(status_error(500, None, "HTTP 500").unwrap().class(), FailureClass::Unknown);
//!
//! // `Retry-After` in both of its forms: delay-seconds, and an HTTP-date read against
//! // the kernel's clock (here 2015-10-21T07:28:00Z, minus 30 s).
//! let limited = HttpResponse {
//!     status: 429,
//!     headers: vec![("Retry-After".into(), "120".into())],
//!     body: Vec::new().into(),
//! };
//! let err = response_error(&limited, None, "HTTP 429").unwrap();
//! assert_eq!(err.to_string(), "retry after 120000 ms: rate-limited: HTTP 429");
//! assert_eq!(err.retry_after_millis(), Some(120_000));
//!
//! let now = Some(Time::from_millis(1_445_412_480_000 - 30_000));
//! assert_eq!(
//!     retry_after("Wed, 21 Oct 2015 07:28:00 GMT", now),
//!     Some(Duration::from_secs(30))
//! );
//! // An absent or malformed header gives no delay; a 503 then stays transient.
//! assert_eq!(retry_after("soon", now), None);
//! let busy = status_error(503, None, "HTTP 503").unwrap();
//! assert!(matches!(busy, Error::Unavailable(_)) && busy.is_transient());
//! ```
//!
//! [`HttpTransport`]: crate::HttpTransport

use std::time::{Duration, UNIX_EPOCH};

use ikigai_core::{Error, Time};
use url::Url;

use crate::HttpResponse;

/// The [`Error`] for an origin's answer with `status`, or `None` for a success (2xx, or a
/// 3xx the caller did not follow). This classifies errors only: a 304 is not content.
/// The HTTP endpoints return it as uncacheable metadata (`http-status=304`). `retry_after` is the delay the answer carried, already
/// parsed (see [`retry_after`]); it is read only for 429 and 503. `detail` becomes the
/// error's message; for a 429 it is prefixed `rate-limited: `, since a 429 is a rate
/// limit whatever the caller called it. See the [module docs](self) for the table.
///
/// ```
/// use std::time::Duration;
/// use ikigai_core::Error;
/// use ikigai_http::status::status_error;
///
/// let later = status_error(503, Some(Duration::from_secs(5)), "HTTP 503").unwrap();
/// assert!(matches!(later, Error::RetryAfter { delay: Some(d), .. } if d == Duration::from_secs(5)));
/// let limited = status_error(429, None, "HTTP 429").unwrap();
/// assert_eq!(limited.to_string(), "retry later: rate-limited: HTTP 429");
/// assert!(matches!(
///     status_error(501, None, "HTTP 501").unwrap(),
///     Error::Unsupported { verb: None, .. }
/// ));
/// ```
pub fn status_error(
    status: u16,
    retry_after: Option<Duration>,
    detail: impl Into<String>,
) -> Option<Error> {
    let detail = detail.into();
    Some(match status {
        200..=399 => return None,
        404 | 410 => Error::NotFound(detail),
        401 | 403 => Error::Refused(detail),
        408 | 504 => Error::Timeout(detail),
        409 | 412 => Error::Conflict(detail),
        413 | 414 | 431 => Error::OverBudget { detail },
        429 => Error::RetryAfter {
            delay: retry_after,
            detail: format!("rate-limited: {detail}"),
        },
        501 => Error::Unsupported { verb: None, detail },
        502 => Error::Unavailable(detail),
        503 => match retry_after {
            Some(delay) => Error::RetryAfter {
                delay: Some(delay),
                detail,
            },
            None => Error::Unavailable(detail),
        },
        _ => Error::Endpoint(detail),
    })
}

/// [`status_error`] for a whole response: reads its `Retry-After` header through
/// [`retry_after`] against `now` (the kernel's clock, [`Invocation::now`]), so an
/// HTTP-date delay is measured on the same clock as everything else the kernel times.
///
/// Call [`response_error_for_status`] when the caller has already checked that the
/// status is at least 400 and needs an [`Error`] directly.
///
/// [`Invocation::now`]: ikigai_core::Invocation::now
pub fn response_error(
    response: &HttpResponse,
    now: Option<Time>,
    detail: impl Into<String>,
) -> Option<Error> {
    let delay = response
        .header("retry-after")
        .and_then(|value| retry_after(value, now));
    status_error(response.status, delay, detail)
}

/// The non-optional form of [`response_error`] for a response whose status the caller
/// has already checked to be at least 400. Uses the same status table, `Retry-After`
/// parsing, kernel clock, and detail text as [`response_error`].
///
/// It never panics: a status below 400 (a caller that did not check after all) answers
/// `Error::Endpoint(detail)`, the fallback callers used to write by hand. Use
/// [`response_error`] to classify a response whose status has not been checked.
///
/// ```
/// use ikigai_core::Error;
/// use ikigai_http::{HttpResponse, status::response_error_for_status};
///
/// let response = HttpResponse {
///     status: 403,
///     headers: Vec::new(),
///     body: Vec::new().into(),
/// };
/// if response.status >= 400 {
///     let error: Error = response_error_for_status(&response, None, "HTTP 403");
///     assert!(matches!(error, Error::Refused(_)));
/// }
/// ```
pub fn response_error_for_status(
    response: &HttpResponse,
    now: Option<Time>,
    detail: impl Into<String>,
) -> Error {
    let detail = detail.into();
    response_error(response, now, detail.clone()).unwrap_or(Error::Endpoint(detail))
}

/// Parse a `Retry-After` value (RFC 9110 §10.2.3): **delay-seconds** (one or more
/// digits, nothing else), or an **HTTP-date** (any of the three forms RFC 9110 §5.6.7
/// obliges a recipient to accept, parsed by the vetted `httpdate` crate) taken relative
/// to `now`.
///
/// `None` when the value is malformed, and for an HTTP-date when there is no clock to
/// measure it from: no delay is better than a guessed one. A date already past is a zero
/// delay. A delay-seconds too large for a `u64` saturates rather than being refused.
///
/// ```
/// use std::time::Duration;
/// use ikigai_core::Time;
/// use ikigai_http::status::retry_after;
///
/// assert_eq!(retry_after("0", None), Some(Duration::ZERO));
/// assert_eq!(retry_after(" 30 ", None), Some(Duration::from_secs(30)));
/// for malformed in ["", "-1", "+5", "1.5", "30s", "soon"] {
///     assert_eq!(retry_after(malformed, None), None, "{malformed:?}");
/// }
/// // An HTTP-date needs a clock; with one, the delay is the date minus now.
/// let date = "Sun, 06 Nov 1994 08:49:37 GMT"; // 784111777 s after the epoch
/// assert_eq!(retry_after(date, None), None);
/// assert_eq!(
///     retry_after(date, Some(Time::from_millis(784_111_777_000 - 2_500))),
///     Some(Duration::from_millis(2_500))
/// );
/// assert_eq!(retry_after(date, Some(Time::from_millis(784_111_777_000 + 1))), Some(Duration::ZERO));
/// ```
pub fn retry_after(value: &str, now: Option<Time>) -> Option<Duration> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.bytes().all(|b| b.is_ascii_digit()) {
        // Only digits, so a parse failure is an overflow.
        return Some(Duration::from_secs(value.parse().unwrap_or(u64::MAX)));
    }
    let at = httpdate::parse_http_date(value).ok()?;
    let at_ms = at.duration_since(UNIX_EPOCH).ok()?.as_millis();
    let at_ms = u64::try_from(at_ms).unwrap_or(u64::MAX);
    Some(Duration::from_millis(
        at_ms.saturating_sub(now?.as_millis()),
    ))
}

/// The [`Error`] for a request that got **no answer at all**: the host transport's
/// failure string from [`HttpTransport::send`]. A transport that gave up waiting for the
/// origin is a [`Timeout`](Error::Timeout) (a wait on something else ran out, which is
/// worth repeating, not an [`OverBudget`](Error::OverBudget): no bound of OURS was
/// exceeded and the input is not what cost too much); everything else, a refused
/// connection, a DNS failure, a TLS failure, a dropped connection, is
/// [`Unavailable`](Error::Unavailable). Both are transient.
///
/// The trait reports failure as a string, so a timeout can only be recognized by its
/// words ("timed out" or "timeout": ureq, reqwest and a browser's fetch each say one).
/// `url` and its host are removed before looking, so a host named `timeout.example`
/// cannot type its own refusals. `detail` becomes the error's message.
///
/// Common clients name the URL in that string, and a caller may have put a credential in
/// its query (`?api_key=…`) or its userinfo (`user:pass@`). So wherever `url` appears in
/// `detail` it is cut down to its scheme, host, port and path, and its query, fragment
/// and userinfo are removed wherever else they appear (ledger #3767). Every caller gets
/// this, so none has to remember it.
///
/// ```
/// use ikigai_core::Error;
/// use ikigai_http::status::transport_error;
///
/// let url = "http://timeout.example/x";
/// let slow = transport_error("operation timed out", url, "http transport: operation timed out");
/// assert!(matches!(slow, Error::Timeout(_)));
/// let down = transport_error(&format!("connection refused: {url}"), url, "http transport: refused");
/// assert!(matches!(down, Error::Unavailable(_)));
///
/// let url = "https://user:pass@api.example.com/v1/me?api_key=secret";
/// let said = format!("error sending request for url ({url})");
/// let err = transport_error(&said, url, format!("http transport: {said}"));
/// assert_eq!(
///     err.to_string(),
///     "unavailable: http transport: error sending request for url (https://api.example.com/v1/me)"
/// );
/// ```
///
/// [`HttpTransport::send`]: crate::HttpTransport::send
pub fn transport_error(error: &str, url: &str, detail: impl Into<String>) -> Error {
    let parsed = Url::parse(url).ok();
    let scrub = |text: &str| match &parsed {
        Some(parsed) => scrub_url(text, url, parsed),
        None => text.to_string(),
    };
    let named = parsed
        .as_ref()
        .map_or_else(|| url.to_string(), without_secrets);
    let host = parsed.as_ref().and_then(Url::host_str).unwrap_or_default();
    let mut words = scrub(error);
    for name in [named.as_str(), host] {
        if !name.is_empty() {
            words = words.replace(name, "");
        }
    }
    let words = words.to_ascii_lowercase();
    let detail = scrub(&detail.into());
    if words.contains("timed out") || words.contains("timeout") {
        Error::Timeout(detail)
    } else {
        Error::Unavailable(detail)
    }
}

/// `url` as an error may name it: scheme, host, port and path, without its userinfo,
/// query or fragment.
pub(crate) fn url_without_secrets(url: &Url) -> String {
    without_secrets(url)
}

fn without_secrets(url: &Url) -> String {
    let mut named = url.clone();
    // Both fail only for a URL that cannot carry userinfo, which then has none.
    let _ = named.set_username("");
    let _ = named.set_password(None);
    named.set_query(None);
    named.set_fragment(None);
    named.to_string()
}

/// `text` with `url` (written as `raw` or as `url` serializes) replaced by
/// [`without_secrets`], and its query, fragment and userinfo removed wherever else they
/// still appear, for a transport that writes the URL in a form of its own.
fn scrub_url(text: &str, raw: &str, url: &Url) -> String {
    let named = without_secrets(url);
    let mut text = text.replace(raw, &named).replace(url.as_str(), &named);
    let userinfo = match url.password() {
        Some(password) => format!("{}:{password}@", url.username()),
        None if !url.username().is_empty() => format!("{}@", url.username()),
        None => String::new(),
    };
    let pieces = [
        url.query()
            .filter(|query| !query.is_empty())
            .map(|query| format!("?{query}")),
        url.fragment()
            .filter(|fragment| !fragment.is_empty())
            .map(|fragment| format!("#{fragment}")),
        (!userinfo.is_empty()).then_some(userinfo),
    ];
    for piece in pieces.into_iter().flatten() {
        text = text.replace(&piece, "");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::FailureClass;

    fn class(status: u16) -> Option<FailureClass> {
        status_error(status, None, format!("HTTP {status}")).map(|e| e.class())
    }

    /// Every row of the table, by variant and by class.
    #[test]
    fn every_row_of_the_table() {
        for status in [200, 201, 204, 207, 299, 301, 304, 399] {
            assert!(status_error(status, None, "x").is_none(), "{status}");
        }
        let kind = |status: u16| {
            status_error(status, None, "x")
                .unwrap_or_else(|| panic!("{status} is an error"))
                .kind()
        };
        for (status, want) in [
            (404, "not-found"),
            (410, "not-found"),
            (401, "refused"),
            (403, "refused"),
            (408, "timeout"),
            (504, "timeout"),
            (409, "conflict"),
            (412, "conflict"),
            (413, "over-budget"),
            (414, "over-budget"),
            (431, "over-budget"),
            (429, "retry-after"),
            (501, "unsupported"),
            (502, "unavailable"),
            (503, "unavailable"),
            (500, "endpoint"),
            (505, "endpoint"),
            (507, "endpoint"),
            (599, "endpoint"),
            (400, "endpoint"),
            (405, "endpoint"),
            (418, "endpoint"),
            (422, "endpoint"),
            (100, "endpoint"),
            (600, "endpoint"),
        ] {
            assert_eq!(kind(status), want, "{status}");
        }
        assert_eq!(class(401), Some(FailureClass::Refused));
        assert_eq!(class(429), Some(FailureClass::RetryAfter));
        assert_eq!(class(413), Some(FailureClass::OverBudget));
        assert_eq!(class(504), Some(FailureClass::Transient));
        assert_eq!(class(502), Some(FailureClass::Transient));
        assert_eq!(class(500), Some(FailureClass::Unknown));
        assert_eq!(class(404), Some(FailureClass::Permanent));
        assert_eq!(class(501), Some(FailureClass::Permanent));
    }

    /// A 503 is `RetryAfter` exactly when it carries a delay; a 429 always is, and keeps
    /// whatever delay it has, `None` included.
    #[test]
    fn retry_after_decides_a_503_and_rides_a_429() {
        let five = Some(Duration::from_secs(5));
        assert!(matches!(
            status_error(503, five, "x"),
            Some(Error::RetryAfter { delay, .. }) if delay == five
        ));
        assert!(matches!(
            status_error(503, None, "x"),
            Some(Error::Unavailable(_))
        ));
        assert!(matches!(
            status_error(429, five, "x"),
            Some(Error::RetryAfter { delay, .. }) if delay == five
        ));
        assert!(matches!(
            status_error(429, None, "x"),
            Some(Error::RetryAfter { delay: None, .. })
        ));
        // Retry-After on any other status is ignored.
        assert!(matches!(
            status_error(502, five, "x"),
            Some(Error::Unavailable(_))
        ));
        assert!(matches!(
            status_error(500, five, "x"),
            Some(Error::Endpoint(_))
        ));
    }

    fn with_retry_after(status: u16, value: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: vec![("retry-after".into(), value.into())],
            body: Vec::new().into(),
        }
    }

    #[test]
    fn checked_error_responses_need_no_optional_fallback() {
        let now = Some(Time::from_millis(1_445_412_480_000 - 90_000));
        for status in (400..=599).chain([600, u16::MAX]) {
            for header in ["7", "Wed, 21 Oct 2015 07:28:00 GMT", "invalid"] {
                let response = with_retry_after(status, header);
                // A caller that already checked the status needs an Error directly.
                let error: Error = response_error_for_status(&response, now, "request failed");
                let existing = response_error(&response, now, "request failed").unwrap();
                assert_eq!(error.kind(), existing.kind(), "{status}: {header}");
                assert_eq!(
                    error.to_string(),
                    existing.to_string(),
                    "{status}: {header}"
                );
                assert_eq!(error.retry_after_millis(), existing.retry_after_millis());
            }
        }
    }

    #[test]
    fn checked_error_response_without_retry_after_preserves_detail() {
        let response = HttpResponse {
            status: 503,
            headers: Vec::new(),
            body: Vec::new().into(),
        };
        let error = response_error_for_status(&response, None, String::from("GET /resource"));
        assert!(matches!(&error, Error::Unavailable(detail) if detail == "GET /resource"));
    }

    /// A status below 400 never panics: it answers the hand-written fallback.
    #[test]
    fn checked_error_response_below_400_is_an_endpoint_error() {
        for status in [0, 100, 199, 200, 299, 300, 304, 399] {
            let response = with_retry_after(status, "7");
            let error = response_error_for_status(&response, None, "not an error");
            assert!(
                matches!(&error, Error::Endpoint(detail) if detail == "not an error"),
                "{status}: {error:?}"
            );
        }
    }

    /// The header in both forms, through a whole response and the kernel clock.
    #[test]
    fn response_error_reads_both_forms_of_the_header() {
        // 2015-10-21T07:28:00Z.
        let date = "Wed, 21 Oct 2015 07:28:00 GMT";
        let at = 1_445_412_480_000u64;
        let now = Some(Time::from_millis(at - 90_000));

        let seconds = response_error(&with_retry_after(429, "7"), now, "HTTP 429").unwrap();
        assert_eq!(seconds.retry_after_millis(), Some(7_000));
        let dated = response_error(&with_retry_after(429, date), now, "HTTP 429").unwrap();
        assert_eq!(dated.retry_after_millis(), Some(90_000));
        let dated = response_error(&with_retry_after(503, date), now, "HTTP 503").unwrap();
        assert_eq!(dated.retry_after_millis(), Some(90_000));

        // No clock: the date cannot be measured, so the 429 has no delay and the 503 is
        // the ordinary transient Unavailable.
        let undated = response_error(&with_retry_after(429, date), None, "HTTP 429").unwrap();
        assert!(matches!(undated, Error::RetryAfter { delay: None, .. }));
        let undated = response_error(&with_retry_after(503, date), None, "HTTP 503").unwrap();
        assert!(matches!(undated, Error::Unavailable(_)));

        // Malformed and absent are the same as no header.
        let bad = response_error(&with_retry_after(503, "in a bit"), now, "HTTP 503").unwrap();
        assert!(matches!(bad, Error::Unavailable(_)));
        let bad = response_error(&with_retry_after(429, "in a bit"), now, "HTTP 429").unwrap();
        assert!(matches!(bad, Error::RetryAfter { delay: None, .. }));
        let none = HttpResponse {
            status: 503,
            headers: Vec::new(),
            body: Vec::new().into(),
        };
        assert!(matches!(
            response_error(&none, now, "HTTP 503"),
            Some(Error::Unavailable(_))
        ));
        // The header name is matched case-insensitively.
        let shouted = HttpResponse {
            status: 503,
            headers: vec![("RETRY-AFTER".into(), "3".into())],
            body: Vec::new().into(),
        };
        assert_eq!(
            response_error(&shouted, None, "x")
                .unwrap()
                .retry_after_millis(),
            Some(3_000)
        );
    }

    /// The three date forms RFC 9110 §5.6.7 obliges a recipient to accept, and the
    /// delay-seconds edge cases.
    #[test]
    fn retry_after_parses_every_form_and_refuses_the_rest() {
        let at = 784_111_777_000u64; // 1994-11-06T08:49:37Z
        let now = Some(Time::from_millis(at - 10_000));
        for date in [
            "Sun, 06 Nov 1994 08:49:37 GMT",  // IMF-fixdate
            "Sunday, 06-Nov-94 08:49:37 GMT", // RFC 850
            "Sun Nov  6 08:49:37 1994",       // asctime
        ] {
            assert_eq!(
                retry_after(date, now),
                Some(Duration::from_secs(10)),
                "{date}"
            );
        }
        assert_eq!(
            retry_after("99999999999999999999999", None),
            Some(Duration::from_secs(u64::MAX)),
            "an overflowing delay-seconds saturates"
        );
        assert_eq!(retry_after("120", None), Some(Duration::from_secs(120)));
        for bad in [
            "",
            "   ",
            "-1",
            "+1",
            "1.0",
            "1e3",
            "0x10",
            "Sun, 06 Nov 1994",
            "12 0",
        ] {
            assert_eq!(retry_after(bad, now), None, "{bad:?}");
        }
    }

    #[test]
    fn a_transport_timeout_is_a_timeout_and_the_url_cannot_say_so() {
        let url = "https://timeout.example/timed out";
        for said in [
            "Network Error: timed out reading response",
            "error sending request: operation timed out",
            "TimeoutError: signal timed out",
            "connect timeout",
        ] {
            let err = transport_error(said, url, said);
            assert!(matches!(err, Error::Timeout(_)), "{said}: {err:?}");
            assert_eq!(err.class(), FailureClass::Transient);
        }
        for said in [
            "connection refused".to_string(),
            format!("dns error for {url}"),
            "tls handshake failed".to_string(),
        ] {
            let err = transport_error(&said, url, said.clone());
            assert!(matches!(err, Error::Unavailable(_)), "{said}: {err:?}");
        }
    }

    /// The URL a failure names loses its userinfo, query and fragment, written whole or
    /// in pieces of the transport's own, and the scrubbing never changes the class.
    #[test]
    fn a_transport_failure_never_repeats_a_query_fragment_or_userinfo() {
        let url = "https://u:p4ss@timeout.example:8443/a/b?api_key=s3cr3t#fr4g";
        for (said, want) in [
            (
                format!("error sending request for url ({url})"),
                "error sending request for url (https://timeout.example:8443/a/b)",
            ),
            (
                "refused: u:p4ss@timeout.example:8443/a/b?api_key=s3cr3t".to_string(),
                "refused: timeout.example:8443/a/b",
            ),
        ] {
            let err = transport_error(&said, url, said.clone());
            assert!(matches!(err, Error::Unavailable(_)), "{said}: {err:?}");
            assert_eq!(err.to_string(), format!("unavailable: {want}"));
        }
        let err = transport_error(
            &format!("{url}: timed out"),
            url,
            format!("{url}: timed out"),
        );
        assert!(matches!(err, Error::Timeout(_)), "{err:?}");
        assert_eq!(
            err.to_string(),
            "timeout: https://timeout.example:8443/a/b: timed out"
        );
        // Text that is not about a URL passes through as it was.
        let err = transport_error("reset? by peer", "response body", "reset? by peer");
        assert_eq!(err.to_string(), "unavailable: reset? by peer");
    }
}
