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
//! | 2xx, 3xx | none: a success | |
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
//!     body: Vec::new(),
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

use crate::HttpResponse;

/// The [`Error`] for an origin's answer with `status`, or `None` for a success (2xx, or a
/// 3xx the caller did not follow). `retry_after` is the delay the answer carried, already
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
/// `url` is removed before looking, so a host named `timeout.example` cannot type its own
/// refusals. `detail` becomes the error's message.
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
/// ```
///
/// [`HttpTransport::send`]: crate::HttpTransport::send
pub fn transport_error(error: &str, url: &str, detail: impl Into<String>) -> Error {
    let words = if url.is_empty() {
        error.to_ascii_lowercase()
    } else {
        error.replace(url, "").to_ascii_lowercase()
    };
    if words.contains("timed out") || words.contains("timeout") {
        Error::Timeout(detail.into())
    } else {
        Error::Unavailable(detail.into())
    }
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
            body: Vec::new(),
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
            body: Vec::new(),
        };
        assert!(matches!(
            response_error(&none, now, "HTTP 503"),
            Some(Error::Unavailable(_))
        ));
        // The header name is matched case-insensitively.
        let shouted = HttpResponse {
            status: 503,
            headers: vec![("RETRY-AFTER".into(), "3".into())],
            body: Vec::new(),
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
}
