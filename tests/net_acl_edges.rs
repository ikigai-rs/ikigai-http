//! Edges of the `urn:cap:net` ACL: each test states the behavior the documented ACL
//! promises at one edge (encoded paths, caller headers, schemes, redirect errors,
//! cached redirects, host spellings) and checks the endpoint keeps it.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Clock, Iri, Kernel, Request, Time, Verb};
use ikigai_http::{net_allows_port, space, HttpRequest, HttpResponse, HttpTransport};

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> Time {
        Time::from_millis(1_000_000)
    }
}

/// One canned answer: status, headers, body.
type Answer = (u16, Vec<(String, String)>, Vec<u8>);
/// One canned answer as a test writes it.
type AnswerSpec<'a> = (u16, Vec<(&'a str, &'a str)>, &'a str);

/// Answers from a queue (the last answer repeats) and records every request it saw.
struct Rec {
    answers: Mutex<Vec<Answer>>,
    seen: Mutex<Vec<HttpRequest>>,
}
impl Rec {
    fn new(answers: Vec<AnswerSpec<'_>>) -> Arc<Self> {
        Arc::new(Rec {
            answers: Mutex::new(
                answers
                    .into_iter()
                    .map(|(s, h, b)| {
                        (
                            s,
                            h.into_iter()
                                .map(|(k, v)| (k.to_string(), v.to_string()))
                                .collect(),
                            b.as_bytes().to_vec(),
                        )
                    })
                    .collect(),
            ),
            seen: Mutex::new(Vec::new()),
        })
    }
    fn ok() -> Arc<Self> {
        Rec::new(vec![(
            200,
            vec![
                ("content-type", "text/plain"),
                ("cache-control", "max-age=60"),
            ],
            "body",
        )])
    }
    fn urls(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.url.clone())
            .collect()
    }
}
#[async_trait]
impl HttpTransport for Rec {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        self.seen.lock().unwrap().push(request);
        let mut answers = self.answers.lock().unwrap();
        let (status, headers, body) = if answers.len() > 1 {
            answers.remove(0)
        } else {
            answers[0].clone()
        };
        Ok(HttpResponse {
            status,
            headers,
            body: body.into(),
        })
    }
}

fn get(url: &str) -> Request {
    Request::new(Verb::Source, Iri::parse("urn:http:get").unwrap())
        .with_arg("url", ArgRef::Inline(url.as_bytes().to_vec()))
}

fn cap(scopes: &[&str]) -> Capability {
    Capability::root().attenuate(scopes.iter().map(|s| s.to_string()))
}

/// The documented example: `example.com` + `-example.com/admin` is "the host except
/// `/admin`". RFC 3986 §6.2.2.2: `%61` is `a`, an unreserved character, so
/// `/%61dmin` IS `/admin` and every origin server decodes it so.
#[test]
fn a_path_deny_holds_against_percent_encoded_unreserved_characters() {
    let c = cap(&["urn:cap:net:example.com", "urn:cap:net:-example.com/admin"]);
    assert!(!net_allows_port(&c, "example.com", Some(443), "/admin"));
    let t = Rec::ok();
    let kernel = Kernel::new(Arc::new(space(t.clone())));
    let out = block_on(kernel.issue(get("https://example.com/%61dmin/users"), &c));
    assert!(
        out.is_err(),
        "the denied subtree was fetched through %61: {:?}",
        t.urls()
    );
}

/// An allow on `/api` must not reach outside `/api` by an encoded slash that the
/// origin (or a proxy in front of it) decodes before resolving dot segments.
#[test]
fn a_path_allow_does_not_escape_through_an_encoded_slash_dot_segment() {
    let c = cap(&["urn:cap:net:example.com/api"]);
    let t = Rec::ok();
    let kernel = Kernel::new(Arc::new(space(t.clone())));
    let out = block_on(kernel.issue(get("https://example.com/api/..%2fadmin"), &c));
    assert!(
        out.is_err(),
        "a request outside /api went out under an /api grant: {:?}",
        t.urls()
    );
}

/// The ACL judges the URL's host. A caller-supplied `Host` header names a different
/// virtual host on the same connection, so `-internal.example.com` must not be
/// reachable by asking `www.example.com` (same front proxy) for it by Host.
#[test]
fn a_caller_host_header_cannot_name_a_host_the_acl_did_not_judge() {
    let c = cap(&[
        "urn:cap:net:*.example.com",
        "urn:cap:net:-internal.example.com",
    ]);
    let t = Rec::ok();
    let kernel = Kernel::new(Arc::new(space(t.clone())));
    let request = get("https://www.example.com/").with_arg(
        "headers",
        ArgRef::Inline(b"Host: internal.example.com".to_vec()),
    );
    let _ = block_on(kernel.issue(request, &c));
    let seen = t.seen.lock().unwrap();
    let host_headers: Vec<_> = seen
        .iter()
        .flat_map(|r| r.headers.iter())
        .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
        .collect();
    assert!(
        host_headers.is_empty(),
        "a Host header for a denied host reached the transport: {host_headers:?}"
    );
}

/// A port-scoped grant (`example.com:443`) must not admit a URL whose effective
/// port is unknown: a non-HTTP scheme has no default port the ACL can judge, and
/// it is not this transport's to send.
#[test]
fn a_port_scoped_grant_does_not_admit_a_non_http_scheme() {
    let c = cap(&["urn:cap:net:example.com:443"]);
    let t = Rec::ok();
    let kernel = Kernel::new(Arc::new(space(t.clone())));
    let _ = block_on(kernel.issue(get("gopher://example.com/"), &c));
    let _ = block_on(kernel.issue(get("file://example.com/etc/passwd"), &c));
    assert!(
        t.urls().is_empty(),
        "non-HTTP URLs reached the transport under a port-443 grant: {:?}",
        t.urls()
    );
}

/// A redirect to a non-HTTP Location on a granted host is not followed.
#[test]
fn a_redirect_to_a_non_http_scheme_is_not_followed() {
    let c = cap(&["urn:cap:net:example.com:443"]);
    let t = Rec::new(vec![
        (302, vec![("location", "file://example.com/etc/passwd")], ""),
        (200, vec![("content-type", "text/plain")], "secret"),
    ]);
    let kernel = Kernel::new(Arc::new(space(t.clone())));
    let _ = block_on(kernel.issue(get("https://example.com/"), &c));
    assert_eq!(
        t.urls(),
        vec!["https://example.com/".to_string()],
        "a non-HTTP redirect target reached the transport"
    );
}

/// A redirected answer is cached under the requested URL. A second caller whose
/// capability grants the first host but NOT the redirect target must not be served
/// the target's content from the cache.
#[test]
fn a_cached_redirect_answer_is_not_served_to_a_caller_denied_the_target() {
    let t = Rec::new(vec![
        (302, vec![("location", "https://b.example/secret")], ""),
        (
            200,
            vec![
                ("content-type", "text/plain"),
                ("cache-control", "max-age=600"),
            ],
            "b's content",
        ),
        (302, vec![("location", "https://b.example/secret")], ""),
    ]);
    let kernel = Kernel::new(Arc::new(space(t.clone()))).with_clock(Arc::new(FixedClock));
    let both = cap(&["urn:cap:net:a.example", "urn:cap:net:b.example"]);
    let only_a = cap(&["urn:cap:net:a.example"]);
    block_on(kernel.issue(get("https://a.example/start"), &both)).unwrap();
    let second = block_on(kernel.issue(get("https://a.example/start"), &only_a));
    assert!(
        second.is_err(),
        "b.example's content served to a caller without b.example: {:?}",
        second.map(|r| String::from_utf8_lossy(&r.bytes).into_owned())
    );
}

/// A POST that is redirected names the Location in its error. A Location commonly
/// carries a credential in its query (an OAuth `code`, a signed-URL signature).
#[test]
fn a_refused_redirect_error_does_not_echo_a_location_query() {
    let c = cap(&["urn:cap:net:example.com", "urn:cap:kernel:cut"]);
    let t = Rec::new(vec![(
        302,
        vec![("location", "https://app.example.com/cb?code=SECRETCODE")],
        "",
    )]);
    let kernel = Kernel::new(Arc::new(space(t.clone())));
    let request = Request::new(Verb::Sink, Iri::parse("urn:http:post").unwrap())
        .with_arg(
            "url",
            ArgRef::Inline(b"https://example.com/oauth/token".to_vec()),
        )
        .with_arg("content", ArgRef::Inline(b"x".to_vec()));
    let err = block_on(kernel.issue(request, &c)).unwrap_err();
    assert!(
        !err.to_string().contains("SECRETCODE"),
        "error text carries the Location's query: {err}"
    );
}

/// Every spelling of a denied host is the denied host.
#[test]
fn host_spellings_of_a_denied_host_stay_denied() {
    let c = cap(&[
        "urn:cap:net:*.example.com",
        "urn:cap:net:-internal.example.com",
        "urn:cap:net:10.0.0.1",
        "urn:cap:net:-10.0.0.1/admin",
    ]);
    for url in [
        "https://INTERNAL.example.com/",
        "https://internal.example.com./",
        "https://internal.EXAMPLE.com.:443/",
        "https://%69nternal.example.com/",
        "https://\u{FF49}nternal.example.com/",
        "https://www.example.com@internal.example.com/",
        "https://user:pw@internal.example.com/",
        "http://167772161/admin",
        "http://0x0a.0.0.1/admin",
        "http://012.0.0.1/admin",
        "http://10.1/admin",
    ] {
        let t = Rec::ok();
        let kernel = Kernel::new(Arc::new(space(t.clone())));
        let out = block_on(kernel.issue(get(url), &c));
        assert!(out.is_err(), "{url} reached {:?}", t.urls());
    }
}

/// The decoded reading must not refuse what the raw reading grants for an encoded
/// slash inside one segment, when the grant covers both readings.
#[test]
fn an_encoded_slash_inside_a_granted_subtree_still_goes_out() {
    let c = cap(&["urn:cap:net:gitlab.example/api"]);
    let t = Rec::ok();
    let kernel = Kernel::new(Arc::new(space(t.clone())));
    block_on(kernel.issue(
        get("https://gitlab.example/api/v4/projects/group%2Fname"),
        &c,
    ))
    .unwrap();
    assert_eq!(t.urls().len(), 1);
}
