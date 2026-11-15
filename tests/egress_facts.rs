//! Facts about today's endpoints that `docs/egress-credentials.md` builds on. Nothing
//! here tests the egress door, which does not exist yet: each test pins a behavior
//! the design says the door must override, so a change to it shows up here first.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Clock, Iri, Kernel, Request, Time, Verb};
use ikigai_http::{space, HttpRequest, HttpResponse, HttpTransport};

struct FixedClock(AtomicU64);
impl Clock for FixedClock {
    fn now(&self) -> Time {
        Time::from_millis(self.0.load(Ordering::SeqCst))
    }
}

/// Answers every request with a fresh-for-a-minute 200 and counts what reached it.
struct Fresh(AtomicU32);
#[async_trait]
impl HttpTransport for Fresh {
    async fn send(&self, _: HttpRequest) -> Result<HttpResponse, String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(HttpResponse {
            status: 200,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("cache-control".into(), "max-age=60".into()),
            ],
            body: b"{\"ok\":true}".to_vec().into(),
        })
    }
}

fn get_with_authorization(value: &str) -> Request {
    Request::new(Verb::Source, Iri::parse("urn:http:get").unwrap())
        .with_arg(
            "url",
            ArgRef::Inline(b"https://api.example.com/v1/me".to_vec()),
        )
        .with_arg("authorization", ArgRef::Inline(value.as_bytes().to_vec()))
}

/// A GET that carries a credential is cached like any other read: the second call
/// with the same credential is a cache hit, and a different credential is a different
/// request identity. The door cannot reuse this path for a substituted request and
/// must make its answer uncacheable itself (the design's "Caching" section).
#[test]
fn a_get_carrying_a_credential_is_cached_today() {
    let transport = Arc::new(Fresh(AtomicU32::new(0)));
    let kernel = Kernel::new(Arc::new(space(transport.clone())))
        .with_clock(Arc::new(FixedClock(AtomicU64::new(0))));
    let cap = Capability::scoped(["urn:cap:net:api.example.com"]);

    block_on(kernel.issue(get_with_authorization("Bearer one"), &cap)).unwrap();
    block_on(kernel.issue(get_with_authorization("Bearer one"), &cap)).unwrap();
    assert_eq!(
        transport.0.load(Ordering::SeqCst),
        1,
        "the second credentialed GET was served from the cache"
    );

    block_on(kernel.issue(get_with_authorization("Bearer two"), &cap)).unwrap();
    assert_eq!(
        transport.0.load(Ordering::SeqCst),
        2,
        "a different credential is a different request identity"
    );
}

/// Fails the way common HTTP clients do, naming the URL it could not reach.
struct NamesTheUrl;
#[async_trait]
impl HttpTransport for NamesTheUrl {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        Err(format!(
            "error sending request for url ({}): connection refused",
            request.url
        ))
    }
}

/// A transport failure's words reach the caller's error text unchanged, URL and query
/// included. A credential substituted into a query parameter would therefore leak
/// through an ordinary connection failure, so the door must scrub every error it
/// returns (the design's "Echoes" section).
#[test]
fn a_transport_failure_repeats_the_url_into_the_error_text() {
    let kernel = Kernel::new(Arc::new(space(Arc::new(NamesTheUrl))));
    let cap = Capability::scoped(["urn:cap:net:api.example.com"]);
    let request = Request::new(Verb::Source, Iri::parse("urn:http:get").unwrap()).with_arg(
        "url",
        ArgRef::Inline(b"https://api.example.com/v1/me?api_key=s3cr3t-value".to_vec()),
    );

    let err = block_on(kernel.issue(request, &cap)).unwrap_err();
    assert!(
        err.to_string().contains("api_key=s3cr3t-value"),
        "the query reached the error text: {err}"
    );
}
