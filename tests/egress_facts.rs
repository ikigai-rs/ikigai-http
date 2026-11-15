//! Facts about today's endpoints that `docs/egress-credentials.md` builds on. Nothing
//! here tests the egress door, which does not exist yet: each test pins a behavior
//! the design builds on or says the door must override, so a change to it shows up
//! here first.

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

/// A transport failure's words reach the caller's error text with the URL cut down to
/// its scheme, host, port and path: the query, the fragment and any userinfo never do,
/// so a credential in a query parameter or in `user:pass@` cannot leak through an
/// ordinary connection failure (ledger #3767). The door still scrubs every error it
/// returns for a value placed anywhere else (the design's "Echoes" section).
#[test]
fn a_transport_failure_names_the_url_without_its_query_or_userinfo() {
    let kernel = Kernel::new(Arc::new(space(Arc::new(NamesTheUrl))));
    let cap = Capability::scoped(["urn:cap:net:api.example.com"]);
    for (url, secrets) in [
        (
            "https://api.example.com/v1/me?api_key=s3cr3t-value",
            &["s3cr3t-value", "api_key", "?"][..],
        ),
        (
            "https://api.example.com/v1/me?key=s3cr3t-value&token=t0ken-value#frag-value",
            &["s3cr3t-value", "t0ken-value", "frag-value", "?", "#"][..],
        ),
        (
            "https://user:pa55word@api.example.com/v1/me",
            &["user", "pa55word", "@"][..],
        ),
        (
            "https://user:pa55word@api.example.com:8443/v1/me?token=t0ken-value",
            &["user", "pa55word", "@", "t0ken-value"][..],
        ),
    ] {
        let request = Request::new(Verb::Source, Iri::parse("urn:http:get").unwrap())
            .with_arg("url", ArgRef::Inline(url.as_bytes().to_vec()));
        let cap = if url.contains(":8443") {
            Capability::scoped(["urn:cap:net:api.example.com:8443"])
        } else {
            cap.clone()
        };

        let text = block_on(kernel.issue(request, &cap))
            .unwrap_err()
            .to_string();
        for secret in secrets {
            assert!(
                !text.contains(secret),
                "{secret:?} reached the error text: {text}"
            );
        }
        let port = if url.contains(":8443") { ":8443" } else { "" };
        assert!(
            text.contains(&format!("https://api.example.com{port}/v1/me")),
            "the scheme, host, port and path still name the request: {text}"
        );
        assert!(
            text.contains("connection refused"),
            "the failure is still said: {text}"
        );
    }
}
