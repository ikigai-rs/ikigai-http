//! `ikigai-http` — an outbound HTTP-**client** module.
//!
//! A standalone **ikigai module crate** (like `ikigai-fs` / `ikigai-fn`): a host
//! links it in and mounts [`space`], gaining the ability to *dereference the web*
//! as ROC resources. It depends only on the published `ikigai-core` kernel.
//!
//! ## One endpoint per method; the ROC verb mirrors HTTP idempotency
//!
//! Each HTTP method is its own resource, and the verb you resolve it with is the
//! one whose cacheability matches the method's idempotency — so "is this cached?"
//! falls straight out of the verb:
//!
//! | resolve            | IRI               | HTTP   | cacheable |
//! |--------------------|-------------------|--------|-----------|
//! | `source`           | `urn:httpGet`     | GET    | yes       |
//! | `exists`           | `urn:httpHead`    | HEAD   | yes       |
//! | `sink`             | `urn:httpPost`    | POST   | no        |
//! | `sink`             | `urn:httpPut`     | PUT    | no        |
//! | `sink`             | `urn:httpPatch`   | PATCH  | no        |
//! | `delete`           | `urn:httpDelete`  | DELETE | no        |
//!
//! The target URL is an argument (`url=`), not part of the IRI, so one binding
//! serves every URL and the cache keys on the URL via the request identity.
//! (OPTIONS-as-`meta` from the locked design is deferred: the kernel intercepts
//! `Verb::Meta` to render an endpoint's *self-description*, so it never reaches the
//! endpoint — wiring OPTIONS needs that routing question settled first.)
//!
//! ## The capability ACL
//!
//! A network capability is carried as `urn:cap:` scopes of the form
//! `urn:cap:net:<host>[/<path-prefix>]`. A leading `-` marks a **deny**:
//!
//! - `urn:cap:net:example.com` — call any path on `example.com`.
//! - `urn:cap:net:example.com/api` — only paths under `/api`.
//! - `urn:cap:net:example.com` **+** `urn:cap:net:-example.com/admin` — the host
//!   except `/admin`.
//!
//! Matching is **longest-prefix wins**, **deny breaks ties**, segment-aware (so
//! `/api` does not match `/apixyz`); no matching rule → **default-deny**. A `root`
//! capability allows everything. (Per the locked design the scope is host/path
//! only — not per-method; an agent is trusted with a host, not with a verb. A
//! finer `urn:cap:net:<method>:…` form is a possible later refinement.)
//!
//! The credential to authenticate with (when one is needed) is itself meant to be
//! capability-gated — the agent gets "may call host X with credential Y", never the
//! raw token — but that, and headers/body/range/auth args, land with the backend.
//!
//! ## Caching (needs `ikigai-core` ≥ 0.1.12)
//!
//! A cacheable `GET`/`HEAD` is threaded on its URL (so a later `sink`/`delete` to
//! the same URL cuts that thread and recomputes it — the write-invalidates-read
//! half of the golden thread, applied to the web) and, when the response carries a
//! `Cache-Control: max-age` / `Expires`, marked [`cacheable_until`] a deadline the
//! kernel's injected [`Clock`] enforces. v1 is **lazy**: validity is checked on
//! read; there is no proactive harvest thread (deferred).

use std::sync::Arc;

use async_trait::async_trait;
use ikigai_core::{
    ArgRef, ArgSpec, Description, Endpoint, EndpointSpace, Error, Exact, Invocation, Iri, ReprType,
    Representation, Request, Result, Verb,
};
use url::Url;

/// One endpoint per HTTP method; the variant fixes the method, the ROC verb it is
/// resolved with, and (via the verb) its cacheability.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}

impl Method {
    /// The HTTP method token.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }

    /// The ROC verb this method is resolved with — chosen so the verb's
    /// cacheability matches the method's idempotency.
    pub fn verb(self) -> Verb {
        match self {
            Method::Get => Verb::Source,
            Method::Head => Verb::Exists,
            Method::Post | Method::Put | Method::Patch => Verb::Sink,
            Method::Delete => Verb::Delete,
        }
    }

    /// The conventional IRI this method binds at.
    pub fn iri(self) -> &'static str {
        match self {
            Method::Get => "urn:httpGet",
            Method::Head => "urn:httpHead",
            Method::Post => "urn:httpPost",
            Method::Put => "urn:httpPut",
            Method::Patch => "urn:httpPatch",
            Method::Delete => "urn:httpDelete",
        }
    }

    /// Whether resolving this method may be served from cache (idempotent reads).
    pub fn is_cacheable(self) -> bool {
        self.verb().is_cacheable()
    }

    /// Whether this method mutates the target (and so should cut its URL thread).
    pub fn is_mutating(self) -> bool {
        matches!(
            self,
            Method::Post | Method::Put | Method::Patch | Method::Delete
        )
    }
}

/// The capability path-ACL for outbound HTTP: does `capability` grant a request to
/// `host` + `path`? Mirrors the file module's matcher but over a URL's authority
/// and path. Scopes are `urn:cap:net:<host>[/<path-prefix>]`; a leading `-` denies.
/// Longest matching rule wins, a deny breaks ties, no rule means deny, and a `root`
/// capability allows everything.
pub fn net_allows(capability: &ikigai_core::Capability, host: &str, path: &str) -> bool {
    if capability.is_root() {
        return true;
    }
    let Some(scopes) = capability.scopes() else {
        return false;
    };
    let target = authority_key(host, path);
    let prefix = "urn:cap:net:";

    let mut best_len: Option<usize> = None;
    let mut allowed = false;
    for scope in scopes {
        let Some(rest) = scope.strip_prefix(prefix) else {
            continue;
        };
        // A leading `-` marks a deny rule; the remainder is the host[/path] rule.
        let (rule_allows, rule) = match rest.strip_prefix('-') {
            Some(r) => (false, r),
            None => (true, rest),
        };
        if !authority_within(rule, &target) {
            continue;
        }
        let len = rule.len();
        match best_len {
            Some(b) if len < b => {} // a more specific rule already decided
            Some(b) if len == b => {
                // Tie on specificity: deny wins.
                allowed = allowed && rule_allows;
            }
            _ => {
                best_len = Some(len);
                allowed = rule_allows;
            }
        }
    }
    best_len.is_some() && allowed
}

/// The `host/path` key a net rule is matched against: host followed by the URL
/// path. (Both are split on `/` for segment-aware prefixing, so the exact joining
/// punctuation is immaterial — only the segments matter.)
fn authority_key(host: &str, path: &str) -> String {
    format!("{host}/{}", path.trim_start_matches('/'))
}

/// Whether `rule` (a `host[/prefix]`) is a **segment prefix** of `target` (a
/// `host/path`): same host, and the rule's path segments are a leading run of the
/// target's — so `example.com/api` covers `/api/x` but not `/apixyz`. An empty
/// rule (host-less `urn:cap:net:`) matches everything.
fn authority_within(rule: &str, target: &str) -> bool {
    let rule_segs: Vec<&str> = rule.split('/').filter(|s| !s.is_empty()).collect();
    let target_segs: Vec<&str> = target.split('/').filter(|s| !s.is_empty()).collect();
    rule_segs.len() <= target_segs.len() && rule_segs.iter().zip(&target_segs).all(|(r, t)| r == t)
}

/// A single outbound request, as ikigai-http hands it to the host's transport.
#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// The host transport's reply.
#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The first header whose name matches `name` case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The host-supplied HTTP I/O seam. ikigai-http stays executor- and
/// runtime-agnostic: a native host implements this with `reqwest`/`ureq`, a
/// browser host with `fetch`, a test with a canned map — so no HTTP client (and no
/// Tokio) is baked into this crate. Async so a real client can await; boxed via
/// `async-trait` so the executor is still chosen at the edge.
#[async_trait]
pub trait HttpTransport: Send + Sync {
    /// Perform `request`, returning the response or a transport-level error.
    async fn send(&self, request: HttpRequest) -> std::result::Result<HttpResponse, String>;
}

/// One HTTP method bound as a resource, backed by a host [`HttpTransport`].
pub struct HttpEndpoint {
    method: Method,
    transport: Arc<dyn HttpTransport>,
}

impl HttpEndpoint {
    /// An endpoint for `method`, performing I/O through `transport`.
    pub fn new(method: Method, transport: Arc<dyn HttpTransport>) -> Self {
        HttpEndpoint { method, transport }
    }
}

#[async_trait]
impl Endpoint for HttpEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        // The target URL is an argument, so one binding serves every URL and the
        // cache keys on the URL via the request identity.
        let url_str = inv.inline_str("url")?;
        let parsed = Url::parse(url_str).map_err(|e| Error::InvalidArgument {
            name: "url".to_string(),
            detail: format!("not a URL: {e}"),
        })?;
        let host = parsed.host_str().ok_or_else(|| Error::InvalidArgument {
            name: "url".to_string(),
            detail: "URL has no host".to_string(),
        })?;

        // Capability gate: the session must be granted this host (and path).
        if !net_allows(inv.capability, host, parsed.path()) {
            return Err(Error::Endpoint(format!(
                "capability does not grant `{}` to `{host}{}`",
                self.method.as_str(),
                parsed.path()
            )));
        }

        // The golden thread for this URL (fragment stripped — not sent on the wire):
        // a cacheable read depends on it; a mutating call cuts it.
        let thread = url_thread(&parsed);

        let body = if self.method.is_mutating() {
            inv.inline_arg("content")
                .map(<[u8]>::to_vec)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let response = self
            .transport
            .send(HttpRequest {
                method: self.method,
                url: url_str.to_string(),
                headers: Vec::new(),
                body,
            })
            .await
            .map_err(|e| Error::Endpoint(format!("http transport: {e}")))?;

        // A mutating method invalidates any cached representation of the same URL,
        // by cutting its thread through the kernel (so it works the same over the
        // wire). Needs `urn:cap:kernel:cut` in the session — `root` has it.
        if self.method.is_mutating() {
            let cut = Request::new(Verb::Sink, kernel_cut_iri())
                .with_arg("thread", ArgRef::Inline(thread.clone().into_bytes()));
            inv.issue(cut).await?;
        }

        // Read the response's cache headers before its body is moved into the repr.
        let repr_type = content_type(&response);
        let max_age = max_age_secs(&response);
        let mut repr = Representation::new(repr_type, response.body);

        // Cacheable reads: thread on the URL, and honour an explicit freshness
        // window (`Cache-Control: max-age`) as a deadline. With no freshness signal
        // — or no clock to measure one — a web read stays uncacheable (a live fact)
        // rather than risk being cached permanently.
        if self.method.is_cacheable() {
            if let (Some(max_age), Some(now)) = (max_age, inv.now()) {
                repr = repr
                    .cacheable_until(now.plus_millis(max_age.saturating_mul(1000)))
                    .depends_on(thread);
            }
        }
        Ok(repr)
    }

    fn name(&self) -> &str {
        "http"
    }

    fn describe(&self) -> Description {
        let mut description = Description::new("http")
            .title(format!("HTTP {}", self.method.as_str()))
            .summary("Dereference a URL as a resource through a host transport, capability-gated by `urn:cap:net`.")
            .verb(self.method.verb())
            .output("application/octet-stream")
            .input(ArgSpec::new("url").summary("the absolute URL to request"));
        if self.method.is_mutating() {
            description =
                description.input(ArgSpec::new("content").summary("the request body bytes"));
        }
        description
    }
}

/// Mount all six HTTP-method endpoints on one host transport: `urn:httpGet`,
/// `urn:httpHead`, `urn:httpPost`, `urn:httpPut`, `urn:httpPatch`, `urn:httpDelete`.
pub fn space(transport: Arc<dyn HttpTransport>) -> EndpointSpace {
    let mut space = EndpointSpace::new();
    for method in [
        Method::Get,
        Method::Head,
        Method::Post,
        Method::Put,
        Method::Patch,
        Method::Delete,
    ] {
        space = space.bind(
            Exact::new(method.iri()),
            HttpEndpoint::new(method, transport.clone()),
        );
    }
    space
}

fn kernel_cut_iri() -> Iri {
    Iri::parse("urn:kernel:cut").expect("urn:kernel:cut is a valid IRI")
}

/// The golden-thread name for a URL: the URL with any fragment removed (a fragment
/// is client-side only and never reaches the server, so two URLs differing only by
/// fragment dereference the same resource).
fn url_thread(url: &Url) -> String {
    let mut u = url.clone();
    u.set_fragment(None);
    u.to_string()
}

/// The response's representation type from its `Content-Type` (media type only,
/// parameters dropped), or `application/octet-stream` if absent.
fn content_type(response: &HttpResponse) -> ReprType {
    match response.header("content-type") {
        Some(ct) => ReprType::new(ct.split(';').next().unwrap_or(ct).trim().to_string()),
        None => ReprType::new("application/octet-stream"),
    }
}

/// The freshness window in seconds from a `Cache-Control: max-age=N`, or `None`
/// when absent or when caching is forbidden (`no-store` / `no-cache`).
fn max_age_secs(response: &HttpResponse) -> Option<u64> {
    let cc = response.header("cache-control")?.to_ascii_lowercase();
    if cc.contains("no-store") || cc.contains("no-cache") {
        return None;
    }
    cc.split(',').find_map(|d| {
        d.trim()
            .strip_prefix("max-age=")
            .and_then(|v| v.trim().parse::<u64>().ok())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::{Capability, Clock, Kernel, Time};
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    #[test]
    fn method_verb_and_cacheability_track_idempotency() {
        assert_eq!(Method::Get.verb(), Verb::Source);
        assert!(Method::Get.is_cacheable());
        assert!(Method::Head.is_cacheable());
        assert!(!Method::Post.is_cacheable());
        assert!(!Method::Delete.is_cacheable());
        assert!(Method::Put.is_mutating());
        assert!(!Method::Get.is_mutating());
        assert_eq!(Method::Patch.as_str(), "PATCH");
        assert_eq!(Method::Delete.iri(), "urn:httpDelete");
    }

    #[test]
    fn root_capability_allows_any_host() {
        let cap = Capability::root();
        assert!(net_allows(&cap, "example.com", "/anything"));
    }

    #[test]
    fn host_scope_grants_the_whole_host_but_not_others() {
        let cap = Capability::root().attenuate(["urn:cap:net:example.com".to_string()]);
        assert!(net_allows(&cap, "example.com", "/"));
        assert!(net_allows(&cap, "example.com", "/api/v1/x"));
        assert!(!net_allows(&cap, "evil.com", "/"));
    }

    #[test]
    fn path_prefix_scope_is_segment_aware() {
        let cap = Capability::root().attenuate(["urn:cap:net:example.com/api".to_string()]);
        assert!(net_allows(&cap, "example.com", "/api"));
        assert!(net_allows(&cap, "example.com", "/api/v1/x"));
        // Not a path under /api, despite the string prefix.
        assert!(!net_allows(&cap, "example.com", "/apixyz"));
        assert!(!net_allows(&cap, "example.com", "/other"));
    }

    #[test]
    fn deny_rule_excludes_a_subtree_and_breaks_ties() {
        let cap = Capability::root().attenuate([
            "urn:cap:net:example.com".to_string(),
            "urn:cap:net:-example.com/admin".to_string(),
        ]);
        assert!(net_allows(&cap, "example.com", "/api"));
        assert!(!net_allows(&cap, "example.com", "/admin"));
        assert!(!net_allows(&cap, "example.com", "/admin/users"));
    }

    #[test]
    fn no_matching_rule_is_default_deny() {
        let cap = Capability::root().attenuate(["urn:cap:net:example.com".to_string()]);
        assert!(!net_allows(&cap, "other.com", "/x"));
    }

    // --- Endpoint behaviour, over a mock transport -------------------------

    #[derive(Clone)]
    struct TestClock(Arc<AtomicU64>);
    impl TestClock {
        fn at(ms: u64) -> Self {
            TestClock(Arc::new(AtomicU64::new(ms)))
        }
        fn set(&self, ms: u64) {
            self.0.store(ms, Ordering::SeqCst);
        }
    }
    impl Clock for TestClock {
        fn now(&self) -> Time {
            Time::from_millis(self.0.load(Ordering::SeqCst))
        }
    }

    /// A transport that returns a fixed response and counts GETs (so a cache hit
    /// shows up as a GET not reaching the wire).
    struct Mock {
        gets: AtomicU32,
        response: HttpResponse,
    }
    impl Mock {
        fn new(response: HttpResponse) -> Self {
            Mock {
                gets: AtomicU32::new(0),
                response,
            }
        }
        fn gets(&self) -> u32 {
            self.gets.load(Ordering::SeqCst)
        }
    }
    #[async_trait]
    impl HttpTransport for Mock {
        async fn send(&self, request: HttpRequest) -> std::result::Result<HttpResponse, String> {
            if request.method == Method::Get {
                self.gets.fetch_add(1, Ordering::SeqCst);
            }
            Ok(self.response.clone())
        }
    }

    fn resp(cache_control: Option<&str>) -> HttpResponse {
        let mut headers = vec![("content-type".to_string(), "text/plain".to_string())];
        if let Some(cc) = cache_control {
            headers.push(("cache-control".to_string(), cc.to_string()));
        }
        HttpResponse {
            status: 200,
            headers,
            body: b"hi".to_vec(),
        }
    }

    fn get(url: &str) -> Request {
        Request::new(Verb::Source, Iri::parse("urn:httpGet").unwrap())
            .with_arg("url", ArgRef::Inline(url.as_bytes().to_vec()))
    }

    #[test]
    fn capability_gate_denies_an_ungranted_host() {
        let kernel = Kernel::new(Arc::new(space(Arc::new(Mock::new(resp(None))))));
        let cap = Capability::root().attenuate(["urn:cap:net:other.com".to_string()]);
        let r = futures::executor::block_on(kernel.issue(get("https://example.com/x"), &cap));
        assert!(
            r.is_err(),
            "an ungranted host must be refused before any I/O"
        );
    }

    #[test]
    fn cacheable_get_serves_until_max_age_then_recomputes() {
        let transport = Arc::new(Mock::new(resp(Some("max-age=60"))));
        let clock = TestClock::at(0);
        let kernel =
            Kernel::new(Arc::new(space(transport.clone()))).with_clock(Arc::new(clock.clone()));
        let cap = Capability::root();
        let url = "https://example.com/x";

        futures::executor::block_on(kernel.issue(get(url), &cap)).unwrap(); // computed, deadline 60_000
        futures::executor::block_on(kernel.issue(get(url), &cap)).unwrap(); // cache hit
        assert_eq!(transport.gets(), 1, "served from cache within max-age");
        clock.set(61_000);
        futures::executor::block_on(kernel.issue(get(url), &cap)).unwrap(); // expired -> refetch
        assert_eq!(transport.gets(), 2, "refetched after max-age elapsed");
    }

    #[test]
    fn a_mutating_call_cuts_the_url_thread() {
        let transport = Arc::new(Mock::new(resp(Some("max-age=600"))));
        let clock = TestClock::at(0);
        let kernel =
            Kernel::new(Arc::new(space(transport.clone()))).with_clock(Arc::new(clock.clone()));
        let cap = Capability::root(); // root carries urn:cap:kernel:cut
        let url = "https://example.com/x";

        futures::executor::block_on(kernel.issue(get(url), &cap)).unwrap();
        futures::executor::block_on(kernel.issue(get(url), &cap)).unwrap();
        assert_eq!(transport.gets(), 1, "cached well within max-age");

        // A POST to the same URL cuts its golden thread.
        let post = Request::new(Verb::Sink, Iri::parse("urn:httpPost").unwrap())
            .with_arg("url", ArgRef::Inline(url.as_bytes().to_vec()))
            .with_arg("content", ArgRef::Inline(b"data".to_vec()));
        futures::executor::block_on(kernel.issue(post, &cap)).unwrap();

        // The cached GET is now invalid even though its deadline hasn't passed.
        futures::executor::block_on(kernel.issue(get(url), &cap)).unwrap();
        assert_eq!(transport.gets(), 2, "GET recomputed after the mutating cut");
    }
}
