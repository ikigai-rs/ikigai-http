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
//! `urn:cap:net:<host>[:<port>][/<path-prefix>]`. A leading `-` marks a **deny**:
//!
//! - `urn:cap:net:example.com` — call any path on `example.com`, any port.
//! - `urn:cap:net:example.com:8443` — only port 8443 on that host.
//! - `urn:cap:net:example.com/api` — only paths under `/api`.
//! - `urn:cap:net:example.com` **+** `urn:cap:net:-example.com/admin` — the host
//!   except `/admin`.
//!
//! Matching is **longest-prefix wins**, **deny breaks ties**, segment-aware (so
//! `/api` does not match `/apixyz`); no matching rule → **default-deny**. A rule
//! without a port matches any port; a rule with a port matches exactly that port
//! (an IPv6 host in a rule uses brackets: `urn:cap:net:[::1]:8080`). A bare
//! `urn:cap:net:` scope (no host) grants **nothing** — there is no wildcard-allow
//! rule; breadth is granted host by host. A `root` capability allows everything.
//! (Per the locked design the scope is host/path only — not per-method; an agent
//! is trusted with a host, not with a verb. A finer `urn:cap:net:<method>:…` form
//! is a possible later refinement.)
//!
//! ## Redirects
//!
//! The **endpoint** owns redirect-following; a host transport must return 3xx
//! responses as-is and never follow them itself (an auto-following transport
//! would let a granted host 302 the request to an ungranted one — the classic
//! SSRF-via-redirect). For cacheable methods (`GET`/`HEAD`) the endpoint follows
//! up to 5 hops, re-running the capability ACL against **each** hop's host, port
//! and path — a redirect to an ungranted authority is a typed `Denied`. Mutating
//! methods never follow a redirect (no cross-host replay of a request body): a
//! 3xx with a `Location` on `POST`/`PUT`/`PATCH`/`DELETE` is a typed error
//! naming the target instead.
//!
//! The credential to authenticate with (when one is needed) is itself meant to be
//! capability-gated — the agent gets "may call host X with credential Y", never the
//! raw token — but that, and headers/body/range/auth args, land with the backend.
//!
//! ## Honest status (needs `ikigai-core` ≥ 0.1.47)
//!
//! The endpoint reports what HTTP said, mapped onto the typed-error taxonomy — it never hands
//! back a `404` error page dressed up as the resource. It is **policy-free**: the caller decides
//! what a status *means* for its purpose.
//!
//! - `GET`/`source` (and the mutating verbs): 2xx → the representation; 404/410 → `NotFound`;
//!   401/403 → `Denied`; 408/504 → `Timeout`; 429/5xx → `Unavailable`; other 4xx → `Endpoint`.
//!   A transport-level failure (DNS/refused/timeout) is `Unavailable`. Because the mapping lands
//!   on the taxonomy, `is_transient` drives the retry/circuit-breaker/failover overlays for free.
//! - `HEAD`/`exists`: a `"true"`/`"false"` text representation, following the `ikigai-fs` `Exists`
//!   convention (existence is an answer, not an error). Existence is **lenient**: the check is only
//!   reached once the server has answered, so any status but 404/410 means the host is reachable and
//!   the endpoint is *present* (`true`) — a 429 throttle, a 5xx error, a 408/504 timeout all count
//!   as there-but-busy. Only 404/410 is *absent* (`false`); only a transport failure (which errors
//!   before the status is seen) is unreachable. This is deliberately more lenient than `Source`:
//!   `Exists` asks "is it there?", `Source` asks "give it to me" (where a 429/5xx is an honest
//!   transient error). A link-checker leans on the split — a bookmark whose host answers `429`/`503`
//!   is not dead.
//!
//! ## Caching (needs `ikigai-core` ≥ 0.1.12)
//!
//! A cacheable `GET`/`HEAD` is threaded on its URL (so a later `sink`/`delete` to
//! the same URL cuts that thread and recomputes it — the write-invalidates-read
//! half of the golden thread, applied to the web) and marked [`cacheable_until`](ikigai_core::Representation::cacheable_until) a
//! deadline the kernel's injected [`Clock`](ikigai_core::Clock) enforces. The freshness window is the
//! caller's `max_age=` directive (seconds) when given — so a liveness/existence
//! check can cache a HEAD that carries no freshness of its own — else the response's
//! `Cache-Control: max-age`; an explicit `no-store`/`no-cache` forbids caching
//! either way. With no window (or no clock) a web read stays uncacheable, a live
//! fact. v1 is **lazy**: validity is checked on read; there is no proactive harvest
//! thread (deferred).

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

    /// The endpoint's description id — UNIQUE per method, so the catalog subject
    /// (`urn:ikigai:endpoint:{id}`) and any projection keyed on it (e.g. an MCP
    /// tool name) don't collide across the six method endpoints.
    pub fn id(self) -> &'static str {
        match self {
            Method::Get => "httpGet",
            Method::Head => "httpHead",
            Method::Post => "httpPost",
            Method::Put => "httpPut",
            Method::Patch => "httpPatch",
            Method::Delete => "httpDelete",
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
/// `host` + `path`, on any port? Mirrors the file module's matcher but over a URL's
/// authority and path. Scopes are `urn:cap:net:<host>[:<port>][/<path-prefix>]`; a
/// leading `-` denies. Longest matching rule wins, a deny breaks ties, no rule
/// means deny, and a `root` capability allows everything.
///
/// This port-less form treats the target port as *unknown*, so port-scoped rules
/// still match (a caller that can't know the port isn't judged on it). The HTTP
/// endpoints themselves use [`net_allows_port`] with the URL's real port, where
/// port-scoped rules are enforced exactly.
pub fn net_allows(capability: &ikigai_core::Capability, host: &str, path: &str) -> bool {
    net_allows_port(capability, host, None, path)
}

/// The port-aware capability ACL: like [`net_allows`], with the target port
/// supplied (`None` = unknown, matches any rule port). A rule that names a port
/// (`urn:cap:net:example.com:8443`) matches only that port; a rule without one
/// matches every port on its host. A bare `urn:cap:net:` scope grants nothing.
pub fn net_allows_port(
    capability: &ikigai_core::Capability,
    host: &str,
    port: Option<u16>,
    path: &str,
) -> bool {
    if capability.is_root() {
        return true;
    }
    let Some(scopes) = capability.scopes() else {
        return false;
    };
    let prefix = "urn:cap:net:";

    let mut best_len: Option<usize> = None;
    let mut allowed = false;
    for scope in scopes {
        let Some(rest) = scope.strip_prefix(prefix) else {
            continue;
        };
        // A leading `-` marks a deny rule; the remainder is the host[:port][/path] rule.
        let (rule_allows, rule) = match rest.strip_prefix('-') {
            Some(r) => (false, r),
            None => (true, rest),
        };
        // A bare `urn:cap:net:` (or `urn:cap:net:-`) contributes no rule: there is
        // no wildcard-allow — an empty rule must not match every authority.
        if rule.is_empty() {
            continue;
        }
        if !rule_matches(rule, host, port, path) {
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

/// Whether one rule (`host[:port][/path-prefix]`) covers the target authority:
/// host equal (case-insensitive), rule port — when present — equal to the target
/// port (an unknown target port matches any rule port), and the rule's path
/// segments a leading run of the target's — so `example.com/api` covers `/api/x`
/// but not `/apixyz`. A bracketed IPv6 host (`[::1]:8080`) parses as
/// host `[::1]`, port `8080` — the trailing-digits check keeps the address's own
/// colons from being misread as a port.
fn rule_matches(rule: &str, host: &str, port: Option<u16>, path: &str) -> bool {
    let (rule_authority, rule_path) = match rule.split_once('/') {
        Some((authority, path)) => (authority, path),
        None => (rule, ""),
    };
    let (rule_host, rule_port) = match rule_authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            match p.parse::<u16>() {
                Ok(n) => (h, Some(n)),
                Err(_) => return false, // digits but out of range: matches nothing
            }
        }
        _ => (rule_authority, None),
    };
    if !rule_host.eq_ignore_ascii_case(host) {
        return false;
    }
    if let (Some(rule_port), Some(port)) = (rule_port, port) {
        if rule_port != port {
            return false;
        }
    }
    let rule_segs: Vec<&str> = rule_path.split('/').filter(|s| !s.is_empty()).collect();
    let target_segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
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
///
/// **Contract: a transport must NOT follow redirects.** A 3xx response is
/// returned as-is; the endpoint follows it (for cacheable methods only), because
/// only the endpoint can re-run the capability ACL against the redirect target —
/// a transport that auto-follows lets a granted host forward the request to an
/// ungranted one behind the capability's back.
#[async_trait]
pub trait HttpTransport: Send + Sync {
    /// Perform `request`, returning the response or a transport-level error.
    /// Redirects are not followed — a 3xx comes back as the response.
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
        // The golden thread for this URL (fragment stripped — not sent on the wire):
        // a cacheable read depends on it; a mutating call cuts it. The thread stays
        // on the REQUESTED URL even when redirects are followed — the request
        // identity (and so the cache key) is the URL the caller named.
        let thread = url_thread(&parsed);

        let body = if self.method.is_mutating() {
            inv.inline_arg("content")
                .map(<[u8]>::to_vec)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let headers = request_headers(inv);

        // Follow redirects here — never in the transport — so the capability ACL
        // runs against EVERY hop's authority, not just the first (the transport
        // contract forbids auto-following for exactly this reason).
        const MAX_REDIRECTS: usize = 5;
        let mut current = parsed.clone();
        let mut hops = 0usize;
        let response = loop {
            let host = current.host_str().ok_or_else(|| Error::InvalidArgument {
                name: "url".to_string(),
                detail: "URL has no host".to_string(),
            })?;
            // Capability gate, per hop: the session must be granted this host,
            // port and path. Typed `Denied` — a permanent authority failure the
            // trace, manifold, and wire recognize as a 403-equivalent without
            // sniffing message text. (Network/transport failures below stay
            // transient `Unavailable`: execution faults, not authorization.)
            if !net_allows_port(
                inv.capability,
                host,
                current.port_or_known_default(),
                current.path(),
            ) {
                let via = if hops > 0 { "redirect target " } else { "" };
                return Err(Error::Denied(format!(
                    "capability does not grant `{}` to {via}`{host}{}`",
                    self.method.as_str(),
                    current.path()
                )));
            }

            let response = self
                .transport
                .send(HttpRequest {
                    method: self.method,
                    url: current.to_string(),
                    headers: headers.clone(),
                    body: body.clone(),
                })
                .await
                // A transport-level failure (DNS, connection refused, timeout, TLS) is a network
                // fault → transient `Unavailable`, so Retry/CircuitBreaker/Failover overlays act on it.
                .map_err(|e| Error::Unavailable(format!("http transport: {e}")))?;

            if !matches!(response.status, 301 | 302 | 303 | 307 | 308) {
                break response;
            }
            let Some(location) = response.header("location") else {
                break response; // a 3xx with nowhere to go is just a response
            };
            if self.method.is_mutating() {
                // Never replay a request body at a redirect target — the target
                // may be a different authority than the one the caller vetted.
                return Err(Error::Endpoint(format!(
                    "HTTP {} redirect on {} not followed (mutating methods never \
                     follow redirects); Location: {location}",
                    response.status,
                    self.method.as_str()
                )));
            }
            hops += 1;
            if hops > MAX_REDIRECTS {
                return Err(Error::Endpoint(format!(
                    "too many redirects (limit {MAX_REDIRECTS}) at `{location}`"
                )));
            }
            current = current.join(location).map_err(|e| {
                Error::Endpoint(format!("invalid redirect Location `{location}`: {e}"))
            })?;
            current.set_fragment(None);
        };

        // HEAD answers *existence*, per the `ikigai-fs` convention: a `"true"`/`"false"` text
        // representation for a definitive presence answer, a typed error when the status doesn't
        // speak to presence. No opinion about what's "dead" — the caller reads the honest signal.
        if self.method == Method::Head {
            let present = exists_outcome(response.status);
            let window = freshness_window(&response, inv);
            let repr = Representation::new(
                ReprType::new("text/plain"),
                if present {
                    b"true".to_vec()
                } else {
                    b"false".to_vec()
                },
            );
            return Ok(with_freshness(repr, window, inv, &thread));
        }

        // Every other method returns a representation on success and a **typed error** on a
        // non-success status — never the error-page body dressed up as the resource.
        source_outcome(response.status)?;

        // A *successful* mutating method invalidates any cached representation of the same URL by
        // cutting its thread through the kernel (so it works the same over the wire; needs
        // `urn:cap:kernel:cut`, which `root` has). On an error status we returned above without
        // cutting — a failed write leaves the cached read valid.
        if self.method.is_mutating() {
            let cut = Request::new(Verb::Sink, kernel_cut_iri())
                .with_arg("thread", ArgRef::Inline(thread.clone().into_bytes()));
            inv.issue(cut).await?;
        }

        let window = freshness_window(&response, inv);
        let repr = Representation::new(content_type(&response), response.body);
        if self.method.is_cacheable() {
            return Ok(with_freshness(repr, window, inv, &thread));
        }
        Ok(repr)
    }

    fn name(&self) -> &str {
        self.method.id()
    }

    fn describe(&self) -> Description {
        let mut description = Description::new(self.method.id())
            .title(format!("HTTP {}", self.method.as_str()))
            .summary("Dereference a URL as a resource through a host transport, capability-gated by `urn:cap:net`.")
            .verb(self.method.verb())
            // The net ACL is parameterized (urn:cap:net:<host-rule>): the wildcard
            // offers this action to any capability holding SOME net grant; the
            // actual host/path is checked against the rules at invoke time.
            .requires("urn:cap:net:*")
            .output("application/octet-stream")
            .input(ArgSpec::new("url").summary("the absolute URL to request"))
            .input(ArgSpec::new("accept").summary("value for the Accept header"))
            .input(ArgSpec::new("authorization").summary("value for the Authorization header"))
            .input(ArgSpec::new("range").summary("value for the Range header, e.g. bytes=0-1023"))
            .input(ArgSpec::new("headers").summary("extra request headers, one `Name: Value` per line"));
        if self.method.is_cacheable() {
            description = description.input(ArgSpec::new("max_age").summary(
                "cache this read for up to N seconds when a stale answer is acceptable (e.g. a \
                 liveness/existence check); takes precedence over the response's own freshness, \
                 except an explicit no-store",
            ));
        }
        if self.method.is_mutating() {
            description = description
                .input(ArgSpec::new("content").summary("the request body bytes"))
                .input(ArgSpec::new("content_type").summary("value for the Content-Type header"));
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

/// Build the request headers from the invocation's arguments: a generic
/// `headers=` block (one `Name: Value` per line) plus convenience args that map to
/// common headers (`accept`, `authorization`, `range`, `content_type`). All are
/// optional; an absent arg contributes nothing. The convenience args are appended
/// after the generic block, so an explicit `accept=` wins over one in `headers=`.
fn request_headers(inv: &Invocation<'_>) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    if let Ok(block) = inv.inline_str("headers") {
        for line in block.lines() {
            if let Some((name, value)) = line.split_once(':') {
                let (name, value) = (name.trim(), value.trim());
                if !name.is_empty() {
                    headers.push((name.to_string(), value.to_string()));
                }
            }
        }
    }
    for (arg, header) in [
        ("accept", "Accept"),
        ("authorization", "Authorization"),
        ("range", "Range"),
        ("content_type", "Content-Type"),
    ] {
        if let Ok(value) = inv.inline_str(arg) {
            headers.push((header.to_string(), value.to_string()));
        }
    }
    headers
}

/// The ROC outcome for a representation-returning resolve from an HTTP status: `Ok(())` on a
/// success (2xx, or a 3xx the transport didn't follow), else a **typed error** mapped onto the
/// taxonomy so `is_transient` drives the retry/circuit-breaker overlays correctly. The module is
/// policy-free — it reports what HTTP said; the caller decides what it means.
fn source_outcome(status: u16) -> Result<()> {
    match status {
        200..=399 => Ok(()),
        404 | 410 => Err(Error::NotFound(format!("HTTP {status}"))),
        401 | 403 => Err(Error::Denied(format!("HTTP {status}"))),
        408 | 504 => Err(Error::Timeout(format!("HTTP {status}"))),
        429 => Err(Error::Unavailable(format!("HTTP {status}"))),
        500..=599 => Err(Error::Unavailable(format!("HTTP {status}"))),
        _ => Err(Error::Endpoint(format!("HTTP {status}"))),
    }
}

/// The existence outcome for a HEAD from an HTTP status. `exists_outcome` is only reached once the
/// server has **answered** (a transport failure errors before this), so any status it sees is proof
/// the host is reachable. Existence is therefore lenient: **only 404/410 are *absent*** (`false`);
/// every other answer — including a 429 throttle, a 5xx server error, or a 408/504 timeout — means
/// the endpoint is *there*, just busy or gated, and is *present* (`true`).
///
/// This is deliberately more lenient than `source_outcome`: `Exists` asks "is it there?" and a
/// server that responds at all answers yes (bar a definitive gone); `Source` asks "give it to me"
/// and a 429/5xx is a real, honestly-typed transient failure. The split matters for callers like a
/// link-checker: a bookmark whose host answers `429`/`503` (rate-limited or briefly down, e.g.
/// behind a Cloudflare bot-wall) is **not a dead link** — only an unresolvable host is unreachable,
/// and only a 404/410 is gone.
fn exists_outcome(status: u16) -> bool {
    !matches!(status, 404 | 410)
}

/// Apply the cache policy for a cacheable read: when a freshness window applies, mark the repr
/// cacheable until that deadline **and** thread it on the URL (so a later write to the same URL
/// cuts it). With no window — or no clock — the read stays uncacheable, a live fact.
fn with_freshness(
    repr: Representation,
    window: Option<u64>,
    inv: &Invocation<'_>,
    thread: &str,
) -> Representation {
    match (window, inv.now()) {
        (Some(secs), Some(now)) => repr
            .cacheable_until(now.plus_millis(secs.saturating_mul(1000)))
            .depends_on(thread.to_string()),
        _ => repr,
    }
}

/// The freshness window (seconds) for a cacheable read: the **caller's** `max_age` arg if given,
/// else the response's `Cache-Control: max-age` — but an explicit `no-store`/`no-cache` forbids
/// caching regardless (a strong origin directive wins over a caller's staleness tolerance). The
/// caller directive is what lets a liveness/existence check cache a HEAD that carries no freshness
/// of its own, instead of hitting the network every time.
fn freshness_window(response: &HttpResponse, inv: &Invocation<'_>) -> Option<u64> {
    if response_forbids_store(response) {
        return None;
    }
    caller_max_age(inv).or_else(|| response_max_age(response))
}

/// The caller's `max_age` directive in seconds, if provided and parseable.
fn caller_max_age(inv: &Invocation<'_>) -> Option<u64> {
    inv.inline_str("max_age")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
}

/// Whether the response forbids caching outright (`Cache-Control: no-store` / `no-cache`).
fn response_forbids_store(response: &HttpResponse) -> bool {
    response.header("cache-control").is_some_and(|cc| {
        let cc = cc.to_ascii_lowercase();
        cc.contains("no-store") || cc.contains("no-cache")
    })
}

/// The response's own freshness window from `Cache-Control: max-age=N`, if present.
fn response_max_age(response: &HttpResponse) -> Option<u64> {
    let cc = response.header("cache-control")?.to_ascii_lowercase();
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
    fn method_ids_are_unique() {
        // The catalog subject + any projection keyed on the description id (an
        // MCP tool name) must not collide across the six method endpoints.
        let ids: Vec<&str> = [
            Method::Get,
            Method::Head,
            Method::Post,
            Method::Put,
            Method::Patch,
            Method::Delete,
        ]
        .iter()
        .map(|m| m.id())
        .collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "method ids collide: {ids:?}");
    }

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

    #[test]
    fn bare_net_scope_grants_nothing() {
        // `urn:cap:net:` with no host used to be a wildcard-allow (an empty rule
        // was a prefix of everything). It must grant nothing: breadth is granted
        // host by host, never by an accidentally-empty rule.
        let cap = Capability::root().attenuate(["urn:cap:net:".to_string()]);
        assert!(!net_allows(&cap, "example.com", "/"));
        assert!(!net_allows(&cap, "169.254.169.254", "/latest/meta-data"));
        let deny_only = Capability::root().attenuate(["urn:cap:net:-".to_string()]);
        assert!(!net_allows(&deny_only, "example.com", "/"));
    }

    #[test]
    fn port_rule_matches_only_its_port() {
        let cap = Capability::root().attenuate(["urn:cap:net:example.com:8443".to_string()]);
        assert!(net_allows_port(&cap, "example.com", Some(8443), "/x"));
        assert!(!net_allows_port(&cap, "example.com", Some(443), "/x"));
        assert!(!net_allows_port(&cap, "example.com", Some(22), "/"));
        // An unknown target port matches (the port-less `net_allows` callers
        // aren't judged on a port they can't know).
        assert!(net_allows(&cap, "example.com", "/x"));
        // A port-less rule matches every port on its host.
        let any = Capability::root().attenuate(["urn:cap:net:example.com".to_string()]);
        assert!(net_allows_port(&any, "example.com", Some(443), "/"));
        assert!(net_allows_port(&any, "example.com", Some(8443), "/"));
        // A ported rule with a path stays segment-aware.
        let scoped = Capability::root().attenuate(["urn:cap:net:example.com:8443/api".to_string()]);
        assert!(net_allows_port(
            &scoped,
            "example.com",
            Some(8443),
            "/api/v1"
        ));
        assert!(!net_allows_port(
            &scoped,
            "example.com",
            Some(8443),
            "/other"
        ));
    }

    #[test]
    fn ipv6_bracketed_rule_parses_host_and_port() {
        let cap = Capability::root().attenuate(["urn:cap:net:[::1]:8080".to_string()]);
        assert!(net_allows_port(&cap, "[::1]", Some(8080), "/v1/chat"));
        assert!(!net_allows_port(&cap, "[::1]", Some(9090), "/v1/chat"));
        // Without a trailing `:digits` run the address's own colons are the host.
        let host_only = Capability::root().attenuate(["urn:cap:net:[::1]".to_string()]);
        assert!(net_allows_port(&host_only, "[::1]", Some(8080), "/"));
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
    fn ungranted_host_is_a_typed_denial_not_transient() {
        // The gate is checked pre-flight (before any socket), so this is hermetic:
        // a capability that grants only `other.com` can never reach `example.com`.
        // The endpoint is invoked directly so we can assert the exact error variant.
        let ep = HttpEndpoint::new(Method::Get, Arc::new(Mock::new(resp(None))));
        let cap = Capability::root().attenuate(["urn:cap:net:other.com".to_string()]);
        let req = Request::new(Verb::Source, Iri::parse("urn:httpGet").unwrap())
            .with_arg("url", ArgRef::Inline(b"https://example.com/x".to_vec()));
        let bindings = ikigai_core::Bindings::new();
        let inv = Invocation::detached(&req, &bindings, &cap);
        let err = futures::executor::block_on(ep.invoke(&inv)).unwrap_err();
        // A capability denial is the typed, permanent `Denied` — never a generic
        // `Endpoint` string, and never transient (re-issuing won't change the answer).
        assert!(matches!(err, Error::Denied(_)), "got {err:?}");
        assert!(!err.is_transient());
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

    /// A transport that records the headers of the last request it received.
    struct Capture(std::sync::Mutex<Vec<(String, String)>>);
    #[async_trait]
    impl HttpTransport for Capture {
        async fn send(&self, request: HttpRequest) -> std::result::Result<HttpResponse, String> {
            *self.0.lock().unwrap() = request.headers.clone();
            Ok(resp(None))
        }
    }

    #[test]
    fn args_become_request_headers() {
        let transport = Arc::new(Capture(std::sync::Mutex::new(Vec::new())));
        let kernel = Kernel::new(Arc::new(space(transport.clone())));
        let cap = Capability::root();
        let req = Request::new(Verb::Source, Iri::parse("urn:httpGet").unwrap())
            .with_arg("url", ArgRef::Inline(b"https://example.com/x".to_vec()))
            .with_arg("accept", ArgRef::Inline(b"application/json".to_vec()))
            .with_arg("range", ArgRef::Inline(b"bytes=0-1023".to_vec()))
            .with_arg("headers", ArgRef::Inline(b"X-Foo: bar\nX-Empty:".to_vec()));
        futures::executor::block_on(kernel.issue(req, &cap)).unwrap();

        let sent = transport.0.lock().unwrap().clone();
        assert!(sent.contains(&("Accept".to_string(), "application/json".to_string())));
        assert!(sent.contains(&("Range".to_string(), "bytes=0-1023".to_string())));
        assert!(sent.contains(&("X-Foo".to_string(), "bar".to_string())));
        assert!(sent.contains(&("X-Empty".to_string(), String::new())));
    }

    // --- honest status + the caller freshness directive --------------------

    /// A transport that returns a chosen status (+ optional `Cache-Control`), counting sends.
    struct Status {
        code: u16,
        cc: Option<&'static str>,
        sends: AtomicU32,
    }
    impl Status {
        fn new(code: u16, cc: Option<&'static str>) -> Arc<Self> {
            Arc::new(Status {
                code,
                cc,
                sends: AtomicU32::new(0),
            })
        }
        fn sends(&self) -> u32 {
            self.sends.load(Ordering::SeqCst)
        }
    }
    #[async_trait]
    impl HttpTransport for Status {
        async fn send(&self, _req: HttpRequest) -> std::result::Result<HttpResponse, String> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            let mut headers = vec![("content-type".to_string(), "text/plain".to_string())];
            if let Some(cc) = self.cc {
                headers.push(("cache-control".to_string(), cc.to_string()));
            }
            Ok(HttpResponse {
                status: self.code,
                headers,
                body: b"body".to_vec(),
            })
        }
    }

    fn get_result(status: u16) -> Result<Representation> {
        let kernel = Kernel::new(Arc::new(space(Status::new(status, None))));
        futures::executor::block_on(kernel.issue(get("https://example.com/x"), &Capability::root()))
    }

    fn head_body(status: u16) -> Result<String> {
        let kernel = Kernel::new(Arc::new(space(Status::new(status, None))));
        let req = Request::new(Verb::Exists, Iri::parse("urn:httpHead").unwrap())
            .with_arg("url", ArgRef::Inline(b"https://example.com/x".to_vec()));
        futures::executor::block_on(kernel.issue(req, &Capability::root()))
            .map(|r| String::from_utf8(r.bytes).unwrap())
    }

    #[test]
    fn get_maps_status_onto_the_typed_error_taxonomy() {
        assert!(get_result(200).is_ok(), "2xx is a representation");
        assert!(matches!(get_result(404).unwrap_err(), Error::NotFound(_)));
        assert!(matches!(get_result(410).unwrap_err(), Error::NotFound(_)));
        assert!(matches!(get_result(401).unwrap_err(), Error::Denied(_)));
        assert!(matches!(get_result(403).unwrap_err(), Error::Denied(_)));
        assert!(matches!(get_result(504).unwrap_err(), Error::Timeout(_)));
        // 429 and 5xx are transient — the retry overlays should act on them.
        let e503 = get_result(503).unwrap_err();
        assert!(matches!(e503, Error::Unavailable(_)) && e503.is_transient());
        assert!(matches!(
            get_result(500).unwrap_err(),
            Error::Unavailable(_)
        ));
        assert!(matches!(
            get_result(429).unwrap_err(),
            Error::Unavailable(_)
        ));
        // A permanent client error we don't type specifically → Endpoint.
        let e422 = get_result(422).unwrap_err();
        assert!(matches!(e422, Error::Endpoint(_)) && !e422.is_transient());
    }

    #[test]
    fn head_existence_is_lenient_only_404_410_are_absent() {
        assert_eq!(head_body(200).unwrap(), "true");
        assert_eq!(head_body(301).unwrap(), "true");
        assert_eq!(head_body(403).unwrap(), "true", "present, just gated");
        assert_eq!(head_body(405).unwrap(), "true", "present, HEAD not allowed");
        assert_eq!(head_body(404).unwrap(), "false");
        assert_eq!(head_body(410).unwrap(), "false");
        // The server *answered*, so the host is reachable — busy/erroring is still present, NOT a
        // dead link. Only a transport failure (tested separately) is unreachable.
        assert_eq!(head_body(429).unwrap(), "true", "throttled, but there");
        assert_eq!(head_body(503).unwrap(), "true", "briefly down, but there");
        assert_eq!(head_body(500).unwrap(), "true", "erroring, but there");
        assert_eq!(
            head_body(504).unwrap(),
            "true",
            "gateway timeout, but reachable"
        );
    }

    #[test]
    fn a_transport_failure_is_a_transient_unavailable() {
        struct Boom;
        #[async_trait]
        impl HttpTransport for Boom {
            async fn send(&self, _r: HttpRequest) -> std::result::Result<HttpResponse, String> {
                Err("connection refused".into())
            }
        }
        let kernel = Kernel::new(Arc::new(space(Arc::new(Boom))));
        let err = futures::executor::block_on(
            kernel.issue(get("https://example.com/x"), &Capability::root()),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unavailable(_)) && err.is_transient());
    }

    /// A GET carrying a `max_age` directive, resolved repeatedly.
    fn max_age_get() -> Request {
        Request::new(Verb::Source, Iri::parse("urn:httpGet").unwrap())
            .with_arg("url", ArgRef::Inline(b"https://example.com/x".to_vec()))
            .with_arg("max_age", ArgRef::Inline(b"3600".to_vec()))
    }

    #[test]
    fn a_caller_max_age_caches_a_response_that_carries_no_freshness() {
        let transport = Status::new(200, None); // origin says nothing about caching
        let clock = TestClock::at(0);
        let kernel =
            Kernel::new(Arc::new(space(transport.clone()))).with_clock(Arc::new(clock.clone()));
        let cap = Capability::root();
        futures::executor::block_on(kernel.issue(max_age_get(), &cap)).unwrap();
        futures::executor::block_on(kernel.issue(max_age_get(), &cap)).unwrap();
        assert_eq!(
            transport.sends(),
            1,
            "the caller directive makes an otherwise-uncacheable read cacheable"
        );
        clock.set(3_601_000);
        futures::executor::block_on(kernel.issue(max_age_get(), &cap)).unwrap();
        assert_eq!(
            transport.sends(),
            2,
            "refetched after the caller window elapsed"
        );
    }

    #[test]
    fn a_caller_max_age_overrides_a_shorter_response_max_age() {
        let transport = Status::new(200, Some("max-age=60"));
        let clock = TestClock::at(0);
        let kernel =
            Kernel::new(Arc::new(space(transport.clone()))).with_clock(Arc::new(clock.clone()));
        let cap = Capability::root();
        futures::executor::block_on(kernel.issue(max_age_get(), &cap)).unwrap();
        clock.set(61_000); // past the origin's 60s, well within the caller's hour
        futures::executor::block_on(kernel.issue(max_age_get(), &cap)).unwrap();
        assert_eq!(
            transport.sends(),
            1,
            "the caller window takes precedence over the shorter response max-age"
        );
    }

    #[test]
    fn no_store_forbids_caching_even_with_a_caller_max_age() {
        let transport = Status::new(200, Some("no-store"));
        let clock = TestClock::at(0);
        let kernel =
            Kernel::new(Arc::new(space(transport.clone()))).with_clock(Arc::new(clock.clone()));
        let cap = Capability::root();
        futures::executor::block_on(kernel.issue(max_age_get(), &cap)).unwrap();
        futures::executor::block_on(kernel.issue(max_age_get(), &cap)).unwrap();
        assert_eq!(
            transport.sends(),
            2,
            "an explicit no-store beats the caller's staleness tolerance"
        );
    }

    // --- Redirects: the endpoint follows, the ACL runs per hop ---------------

    /// A transport scripted with a response per call, recording each requested
    /// URL. When the script runs out it repeats the last response (so a
    /// redirect-forever loop needs only one entry).
    struct Seq {
        responses: std::sync::Mutex<Vec<HttpResponse>>,
        urls: std::sync::Mutex<Vec<String>>,
    }
    impl Seq {
        fn new(responses: Vec<HttpResponse>) -> Arc<Self> {
            Arc::new(Seq {
                responses: std::sync::Mutex::new(responses),
                urls: std::sync::Mutex::new(Vec::new()),
            })
        }
        fn urls(&self) -> Vec<String> {
            self.urls.lock().unwrap().clone()
        }
    }
    #[async_trait]
    impl HttpTransport for Seq {
        async fn send(&self, request: HttpRequest) -> std::result::Result<HttpResponse, String> {
            self.urls.lock().unwrap().push(request.url.clone());
            let mut scripted = self.responses.lock().unwrap();
            Ok(if scripted.len() > 1 {
                scripted.remove(0)
            } else {
                scripted[0].clone()
            })
        }
    }

    fn redirect_to(status: u16, location: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: vec![("location".to_string(), location.to_string())],
            body: Vec::new(),
        }
    }

    fn ok_body(body: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn a_redirect_to_a_granted_host_is_followed_with_the_acl_re_run() {
        let transport = Seq::new(vec![
            redirect_to(302, "https://b.example.com/data"),
            ok_body("moved here"),
        ]);
        let kernel = Kernel::new(Arc::new(space(transport.clone())));
        let cap = Capability::root().attenuate([
            "urn:cap:net:a.example.com".to_string(),
            "urn:cap:net:b.example.com".to_string(),
        ]);
        let out =
            futures::executor::block_on(kernel.issue(get("https://a.example.com/start"), &cap))
                .unwrap();
        assert_eq!(out.bytes, b"moved here");
        assert_eq!(
            transport.urls(),
            vec![
                "https://a.example.com/start".to_string(),
                "https://b.example.com/data".to_string(),
            ],
            "both hops went over the wire, in order"
        );
    }

    #[test]
    fn a_redirect_to_an_ungranted_host_is_a_typed_denial() {
        // The first host is granted and answers with a 302 to a host the
        // capability does NOT grant — the classic SSRF-via-redirect. The hop must
        // die at the ACL, typed `Denied`, without the second request being sent.
        let transport = Seq::new(vec![
            redirect_to(302, "http://169.254.169.254/latest/meta-data"),
            ok_body("must never be reached"),
        ]);
        let ep = HttpEndpoint::new(Method::Get, transport.clone());
        let cap = Capability::root().attenuate(["urn:cap:net:a.example.com".to_string()]);
        let req = Request::new(Verb::Source, Iri::parse("urn:httpGet").unwrap()).with_arg(
            "url",
            ArgRef::Inline(b"https://a.example.com/start".to_vec()),
        );
        let bindings = ikigai_core::Bindings::new();
        let inv = Invocation::detached(&req, &bindings, &cap);
        let err = futures::executor::block_on(ep.invoke(&inv)).unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "got {err:?}");
        assert!(
            err.to_string().contains("redirect target"),
            "the denial names the redirect: {err}"
        );
        assert_eq!(
            transport.urls().len(),
            1,
            "the ungranted hop was refused before any I/O"
        );
    }

    #[test]
    fn mutating_methods_never_follow_redirects() {
        let transport = Seq::new(vec![
            redirect_to(307, "https://b.example.com/submit"),
            ok_body("must never be reached"),
        ]);
        let kernel = Kernel::new(Arc::new(space(transport.clone())));
        let cap = Capability::root(); // even root: the refusal is policy, not authority
        let req = Request::new(Verb::Sink, Iri::parse("urn:httpPost").unwrap())
            .with_arg(
                "url",
                ArgRef::Inline(b"https://a.example.com/form".to_vec()),
            )
            .with_arg("content", ArgRef::Inline(b"payload".to_vec()));
        let err = futures::executor::block_on(kernel.issue(req, &cap)).unwrap_err();
        assert!(
            err.to_string().contains("never follow redirects"),
            "got {err}"
        );
        assert_eq!(
            transport.urls().len(),
            1,
            "the body was not replayed at the redirect target"
        );
    }

    #[test]
    fn a_redirect_loop_stops_at_the_hop_limit() {
        // One scripted entry that repeats: every request 302s back to itself.
        let transport = Seq::new(vec![redirect_to(302, "https://a.example.com/loop")]);
        let kernel = Kernel::new(Arc::new(space(transport.clone())));
        let cap = Capability::root().attenuate(["urn:cap:net:a.example.com".to_string()]);
        let err =
            futures::executor::block_on(kernel.issue(get("https://a.example.com/loop"), &cap))
                .unwrap_err();
        assert!(err.to_string().contains("too many redirects"), "got {err}");
        assert_eq!(
            transport.urls().len(),
            6,
            "the original request plus five followed hops, then the limit"
        );
    }

    #[test]
    fn a_relative_location_resolves_against_the_current_url() {
        let transport = Seq::new(vec![redirect_to(301, "/moved"), ok_body("relative ok")]);
        let kernel = Kernel::new(Arc::new(space(transport.clone())));
        let cap = Capability::root().attenuate(["urn:cap:net:a.example.com".to_string()]);
        let out = futures::executor::block_on(kernel.issue(get("https://a.example.com/old"), &cap))
            .unwrap();
        assert_eq!(out.bytes, b"relative ok");
        assert_eq!(
            transport.urls()[1],
            "https://a.example.com/moved",
            "a relative Location joins the current URL"
        );
    }
}
