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
//! | resolve  | IRI                 | id              | HTTP     | cacheable |
//! |----------|---------------------|-----------------|----------|-----------|
//! | `source` | `urn:http:get`      | `http-get`      | GET      | yes       |
//! | `exists` | `urn:http:head`     | `http-head`     | HEAD     | yes       |
//! | `sink`   | `urn:http:post`     | `http-post`     | POST     | no        |
//! | `sink`   | `urn:http:put`      | `http-put`      | PUT      | no        |
//! | `sink`   | `urn:http:patch`    | `http-patch`    | PATCH    | no        |
//! | `delete` | `urn:http:delete`   | `http-delete`   | DELETE   | no        |
//! | `sink`   | `urn:http:propfind` | `http-propfind` | PROPFIND | no        |
//! | `sink`   | `urn:http:report`   | `http-report`   | REPORT   | no        |
//!
//! The target URL is an argument (`url=`), not part of the IRI, so one binding
//! serves every URL and the cache keys on the URL via the request identity.
//!
//! ## WebDAV: PROPFIND and REPORT (0.2.2, ledger #1875)
//!
//! `PROPFIND` (RFC 4918 §9.1) and `REPORT` (RFC 3253 §3.6) are what CalDAV and
//! CardDAV are built on: listing a calendar home, a `calendar-query` (RFC 4791), an
//! RFC 6578 `sync-collection`. Both are safe methods that carry an XML request
//! body, so they resolve with `sink` (the verb that takes `content=`) and are
//! **uncacheable**, but they are not writes: a success does NOT cut the URL's golden
//! thread, so a cached `GET` of the same URL stays cached. The `Depth` header goes
//! through `headers=` (`headers="Depth: 1"`); there is no separate argument. A
//! `207 Multi-Status` is a success and its body passes through with the origin's
//! `Content-Type`. Like the mutating methods they **never follow a redirect**: a
//! 3xx with a `Location` is a typed error naming the target, so the request body is
//! never replayed at an authority the caller did not vet. The capability ACL is the
//! same `urn:cap:net:<host>` check as every other method.
//!
//! ```
//! use ikigai_http::Method;
//! assert_eq!(Method::Propfind.as_str(), "PROPFIND");
//! assert_eq!(Method::Propfind.iri(), "urn:http:propfind");
//! assert_eq!(Method::Report.id(), "http-report");
//! assert!(!Method::Report.is_cacheable() && !Method::Report.is_mutating());
//! ```
//!
//! ## Deprecated names (still bound in 0.3.x)
//!
//! Through 0.1.x the six bound at `urn:httpGet` … `urn:httpDelete` with ids
//! `httpGet` … `httpDelete`. 0.2.0 renamed them to the kebab-case convention
//! ikigai-core's crate docs state, and keeps each old IRI as a deprecated
//! **alias** of its new one for this minor release, so a consumer holding an old
//! name keeps working while it migrates (see [`deprecated_aliases`]). An alias
//! resolves exactly as its backing name: one cache entry, one golden thread, the
//! backing description (id `http-get`, not `httpGet`), and only the new names in
//! the catalog. The old ids are NOT kept: an id is a name, not an IRI, and nothing
//! resolves by it, so an agent's MCP tool names move with this release.
//!
//! They were due to go in 0.3.0 and **stay bound through 0.3.x**: when 0.3.0 was cut
//! (ledger #1546), callers still named them (ikigai-runbook's demo commands, the
//! `RateLimit` example in ikigai-throttle's docs), and removing a name breaks its
//! callers at run time, never at compile time. Their removal is a later minor of its
//! own, once those have moved; `urn:kernel:aliases` counts what still calls them.
//!
//! ```
//! use ikigai_http::Method;
//! assert_eq!(Method::Get.iri(), "urn:http:get");
//! assert_eq!(Method::Get.id(), "http-get");
//! assert_eq!(Method::Get.deprecated_iri(), "urn:httpGet");
//! ```
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
//! - `urn:cap:net:*.edu` — every host under `.edu` (`mit.edu`, `a.b.mit.edu`), in
//!   ONE token (ledger #35; see "Host globs" below).
//!
//! Matching is **most specific wins**, **deny breaks ties**, segment-aware (so
//! `/api` does not match `/apixyz`); no matching rule → **default-deny**. A rule
//! without a port matches any port; a rule with a port matches exactly that port
//! (an IPv6 host in a rule uses brackets: `urn:cap:net:[::1]:8080`). A bare
//! `urn:cap:net:` scope (no host) grants **nothing**: there is no match-everything
//! rule, and the widest grant short of `root` is a glob over one suffix. A `root`
//! capability allows everything. A rule with an empty host or an invalid port
//! (empty, nonnumeric, or outside `0..=65535`) is malformed: an allow grants
//! nothing, and a deny refuses the whole check, even for another host or path.
//! (Per the locked design the scope is host/path only — not per-method; an agent
//! is trusted with a host, not with a verb. A finer `urn:cap:net:<method>:…` form
//! is a possible later refinement.)
//!
//! Hosts are compared **normalized**, the request's and the rule's alike: ASCII case
//! ignored, one trailing dot dropped (`mit.edu.` is `mit.edu`), an internationalized
//! name in its A-label (punycode) form (`bücher.de` is `xn--bcher-kva.de`), and an IP
//! literal in canonical form. The normalization is the URL parser's own (the `url`
//! crate's WHATWG host parser and IDNA), so a rule means the host a URL resolves to.
//!
//! ### Host globs
//!
//! `urn:cap:net:*.<suffix>[:<port>][/<path-prefix>]`, as an allow or a deny
//! (`urn:cap:net:-*.example.com`). The `*` is the **whole leftmost label** and stands
//! for one or more labels:
//!
//! - `*.edu` matches `mit.edu` and `a.b.mit.edu`, and NOT `edu` itself, `xedu`,
//!   `notedu`, or `mit.edu.evil.com`. Labels match whole, so `*.example.com` does not
//!   match `badexample.com`.
//! - A glob never matches an IP literal: `*.1` is not a glob at all (its suffix is a
//!   number), and no glob matches `10.0.0.1` or `[::1]`.
//! - Only that one form is a glob. A `*` anywhere else in the host is **malformed**:
//!   `*`, `*.`, `**.com`, `*foo.com`, `foo*.com`, `a.*.com`, `*.*.com`. A malformed
//!   allow grants nothing; a malformed **deny refuses every request** under that
//!   capability, because skipping it would silently widen what the holder meant to
//!   grant. Either way a malformed rule never widens.
//!
//! **Specificity**, from most to least: an exact host outranks every glob for the same
//! host; between globs a longer suffix outranks a shorter one; between rules with the
//! same host part, the longer `:port`/`/path` wins, as it always has. A deny still
//! breaks a tie. So `*.edu` + `-*.cs.mit.edu` grants `mit.edu` but not `ai.cs.mit.edu`;
//! `-*.edu` + `mit.edu` grants only `mit.edu`; `*.edu/api` + `-*.edu/api/admin` grants
//! `/api` under `.edu` except `/api/admin`. The host decides FIRST: `mit.edu` +
//! `-*.edu/admin` grants `mit.edu/admin`, since an exact host outranks the glob
//! whatever its path; to keep `/admin` out there, say so on the exact host
//! (`-mit.edu/admin`).
//!
//! ⚠ **A glob over a public suffix is very broad.** `*.com` or `*.co.uk` is every
//! registrable name under it, and nothing here consults a public-suffix list. A TLD
//! glob is allowed on purpose (the `.edu` ceiling is the point of the form), so treat
//! one as close to `root` for that suffix.
//!
//! ```
//! use ikigai_core::Capability;
//! use ikigai_http::{net_allows, net_allows_port};
//!
//! let cap = Capability::root().attenuate([
//!     "urn:cap:net:*.edu".to_string(),
//!     "urn:cap:net:-*.cs.mit.edu".to_string(),
//! ]);
//! assert!(net_allows(&cap, "mit.edu", "/"));
//! assert!(net_allows(&cap, "a.b.mit.edu", "/x"));
//! assert!(net_allows(&cap, "MIT.EDU.", "/")); // normalized
//! assert!(!net_allows(&cap, "ai.cs.mit.edu", "/")); // the longer suffix denies
//! assert!(!net_allows(&cap, "edu", "/")); // not the suffix itself
//! assert!(!net_allows(&cap, "mit.edu.evil.com", "/"));
//!
//! // A port on a glob, and a malformed rule granting nothing.
//! let port = Capability::root().attenuate([
//!     "urn:cap:net:*.edu:443".to_string(),
//!     "urn:cap:net:foo*.com".to_string(),
//! ]);
//! assert!(net_allows_port(&port, "mit.edu", Some(443), "/"));
//! assert!(!net_allows_port(&port, "mit.edu", Some(80), "/"));
//! assert!(!net_allows(&port, "foox.com", "/"));
//! ```
//!
//! ## Redirects
//!
//! The **endpoint** owns redirect-following; a host transport must return 3xx
//! responses as-is and never follow them itself (an auto-following transport
//! would let a granted host 302 the request to an ungranted one — the classic
//! SSRF-via-redirect). For cacheable methods (`GET`/`HEAD`) the endpoint follows
//! up to 5 hops, re-running the capability ACL against **each** hop's host, port
//! and path — a redirect to an ungranted authority is a typed `Denied`, a host
//! outside a granted glob included. Every
//! other method sends a body and never follows a redirect (no cross-host replay of
//! a request body): a 3xx with a `Location` on `POST`/`PUT`/`PATCH`/`DELETE`/
//! `PROPFIND`/`REPORT` is a typed error naming the target instead.
//!
//! When a redirect changes origin (scheme, host, or effective port), the endpoint
//! removes `Authorization`, `Proxy-Authorization`, and `Cookie`, case-insensitively,
//! including values supplied through `headers=`. They stay removed on every later
//! hop, even one returning to the original origin. Same-origin redirects preserve
//! them; other headers are preserved on every hop. This follows the credential
//! isolation principle in Fetch's [HTTP-redirect fetch](https://fetch.spec.whatwg.org/#http-redirect-fetch)
//! and [curl's restriction on forwarding Authorization](https://curl.se/docs/CVE-2018-1000007.html).
//! A caller who needs a credential on the target must call the target directly.
//!
//! The credential to authenticate with (when one is needed) is itself meant to be
//! capability-gated — the agent gets "may call host X with credential Y", never the
//! raw token — but that, and headers/body/range/auth args, land with the backend.
//!
//! ## Authorization headers and base64: the shared helpers
//!
//! Two plain-function modules, usable with or without the endpoints, are the
//! ecosystem's one implementation of a standard every HTTP caller needs (ledger
//! #1857): [`auth`] builds `Basic` (RFC 7617) and `Bearer` (RFC 6750) header values
//! and recognizes the scheme of an incoming one, and [`base64`] is RFC 4648 base64
//! (the vetted `base64` crate behind a two-function face; [`base64`]'s docs say why).
//! A module calls these rather than formatting a header or encoding by hand.
//!
//! ```
//! let auth = ikigai_http::auth::basic("Aladdin", "open sesame").unwrap();
//! assert_eq!(auth.as_str(), "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
//! assert_eq!(ikigai_http::base64::decode(auth.credentials()).unwrap(), b"Aladdin:open sesame");
//! ```
//!
//! ## Honest status: one table (0.3.0, needs `ikigai-core` ≥ 0.1.108)
//!
//! The endpoint reports what HTTP said, mapped onto the typed-error taxonomy — it never hands
//! back a `404` error page dressed up as the resource. It is **policy-free**: the caller decides
//! what a status *means* for its purpose. The mapping is ONE public table, [`status`], which
//! every module that talks HTTP calls instead of keeping a copy; each error's
//! [`class`](ikigai_core::Error::class) (core's) says who may repeat it.
//!
//! - `GET`/`source` (and every method that sends a body): 2xx → the representation; 404/410 →
//!   `NotFound`; **401/403 → `Refused`** (an origin refused our credential; `Denied` stays the
//!   capability floor's word); 408/504 → `Timeout`; 409/412 → `Conflict`; 413/414/431 →
//!   `OverBudget`; **429 → `RetryAfter`**, its delay from `Retry-After` (delay-seconds, or an
//!   HTTP-date on the kernel's clock); 503 → `RetryAfter` with a usable `Retry-After`, else
//!   `Unavailable`; 502 → `Unavailable`; 501 → `Unsupported`; **500 and every other 5xx →
//!   `Endpoint`** (unknown, not transient); any other status → `Endpoint`.
//! - A transport-level failure is `Timeout` when the transport says it timed out, else
//!   `Unavailable` ([`status::transport_error`]). Each action declares these classes
//!   ([`Description::fails`]), so the manifold says what can go wrong before anything does.
//!
//! ```
//! use ikigai_core::{Error, FailureClass};
//! let refused = ikigai_http::status::status_error(401, None, "HTTP 401").unwrap();
//! assert!(matches!(refused, Error::Refused(_)));
//! assert_eq!(refused.class(), FailureClass::Refused);
//! ```
//! - `HEAD`/`exists`: a `"true"`/`"false"` text representation, following the `ikigai-fs` `Exists`
//!   convention (existence is an answer, not an error). Existence is **lenient**: the check is only
//!   reached once the server has answered, so any status but 304/404/410 means the host is reachable and
//!   the endpoint is *present* (`true`) — a 429 throttle, a 5xx error, a 408/504 timeout all count
//!   as there-but-busy. Only 404/410 is *absent* (`false`); only a transport failure (which errors
//!   before the status is seen) is unreachable. This is deliberately more lenient than `Source`:
//!   `Exists` asks "is it there?", `Source` asks "give it to me" (where a 429/5xx is an honest
//!   transient error). A link-checker leans on the split — a bookmark whose host answers `429`/`503`
//!   is not dead.
//!
//! A `304 Not Modified` answers an endpoint-generated conditional GET/HEAD by
//! serving core's stored body under the 304's own freshness deadline. Its transport
//! body is dropped unread. Without such a condition it remains an empty,
//! uncacheable result with `repr_type.params["http-status"] = "304"`; callers
//! sending their own validators must inspect that metadata and reuse their content.
//!
//! ## Caching (needs `ikigai-core` ≥ 0.2.6)
//!
//! GET/HEAD answers carry the origin's `ETag` and/or `Last-Modified`. A stale
//! offer from core sends `If-None-Match` and/or `If-Modified-Since`; a 200 replaces
//! the representation. Cached answers depend on the URL's golden thread, so a
//! successful mutation invalidates them, including after revalidation.
//!
//! Freshness comes from the caller's `max_age=`, then `Cache-Control: max-age`,
//! then `Expires`, then 10% of the age since `Last-Modified` (capped at one day).
//! Dates use the response's `Date` or the injected kernel clock. `no-store`
//! forbids storage; `no-cache` and `max-age=0, must-revalidate` override the caller
//! with a zero lifetime. Validator-only answers also receive a zero lifetime.
//! Without a kernel clock reads stay uncacheable. RSS ttl is not an HTTP policy.
//!
//! **Core 0.2.6 limitation:** core declines entries already expired when returned.
//! Zero-lifetime answers therefore still refetch unconditionally; storing them
//! for revalidation on every read requires a core fix. Positive-lifetime answers
//! revalidate after expiration. See the ignored regression tests for the blocker.

use std::sync::Arc;

use async_trait::async_trait;
use ikigai_core::{
    Alias, AliasTable, ArgRef, ArgSpec, Description, Endpoint, EndpointSpace, Error, Exact,
    FailureClass, Invocation, Iri, OriginValidator, ReprType, Representation, Request, Result,
    Verb,
};
use url::Url;

pub mod auth;
pub mod base64;
pub mod body;
pub mod range;
pub mod status;
pub use body::{HttpBody, DEFAULT_MAX_RESPONSE_BYTES};

/// The XSD datatypes the inputs declare: the URL is an IRI, a header value is a
/// string, a freshness window is a count of seconds.
const XSD_ANY_URI: &str = "http://www.w3.org/2001/XMLSchema#anyURI";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const XSD_NON_NEGATIVE_INTEGER: &str = "http://www.w3.org/2001/XMLSchema#nonNegativeInteger";

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
    /// WebDAV `PROPFIND` (RFC 4918): safe, carries an XML body, never cached.
    Propfind,
    /// WebDAV `REPORT` (RFC 3253): safe, carries an XML body, never cached.
    Report,
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
            Method::Propfind => "PROPFIND",
            Method::Report => "REPORT",
        }
    }

    /// The ROC verb this method is resolved with — chosen so the verb's
    /// cacheability matches the method's idempotency. `PROPFIND` and `REPORT` are
    /// safe but carry a request body and must not be cached, so they take `Sink`,
    /// the verb that receives `content=`.
    pub fn verb(self) -> Verb {
        match self {
            Method::Get => Verb::Source,
            Method::Head => Verb::Exists,
            Method::Post | Method::Put | Method::Patch | Method::Propfind | Method::Report => {
                Verb::Sink
            }
            Method::Delete => Verb::Delete,
        }
    }

    /// Every method, in the order [`space`] binds them.
    pub const ALL: [Method; 8] = [
        Method::Get,
        Method::Head,
        Method::Post,
        Method::Put,
        Method::Patch,
        Method::Delete,
        Method::Propfind,
        Method::Report,
    ];

    /// The conventional IRI this method binds at: `urn:http:` plus the method,
    /// lowercased.
    pub fn iri(self) -> &'static str {
        match self {
            Method::Get => "urn:http:get",
            Method::Head => "urn:http:head",
            Method::Post => "urn:http:post",
            Method::Put => "urn:http:put",
            Method::Patch => "urn:http:patch",
            Method::Delete => "urn:http:delete",
            Method::Propfind => "urn:http:propfind",
            Method::Report => "urn:http:report",
        }
    }

    /// The pre-0.2.0 IRI, kept bound as a deprecated alias of [`iri`](Self::iri)
    /// through the 0.3.x line, and removed in a later minor. See [`deprecated_aliases`].
    ///
    /// `PROPFIND` and `REPORT` arrived in 0.2.2 and never had an old name, so for
    /// them this is [`iri`](Self::iri) itself, and [`deprecated_aliases`] has no
    /// rule for them ([`has_deprecated_iri`](Self::has_deprecated_iri) is `false`).
    pub fn deprecated_iri(self) -> &'static str {
        match self {
            Method::Get => "urn:httpGet",
            Method::Head => "urn:httpHead",
            Method::Post => "urn:httpPost",
            Method::Put => "urn:httpPut",
            Method::Patch => "urn:httpPatch",
            Method::Delete => "urn:httpDelete",
            Method::Propfind | Method::Report => self.iri(),
        }
    }

    /// Whether this method has a pre-0.2.0 name bound as a deprecated alias: the
    /// original six do, `PROPFIND` and `REPORT` (0.2.2) do not.
    pub fn has_deprecated_iri(self) -> bool {
        self.deprecated_iri() != self.iri()
    }

    /// The endpoint's description id: a kebab-case noun, the one the MCP
    /// projection turns into an agent's tool name. UNIQUE per method, so the
    /// catalog subject (`urn:ikigai:endpoint:{id}`) and any projection keyed on it
    /// don't collide across the method endpoints.
    pub fn id(self) -> &'static str {
        match self {
            Method::Get => "http-get",
            Method::Head => "http-head",
            Method::Post => "http-post",
            Method::Put => "http-put",
            Method::Patch => "http-patch",
            Method::Delete => "http-delete",
            Method::Propfind => "http-propfind",
            Method::Report => "http-report",
        }
    }

    /// Whether resolving this method may be served from cache (idempotent reads).
    pub fn is_cacheable(self) -> bool {
        self.verb().is_cacheable()
    }

    /// Whether this method mutates the target (and so should cut its URL thread).
    /// `PROPFIND` and `REPORT` are safe methods: they carry a body but change
    /// nothing, so they are not mutating and cut no thread.
    pub fn is_mutating(self) -> bool {
        matches!(
            self,
            Method::Post | Method::Put | Method::Patch | Method::Delete
        )
    }

    /// Whether the endpoint sends `content=` as the request body: every method
    /// but `GET` and `HEAD`. A method that sends a body never follows a redirect.
    fn sends_body(self) -> bool {
        !self.is_cacheable()
    }
}

/// The capability path-ACL for outbound HTTP: does `capability` grant a request to
/// `host` + `path`, on any port? Mirrors the file module's matcher but over a URL's
/// authority and path. Scopes are `urn:cap:net:<host>[:<port>][/<path-prefix>]`,
/// where `<host>` may also be a leftmost-label glob (`*.edu`); a leading `-` denies.
/// The most specific matching rule wins (an exact host over any glob, a longer glob
/// suffix over a shorter one, then the longer port/path), a deny breaks ties, no
/// rule means deny, and a `root` capability allows everything. The module docs,
/// "The capability ACL", state the whole grammar.
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
///
/// A host glob (`urn:cap:net:*.edu`) matches every host strictly under its suffix,
/// whole labels only, and never an IP literal. A rule with a `*` anywhere else in its
/// host is MALFORMED: as an allow it grants nothing, and as a deny it makes this
/// check refuse every request, since ignoring a deny would widen the grant.
/// The same applies to rules with an empty host or an invalid port (empty,
/// nonnumeric, or outside `0..=65535`).
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
    // The request host, normalized once: ASCII lowercase, one trailing dot dropped,
    // an IDN in its A-label (punycode) form, an IP literal canonical. `None` when the
    // host does not parse; such a host matches exact rules by plain comparison and no
    // glob.
    let target = normalize_host(host);

    let mut best: Option<Specificity> = None;
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
        let parsed = match parse_rule(rule) {
            Ok(parsed) => parsed,
            // A malformed rule. As an allow it grants nothing. As a deny it refuses the
            // whole check: the holder meant to exclude SOMETHING and we cannot tell
            // what, so skipping it would silently widen the grant.
            Err(Malformed) => {
                if rule_allows {
                    continue;
                }
                return false;
            }
        };
        let Some(specificity) = parsed.matches(host, target.as_ref(), port, path) else {
            continue;
        };
        match best {
            Some(b) if specificity < b => {} // a more specific rule already decided
            Some(b) if specificity == b => {
                // Tie on specificity: deny wins.
                allowed = allowed && rule_allows;
            }
            _ => {
                best = Some(specificity);
                allowed = rule_allows;
            }
        }
    }
    best.is_some() && allowed
}

/// How specific a matching rule is, compared lexicographically: the HOST first (an
/// exact host outranks every glob, and a glob with a longer suffix outranks a shorter
/// one), then the length of the rest of the rule (`:port` and `/path`), which is how
/// rules on one exact host have always been ranked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Specificity {
    host: HostRank,
    rest: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum HostRank {
    /// A glob, ranked by the byte length of its normalized suffix. Two globs that
    /// both match one host are both suffixes of it, so the longer is the narrower.
    Glob(usize),
    /// An exact host: above every glob.
    Exact,
}

/// A rule with a malformed host glob, an empty host, or an invalid port.
#[derive(Debug, PartialEq, Eq)]
struct Malformed;

/// A host in canonical form.
#[derive(Clone, Debug, PartialEq, Eq)]
enum NormHost {
    /// A registered name: ASCII lowercase, A-labels, no trailing dot, no empty label.
    Domain(String),
    /// An IPv4 literal (dotted decimal) or a bracketed IPv6 literal (`[::1]`).
    Ip(String),
}

/// Normalize a host the way the URL parser does (WHATWG host parsing through the
/// `url` crate's IDNA, never by hand): one trailing dot dropped, ASCII lowercased,
/// an IDN mapped to its A-label (punycode) form, an IP literal in canonical form.
/// `None` when it is not a host the parser accepts, or a name with an empty label.
fn normalize_host(host: &str) -> Option<NormHost> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        return None;
    }
    match url::Host::parse(host).ok()? {
        url::Host::Domain(d) => {
            if d.split('.').any(str::is_empty) {
                None
            } else {
                Some(NormHost::Domain(d))
            }
        }
        url::Host::Ipv4(a) => Some(NormHost::Ip(a.to_string())),
        url::Host::Ipv6(a) => Some(NormHost::Ip(format!("[{a}]"))),
    }
}

/// The host part of a parsed rule.
enum RuleHost<'a> {
    /// An exact host, kept raw (compared case-insensitively when it does not
    /// normalize) and normalized.
    Exact(&'a str, Option<NormHost>),
    /// `*.<suffix>`: the normalized suffix, always a registered name.
    Glob(String),
}

/// One parsed rule: `host[:port][/path-prefix]`.
struct Rule<'a> {
    host: RuleHost<'a>,
    port: Option<u16>,
    path: &'a str,
    /// The byte length of `[:port][/path]`, the rule's specificity after its host.
    rest: usize,
}

/// Parse one rule, rejecting malformed globs, empty hosts, and invalid ports.
/// A bracketed IPv6 host (`[::1]:8080`) parses as host `[::1]`, port `8080`;
/// a bracketed authority ending in `]` has no port.
fn parse_rule(rule: &str) -> std::result::Result<Rule<'_>, Malformed> {
    let (rule_authority, rule_path) = match rule.split_once('/') {
        Some((authority, path)) => (authority, path),
        None => (rule, ""),
    };
    let (rule_host, rule_port) = match rule_authority.rsplit_once(':') {
        Some((h, p)) if !(rule_authority.starts_with('[') && rule_authority.ends_with(']')) => {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Malformed);
            }
            (h, Some(p.parse::<u16>().map_err(|_| Malformed)?))
        }
        _ => (rule_authority, None),
    };
    if rule_host.is_empty() {
        return Err(Malformed);
    }
    let host = if rule_host.contains('*') {
        // Exactly one form: `*.` followed by a suffix with no `*`, which normalizes to
        // a registered name. That refuses `*`, `*.`, `**.com`, `*foo.com`, `foo*.com`,
        // `a.*.com`, `*.*.com`, and a suffix that is an IP literal (`*.1`, `*.[::1]`).
        let suffix = rule_host.strip_prefix("*.").ok_or(Malformed)?;
        if suffix.contains('*') {
            return Err(Malformed);
        }
        match normalize_host(suffix) {
            Some(NormHost::Domain(d)) => RuleHost::Glob(d),
            _ => return Err(Malformed),
        }
    } else {
        RuleHost::Exact(rule_host, normalize_host(rule_host))
    };
    Ok(Rule {
        host,
        port: rule_port,
        path: rule_path,
        rest: rule.len() - rule_host.len(),
    })
}

impl Rule<'_> {
    /// Whether this rule covers the target authority, and if so how specifically:
    /// the host matches (below), the rule port — when present — equals the target
    /// port (an unknown target port matches any rule port), and the rule's path
    /// segments are a leading run of the target's — so `example.com/api` covers
    /// `/api/x` but not `/apixyz`.
    ///
    /// An exact host matches when both sides normalize to the same host, or, when
    /// either does not normalize, when they are equal ignoring ASCII case. A glob
    /// `*.<suffix>` matches a registered name that ends in `.<suffix>` and is longer
    /// than it, so it never matches the suffix itself, a name that merely ends in the
    /// same letters (`xedu`), an IP literal, or a host with a `*` in it.
    fn matches(
        &self,
        raw_host: &str,
        target: Option<&NormHost>,
        port: Option<u16>,
        path: &str,
    ) -> Option<Specificity> {
        let host = match &self.host {
            RuleHost::Exact(raw, norm) => {
                let same = match (norm, target) {
                    (Some(rule), Some(target)) => rule == target,
                    _ => raw.eq_ignore_ascii_case(raw_host),
                };
                if !same {
                    return None;
                }
                HostRank::Exact
            }
            RuleHost::Glob(suffix) => {
                let Some(NormHost::Domain(name)) = target else {
                    return None;
                };
                let under = name.len() > suffix.len() + 1
                    && name.ends_with(suffix.as_str())
                    && name.as_bytes()[name.len() - suffix.len() - 1] == b'.';
                if !under || name.contains('*') {
                    return None;
                }
                HostRank::Glob(suffix.len())
            }
        };
        if let (Some(rule_port), Some(port)) = (self.port, port) {
            if rule_port != port {
                return None;
            }
        }
        let rule_segs: Vec<&str> = self.path.split('/').filter(|s| !s.is_empty()).collect();
        let target_segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let covered = rule_segs.len() <= target_segs.len()
            && rule_segs.iter().zip(&target_segs).all(|(r, t)| r == t);
        covered.then_some(Specificity {
            host,
            rest: self.rest,
        })
    }
}

/// A single outbound request, as ikigai-http hands it to the host's transport.
#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// The host transport's reply. The body is consumed once; dropping it stops reads.
#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: HttpBody,
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
/// Return headers before collecting the body. Wrap the client's asynchronous
/// reader with [`HttpBody::from_reader`]; do not buffer an unbounded response
/// inside `send`. Dropping a body must stop further reads. The endpoint counts
/// actual bytes as it collects them, with an 8 MiB default limit (configurable
/// through [`space_with`] or [`HttpEndpoint::with_max_response_bytes`]), regardless of Content-Length.
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
    max_response_bytes: usize,
}

impl HttpEndpoint {
    /// An endpoint for `method`, performing I/O through `transport`.
    pub fn new(method: Method, transport: Arc<dyn HttpTransport>) -> Self {
        HttpEndpoint {
            method,
            transport,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
    /// Set the host's collection limit. HEAD, redirects and error statuses drop
    /// the body unread; successful responses are collected within this limit.
    pub fn with_max_response_bytes(mut self, limit: usize) -> Self {
        self.max_response_bytes = limit;
        self
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

        let body = if self.method.sends_body() {
            inv.inline_arg("content")
                .map(<[u8]>::to_vec)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let mut headers = request_headers(inv);

        // Only an endpoint-generated condition can validate the offered body.
        let conditional = self.method.is_cacheable()
            && inv.stale().is_some_and(|stale| {
                let validator = &stale.validator;
                headers.retain(|(name, _)| {
                    !name.eq_ignore_ascii_case("If-None-Match")
                        && !name.eq_ignore_ascii_case("If-Modified-Since")
                });
                if let Some(etag) = &validator.etag {
                    headers.push(("If-None-Match".into(), etag.clone()));
                }
                if let Some(modified) = &validator.last_modified {
                    headers.push(("If-Modified-Since".into(), modified.clone()));
                }
                validator.etag.is_some() || validator.last_modified.is_some()
            });

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

            let target = current.to_string();
            let response = self
                .transport
                .send(HttpRequest {
                    method: self.method,
                    url: target.clone(),
                    headers: headers.clone(),
                    body: body.clone(),
                })
                .await
                // A transport-level failure is a network fault, transient either way: a
                // `Timeout` when the transport gave up waiting (a wait on the origin, not a
                // bound of ours), else `Unavailable` (DNS, refused, TLS, dropped).
                .map_err(|e| {
                    status::transport_error(&e, &target, format!("http transport: {e}"))
                })?;

            if !matches!(response.status, 301 | 302 | 303 | 307 | 308) {
                break response;
            }
            let Some(location) = response.header("location") else {
                break response; // a 3xx with nowhere to go is just a response
            };
            if self.method.sends_body() {
                // Never replay a request body at a redirect target — the target
                // may be a different authority than the one the caller vetted.
                return Err(Error::Endpoint(format!(
                    "HTTP {} redirect on {} not followed (methods that send a body \
                     never follow redirects); Location: {location}",
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
            if current.origin() != parsed.origin() {
                // Mutate the shared list so credentials stay stripped even if
                // a later redirect returns to the original origin.
                headers.retain(|(name, _)| {
                    !["Authorization", "Proxy-Authorization", "Cookie"]
                        .iter()
                        .any(|credential| name.eq_ignore_ascii_case(credential))
                });
            }
        };

        if response.status == 304 && conditional {
            // The body stays in core's cache; drop the transport body unread.
            let now = inv.now().expect("a stale offer has a kernel clock");
            let window = freshness_window(&response, inv);
            let mut repr = Representation::revalidated(
                now.plus_millis(window.unwrap_or(0).saturating_mul(1000)),
            );
            if response_forbids_store(&response) {
                repr = repr.with_expiry(ikigai_core::Expiry::Always);
            }
            // A 304 may update just one member of the validator pair.
            let mut validator = inv
                .stale()
                .expect("conditional stale offer")
                .validator
                .clone();
            let updated = response_validator(&response);
            if updated.etag.is_some() {
                validator.etag = updated.etag;
            }
            if updated.last_modified.is_some() {
                validator.last_modified = updated.last_modified;
            }
            return Ok(repr.validated_by(validator));
        }

        // A 304 carries no content to serve or cache. Preserve the status in the
        // representation type and return before freshness or mutation handling,
        // even when the caller supplied max_age. Drop the transport body unread.
        if response.status == 304 {
            let repr_type = if self.method == Method::Head {
                ReprType::new("text/plain")
            } else {
                content_type(&response)
            };
            return Ok(Representation::new(
                repr_type.with_param("http-status", "304"),
                Vec::new(),
            ));
        }

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
            return Ok(with_freshness(
                with_validator(repr, response_validator(&response)),
                window,
                inv,
                &thread,
            ));
        }

        // Every other method returns a representation on success and a **typed error** on a
        // non-success status — never the error-page body dressed up as the resource. The one
        // table ([`status`]); a `Retry-After` HTTP-date is read on the kernel's clock.
        if let Some(err) =
            status::response_error(&response, inv.now(), format!("HTTP {}", response.status))
        {
            return Err(err);
        }

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
        let repr_type = content_type(&response);
        let validator = response_validator(&response);
        let bytes = response.body.collect(self.max_response_bytes).await?;
        let repr = Representation::new(repr_type, bytes);
        if self.method.is_cacheable() {
            return Ok(with_freshness(
                with_validator(repr, validator),
                window,
                inv,
                &thread,
            ));
        }
        Ok(repr)
    }

    fn name(&self) -> &str {
        self.method.id()
    }

    /// The contract as the manifold states it. Only `url` is required; every
    /// other input is an optional header or directive. The declared output is
    /// what the action serves when the origin sends no `Content-Type` — the
    /// origin's own label passes through otherwise, a set no description can
    /// enumerate — except `HEAD`, whose `"true"`/`"false"` is always `text/plain`.
    fn describe(&self) -> Description {
        let summary = if self.method == Method::Head {
            "Ask whether a URL is present (`true`/`false`) with an HTTP HEAD through a host \
             transport, capability-gated by `urn:cap:net`; an unsolicited 304 is an empty, \
             uncacheable result with `http-status=304` type metadata."
        } else if self.method == Method::Propfind {
            "Send a WebDAV PROPFIND (RFC 4918) to a URL through a host transport, \
             capability-gated by `urn:cap:net`: `content` is the XML request, `Depth` goes in \
             `headers=`; never cached, never follows a redirect, and a 207 Multi-Status is \
             the result."
        } else if self.method == Method::Report {
            "Send a WebDAV REPORT (RFC 3253; CalDAV calendar-query, RFC 6578 sync-collection) \
             to a URL through a host transport, capability-gated by `urn:cap:net`: `content` \
             is the XML request, `Depth` goes in `headers=`; never cached, never follows a \
             redirect, and a 207 Multi-Status is the result."
        } else {
            "Dereference a URL as a resource through a host transport, capability-gated by \
             `urn:cap:net`; the origin's Content-Type labels the result."
        };
        let output = if self.method == Method::Head {
            "text/plain"
        } else {
            "application/octet-stream"
        };
        let header = |name: &str, summary: &str| {
            ArgSpec::new(name)
                .optional()
                .class(XSD_STRING)
                .summary(summary)
        };
        let mut description = Description::new(self.method.id())
            .title(format!("HTTP {}", self.method.as_str()))
            .summary(summary)
            .verb(self.method.verb())
            // The net ACL is parameterized (urn:cap:net:<host-rule>): the wildcard
            // offers this action to any capability holding SOME net grant; the
            // actual host/path is checked against the rules at invoke time.
            .requires("urn:cap:net:*")
            .output(output)
            .input(
                ArgSpec::new("url")
                    .class(XSD_ANY_URI)
                    .summary("the absolute URL to request"),
            )
            .input(header("accept", "value for the Accept header"))
            .input(header(
                "authorization",
                "value for the Authorization header",
            ))
            .input(header(
                "range",
                "value for the Range header, e.g. bytes=0-1023",
            ))
            .input(header(
                "if_range",
                "strong entity tag or HTTP-date for If-Range",
            ))
            .input(header(
                "headers",
                "extra request headers, one `Name: Value` per line",
            ));
        if self.method.is_cacheable() {
            description = description.input(
                ArgSpec::new("max_age")
                    .optional()
                    .class(XSD_NON_NEGATIVE_INTEGER)
                    .summary(
                        "cache this read for up to N seconds when a stale answer is acceptable \
                         (e.g. a liveness/existence check); takes precedence over the response's \
                         own freshness, except an explicit no-store",
                    ),
            );
        }
        // The failure classes each action can produce beyond the implied ones (permanent
        // always; denied, since it `requires` a scope). HEAD's existence check is lenient: an
        // answered status is `true`/`false`, so only a transport failure (transient) or a
        // redirect it cannot follow (unknown) is an error. Every other method can see the
        // whole status table.
        description = description
            .fails(FailureClass::Transient)
            .fails(FailureClass::Unknown);
        if self.method != Method::Head {
            description = description
                .fails(FailureClass::RetryAfter)
                .fails(FailureClass::OverBudget)
                .fails(FailureClass::Refused);
        }
        if self.method.sends_body() {
            description = description
                // The body is bytes of whatever type `content_type` says — a PNG is
                // a valid body. `xsd:string` is the type the WIRE carries (a piped
                // value, an MCP argument), not a claim about the value.
                .input(header("content", "the request body bytes"))
                .input(header("content_type", "value for the Content-Type header"));
        }
        description
    }
}

/// Mount all eight HTTP-method endpoints on one host transport: `urn:http:get`,
/// `urn:http:head`, `urn:http:post`, `urn:http:put`, `urn:http:patch`,
/// `urn:http:delete`, `urn:http:propfind`, `urn:http:report`, plus the six pre-0.2.0
/// names (`urn:httpGet` … `urn:httpDelete`) as deprecated aliases of the first six,
/// through 0.3.x (see [`deprecated_aliases`]).
///
/// Responses use the 8 MiB default limit; use [`space_with`] to set another limit.
///
/// The space is an [`Alias`] over the eight bindings ([`endpoints`]): the overlay
/// core provides for exactly this migration, so an old name shares its new name's
/// cache entry and golden thread, describes itself by the new id, and is absent
/// from the catalog. Hold it as an `Arc<dyn Space>`: in the minor that removes the
/// aliases, this returns the [`EndpointSpace`] again.
///
/// ```
/// use std::sync::Arc;
/// use ikigai_core::{Iri, Kernel};
/// use ikigai_http::{HttpRequest, HttpResponse, HttpTransport};
///
/// struct Offline;
/// #[async_trait::async_trait]
/// impl HttpTransport for Offline {
///     async fn send(&self, _: HttpRequest) -> Result<HttpResponse, String> {
///         Err("offline".into())
///     }
/// }
///
/// let kernel = Kernel::new(Arc::new(ikigai_http::space(Arc::new(Offline))));
/// let old = kernel.describe(&Iri::parse("urn:httpGet").unwrap()).unwrap();
/// let new = kernel.describe(&Iri::parse("urn:http:get").unwrap()).unwrap();
/// assert_eq!(old.id, "http-get");
/// assert_eq!(old.id, new.id);
/// ```
pub fn space(transport: Arc<dyn HttpTransport>) -> Alias {
    space_with(transport, DEFAULT_MAX_RESPONSE_BYTES)
}

/// Mount the same endpoints and deprecated aliases as [`space`], with the host's
/// response-body collection limit in bytes applied to every method.
///
/// The limit counts actual body bytes, regardless of `Content-Length`. A body
/// exceeding it returns [`Error::OverBudget`], never a truncated response. Zero
/// permits only empty bodies. HEAD, redirects, and error statuses drop bodies
/// unread. [`space`] keeps its 8 MiB default.
///
/// This is a per-response HTTP limit, independent of the run's byte budget
/// (`urn:cap:stream:memory:<bytes>`). These endpoints collect into an already
/// buffered [`Representation`], which core does not charge to the run's stream
/// memory pool; a smaller run budget therefore does not lower this HTTP limit.
/// Where a later operation also buffers streams under the run's budget, it must
/// satisfy that budget as well: neither setting overrides the other, and a
/// memory grant cannot raise this HTTP limit.
///
/// ```
/// # use std::sync::Arc;
/// # use ikigai_http::HttpTransport;
/// fn mount(transport: Arc<dyn HttpTransport>) -> ikigai_core::Alias {
///     ikigai_http::space_with(transport, 16 * 1024 * 1024)
/// }
/// ```
pub fn space_with(transport: Arc<dyn HttpTransport>, max_response_bytes: usize) -> Alias {
    Alias::new(
        Arc::new(deprecated_aliases()),
        Arc::new(endpoints_with_limit(transport, max_response_bytes)),
    )
}

/// The eight HTTP-method endpoints bound at their names, with no aliases: what
/// [`space`] wraps. For a host that has migrated every caller and wants the old
/// names to miss now rather than when the aliases are removed.
pub fn endpoints(transport: Arc<dyn HttpTransport>) -> EndpointSpace {
    endpoints_with_limit(transport, DEFAULT_MAX_RESPONSE_BYTES)
}

fn endpoints_with_limit(
    transport: Arc<dyn HttpTransport>,
    max_response_bytes: usize,
) -> EndpointSpace {
    let mut space = EndpointSpace::new();
    for method in Method::ALL {
        space = space.bind(
            Exact::new(method.iri()),
            HttpEndpoint::new(method, transport.clone())
                .with_max_response_bytes(max_response_bytes),
        );
    }
    space
}

/// The deprecated pre-0.2.0 names as an alias table: one exact rule per original
/// method, `urn:httpGet` → `urn:http:get` and likewise for the other five
/// (`PROPFIND` and `REPORT` never had an old name, so they get none). [`space`] already
/// applies it. A host that also wants the rules in the kernel's own hands (the
/// readout and per-rule counters at `urn:kernel:aliases`, which show whether
/// anything still calls an old name) installs the same table with
/// `Kernel::with_aliases`; the two compose, since a canonical name matches no rule.
/// Kept through 0.3.x; removed in a later minor.
pub fn deprecated_aliases() -> AliasTable {
    Method::ALL
        .into_iter()
        .filter(|method| method.has_deprecated_iri())
        .fold(AliasTable::new(), |table, method| {
            table.exact(method.deprecated_iri(), method.iri())
        })
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
        ("if_range", "If-Range"),
        ("content_type", "Content-Type"),
    ] {
        if let Ok(value) = inv.inline_str(arg) {
            headers.push((header.to_string(), value.to_string()));
        }
    }
    headers
}

/// The existence outcome for a HEAD from an HTTP status. `exists_outcome` is only reached once the
/// server has **answered** (a transport failure errors before this), so any status it sees is proof
/// the host is reachable. Existence is therefore lenient: **only 404/410 are *absent*** (`false`);
/// every other answer — including a 429 throttle, a 5xx server error, or a 408/504 timeout — means
/// the endpoint is *there*, just busy or gated, and is *present* (`true`).
///
/// This is deliberately more lenient than the [`status`] table a `GET` reads: `Exists` asks "is it there?" and a
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
/// else `Cache-Control: max-age`, `Expires`, or a capped Last-Modified heuristic.
/// `no-store` forbids storage; `no-cache` and `max-age=0, must-revalidate` force
/// a zero lifetime regardless of the caller's staleness tolerance. The
/// caller directive is what lets a liveness/existence check cache a HEAD that carries no freshness
/// of its own, instead of hitting the network every time.
fn freshness_window(response: &HttpResponse, inv: &Invocation<'_>) -> Option<u64> {
    if response_forbids_store(response) {
        return None;
    }
    if cache_directive(response, "no-cache")
        || (cache_directive(response, "must-revalidate") && response_max_age(response) == Some(0))
    {
        return Some(0);
    }
    caller_max_age(inv)
        .or_else(|| response_max_age(response))
        .or_else(|| response_date_freshness(response, inv))
        .or_else(|| {
            let validator = response_validator(response);
            (validator.etag.is_some() || validator.last_modified.is_some()).then_some(0)
        })
}

/// RFC 9111 §4.2.1–4.2.2: explicit expiration takes precedence over heuristics,
/// including when Expires is invalid or already stale. Use the injected clock
/// only when the origin supplies no usable Date; never read the host wall clock.
fn response_date_freshness(response: &HttpResponse, inv: &Invocation<'_>) -> Option<u64> {
    use std::time::{Duration, UNIX_EPOCH};

    let date = response
        .header("date")
        .and_then(|value| httpdate::parse_http_date(value).ok())
        .or_else(|| UNIX_EPOCH.checked_add(Duration::from_millis(inv.now()?.as_millis())))?;
    if let Some(expires) = response.header("expires") {
        return Some(
            httpdate::parse_http_date(expires)
                .ok()
                .and_then(|expires| expires.duration_since(date).ok())
                .map_or(0, |duration| duration.as_secs()),
        );
    }
    let modified = httpdate::parse_http_date(response.header("last-modified")?).ok()?;
    Some(
        date.duration_since(modified)
            .ok()?
            .as_secs()
            .saturating_div(10)
            .min(86_400),
    )
}

/// The caller's `max_age` directive in seconds, if provided and parseable.
fn caller_max_age(inv: &Invocation<'_>) -> Option<u64> {
    inv.inline_str("max_age")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
}

fn with_validator(repr: Representation, validator: OriginValidator) -> Representation {
    if validator.etag.is_some() || validator.last_modified.is_some() {
        repr.validated_by(validator)
    } else {
        repr
    }
}

/// HTTP validators are opaque origin values, including weak tags and date spelling.
fn response_validator(response: &HttpResponse) -> OriginValidator {
    OriginValidator {
        etag: response.header("etag").map(str::to_owned),
        last_modified: response.header("last-modified").map(str::to_owned),
    }
}

fn cache_directive(response: &HttpResponse, name: &str) -> bool {
    response.header("cache-control").is_some_and(|cc| {
        cc.split(',').any(|directive| {
            directive
                .trim()
                .split('=')
                .next()
                .is_some_and(|key| key.trim().eq_ignore_ascii_case(name))
        })
    })
}

/// Only no-store forbids retaining the response for revalidation.
fn response_forbids_store(response: &HttpResponse) -> bool {
    cache_directive(response, "no-store")
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
        let ids: Vec<&str> = Method::ALL.iter().map(|m| m.id()).collect();
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
        assert_eq!(Method::Delete.iri(), "urn:http:delete");
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

    /// A host deny survives both of core's narrowing operations (ledger #874, after
    /// core 0.1.86 made exclusions sticky, ledger #858). Through core 0.1.85,
    /// `attenuate` and `clamp` kept only the scopes BOTH sides named, so a delegate that
    /// asked for the host allow alone, or a peer that carried only it, shed the
    /// `-example.com/admin` exclusion and reached `/admin`: narrowing WIDENED. This test
    /// fails on 0.1.85 and passes on 0.1.86, which is why the core floor is 0.1.86.
    #[test]
    fn a_host_deny_survives_attenuate_and_clamp() {
        let held =
            Capability::scoped(["urn:cap:net:example.com", "urn:cap:net:-example.com/admin"]);
        assert!(!net_allows(&held, "example.com", "/admin"));

        // A delegate asks for the allow alone; the exclusion comes along regardless.
        let delegated = held.attenuate(["urn:cap:net:example.com"]);
        // A peer carries only the allow; the server resolves under ceiling.clamp(carried).
        let clamped = held.clamp(&Capability::scoped(["urn:cap:net:example.com"]));

        for narrowed in [&delegated, &clamped] {
            assert!(
                narrowed
                    .scopes()
                    .is_some_and(|s| s.contains("urn:cap:net:-example.com/admin")),
                "the exclusion was dropped: {narrowed:?}"
            );
            assert!(net_allows(narrowed, "example.com", "/api"));
            assert!(!net_allows(narrowed, "example.com", "/admin"));
            assert!(!net_allows(narrowed, "example.com", "/admin/users"));
            assert!(!net_allows_port(
                narrowed,
                "example.com",
                Some(443),
                "/admin"
            ));
        }
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
        response: std::sync::Mutex<HttpResponse>,
    }
    impl Mock {
        fn new(response: HttpResponse) -> Self {
            Mock {
                gets: AtomicU32::new(0),
                response: std::sync::Mutex::new(response),
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
            Ok(clone_buffered_response(&self.response.lock().unwrap()))
        }
    }

    fn clone_buffered_response(response: &HttpResponse) -> HttpResponse {
        HttpResponse {
            status: response.status,
            headers: response.headers.clone(),
            body: response
                .body
                .as_bytes()
                .expect("buffered fixture")
                .to_vec()
                .into(),
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
            body: b"hi".to_vec().into(),
        }
    }

    fn get(url: &str) -> Request {
        Request::new(Verb::Source, Iri::parse("urn:http:get").unwrap())
            .with_arg("url", ArgRef::Inline(url.as_bytes().to_vec()))
    }

    #[test]
    fn oversized_response_is_over_budget() {
        let mut response = resp(None);
        response.body = vec![0; 8 * 1024 * 1024 + 1].into();
        let ep = HttpEndpoint::new(Method::Get, Arc::new(Mock::new(response)));
        let cap = Capability::root();
        let req = get("https://example.com/large");
        let bindings = ikigai_core::Bindings::new();
        let inv = Invocation::detached(&req, &bindings, &cap);
        let result = futures::executor::block_on(ep.invoke(&inv));
        assert!(
            matches!(result, Err(Error::OverBudget { .. })),
            "an oversized response must be refused"
        );
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
        let req = Request::new(Verb::Source, Iri::parse("urn:http:get").unwrap())
            .with_arg("url", ArgRef::Inline(b"https://example.com/x".to_vec()));
        let bindings = ikigai_core::Bindings::new();
        let inv = Invocation::detached(&req, &bindings, &cap);
        let err = futures::executor::block_on(ep.invoke(&inv)).unwrap_err();
        // A capability denial is the typed, permanent `Denied` — never a generic
        // `Endpoint` string, and never transient (re-issuing won't change the answer).
        assert!(matches!(err, Error::Denied(_)), "got {err:?}");
        assert!(!err.is_transient());
    }

    /// A caller-supplied validator must produce an explicit, uncacheable 304
    /// result, even when either side supplies a freshness window.
    #[test]
    fn not_modified_is_explicit_and_never_cached() {
        struct ConditionalOrigin {
            status: u16,
            sends: AtomicU32,
        }
        #[async_trait]
        impl HttpTransport for ConditionalOrigin {
            async fn send(
                &self,
                request: HttpRequest,
            ) -> std::result::Result<HttpResponse, String> {
                assert!(request
                    .headers
                    .iter()
                    .any(|(name, value)| name.eq_ignore_ascii_case("if-none-match")
                        && value == "\"abc\""));
                self.sends.fetch_add(1, Ordering::SeqCst);
                Ok(HttpResponse {
                    status: self.status,
                    headers: vec![("Cache-Control".into(), "max-age=600".into())],
                    body: if self.status == 200 {
                        b"content".to_vec()
                    } else {
                        Vec::new()
                    }
                    .into(),
                })
            }
        }
        for status in [304, 200] {
            for max_age in [None, Some("600")] {
                let transport = Arc::new(ConditionalOrigin {
                    status,
                    sends: AtomicU32::new(0),
                });
                let kernel = Kernel::new(Arc::new(space(transport.clone())))
                    .with_clock(Arc::new(TestClock::at(0)));
                let mut request = get("https://example.com/conditional").with_arg(
                    "headers",
                    ArgRef::Inline(b"If-None-Match: \"abc\"".to_vec()),
                );
                if let Some(age) = max_age {
                    request = request.with_arg("max_age", ArgRef::Inline(age.as_bytes().to_vec()));
                }
                for _ in 0..2 {
                    let repr = futures::executor::block_on(
                        kernel.issue(request.clone(), &Capability::root()),
                    )
                    .unwrap();
                    if status == 304 {
                        assert_eq!(
                            repr.repr_type.params.get("http-status").map(String::as_str),
                            Some("304"),
                            "304 must be distinguishable from an empty success"
                        );
                        assert!(repr.bytes.is_empty());
                        assert_eq!(repr.expiry, ikigai_core::Expiry::Always);
                    } else {
                        assert_eq!(repr.bytes, b"content");
                        assert!(!repr.repr_type.params.contains_key("http-status"));
                    }
                }
                assert_eq!(
                    transport.sends.load(Ordering::SeqCst),
                    if status == 304 { 2 } else { 1 },
                    "304 must reach the origin again; 200 retains normal caching"
                );
            }
        }
    }

    #[test]
    fn date_freshness_over_mock_transport() {
        const DATE: &str = "Wed, 28 Oct 2026 12:00:00 GMT";
        const EXPIRES: &str = "Wed, 28 Oct 2026 14:00:00 GMT";
        const OLD: &str = "Sun, 18 Oct 2026 12:00:00 GMT";
        const HOUR: &str = "Wed, 28 Oct 2026 11:00:00 GMT";
        let now = 1_793_188_800_000;
        let cases = [
            (
                "date_beats_clock",
                vec![("Date", HOUR), ("Expires", EXPIRES)],
                None,
                Some(10800),
            ),
            (
                "invalid_date_uses_clock",
                vec![("Date", "invalid"), ("Expires", EXPIRES)],
                None,
                Some(7200),
            ),
            (
                "expires_now",
                vec![("Date", DATE), ("Expires", DATE), ("Last-Modified", OLD)],
                None,
                Some(0),
            ),
            (
                "expires",
                vec![("Date", DATE), ("Expires", EXPIRES)],
                None,
                Some(7200),
            ),
            (
                "expires_clock",
                vec![("Expires", EXPIRES)],
                None,
                Some(7200),
            ),
            (
                "past_expires",
                vec![("Date", DATE), ("Expires", OLD), ("Last-Modified", OLD)],
                None,
                Some(0),
            ),
            (
                "bad_expires",
                vec![
                    ("Date", DATE),
                    ("Expires", "invalid"),
                    ("Last-Modified", OLD),
                ],
                None,
                Some(0),
            ),
            (
                "capped_heuristic",
                vec![("Date", DATE), ("Last-Modified", OLD)],
                None,
                Some(86400),
            ),
            (
                "short_heuristic",
                vec![("Date", DATE), ("Last-Modified", HOUR)],
                None,
                Some(360),
            ),
            (
                "heuristic_clock",
                vec![("Last-Modified", HOUR)],
                None,
                Some(360),
            ),
            (
                "future_modified",
                vec![("Date", DATE), ("Last-Modified", EXPIRES)],
                None,
                Some(0),
            ),
            (
                "bad_modified",
                vec![("Last-Modified", "invalid")],
                None,
                Some(0),
            ),
            (
                "max_age",
                vec![
                    ("Date", DATE),
                    ("Expires", EXPIRES),
                    ("Cache-Control", "max-age=60"),
                ],
                None,
                Some(60),
            ),
            (
                "caller",
                vec![
                    ("Date", DATE),
                    ("Expires", EXPIRES),
                    ("Cache-Control", "max-age=60"),
                ],
                Some("30"),
                Some(30),
            ),
            (
                "no_store",
                vec![
                    ("Date", DATE),
                    ("Expires", EXPIRES),
                    ("Last-Modified", OLD),
                    ("Cache-Control", "no-store, max-age=60"),
                ],
                Some("30"),
                None,
            ),
            (
                "no_cache",
                vec![
                    ("Date", DATE),
                    ("Expires", EXPIRES),
                    ("Cache-Control", "no-cache"),
                ],
                Some("30"),
                Some(0),
            ),
            (
                "zero_max_age",
                vec![
                    ("Date", DATE),
                    ("Expires", EXPIRES),
                    ("Cache-Control", "max-age=0, must-revalidate"),
                ],
                None,
                Some(0),
            ),
            ("no_freshness", vec![], None, None),
        ];
        for (name, headers, caller, seconds) in cases {
            let mut response = resp(None);
            response
                .headers
                .extend(headers.into_iter().map(|(k, v)| (k.into(), v.into())));
            let transport = Arc::new(Mock::new(response));
            let clock = TestClock::at(now);
            let kernel =
                Kernel::new(Arc::new(space(transport.clone()))).with_clock(Arc::new(clock.clone()));
            let mut request = get("https://example.com/freshness");
            if let Some(age) = caller {
                request = request.with_arg("max_age", ArgRef::Inline(age.as_bytes().to_vec()));
            }
            let issue = || {
                futures::executor::block_on(kernel.issue(request.clone(), &Capability::root()))
                    .unwrap()
            };
            let repr = issue();
            if let Some(seconds) = seconds {
                let expected = Representation::new(ReprType::new("text/plain"), vec![])
                    .cacheable_until(Time::from_millis(now + seconds * 1000));
                assert_eq!(repr.expiry, expected.expiry, "{name}");
                if seconds > 0 {
                    clock.set(now + seconds * 1000 - 1);
                    issue();
                    assert_eq!(transport.gets(), 1, "{name}: cached before deadline");
                }
                clock.set(now + seconds * 1000 + 1);
                issue();
                assert_eq!(transport.gets(), 2, "{name}: refetched after deadline");
            } else {
                assert_eq!(repr.expiry, ikigai_core::Expiry::Always, "{name}");
                issue();
                assert_eq!(transport.gets(), 2, "{name}: must stay live");
            }
            let clockless = Kernel::new(Arc::new(space(transport.clone())));
            let repr =
                futures::executor::block_on(clockless.issue(request, &Capability::root())).unwrap();
            assert_eq!(repr.expiry, ikigai_core::Expiry::Always, "{name}: no clock");
        }
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
        let post = Request::new(Verb::Sink, Iri::parse("urn:http:post").unwrap())
            .with_arg("url", ArgRef::Inline(url.as_bytes().to_vec()))
            .with_arg("content", ArgRef::Inline(b"data".to_vec()));
        futures::executor::block_on(kernel.issue(post, &cap)).unwrap();

        // The cached GET is now invalid even though its deadline hasn't passed.
        futures::executor::block_on(kernel.issue(get(url), &cap)).unwrap();
        assert_eq!(transport.gets(), 2, "GET recomputed after the mutating cut");
    }

    // --- Deprecated names (kept through 0.3.x; removed in a later minor) ---

    fn get_at(iri: &str, url: &str) -> Request {
        Request::new(Verb::Source, Iri::parse(iri).unwrap())
            .with_arg("url", ArgRef::Inline(url.as_bytes().to_vec()))
    }

    /// `urn:httpGet` resolves exactly as `urn:http:get`: the same bytes and type,
    /// from ONE cache entry, whichever name computed it. Two entries would be the
    /// invisible failure: both answers look right, and a write through one name
    /// leaves the other stale.
    #[test]
    fn a_deprecated_name_shares_its_new_names_cache_entry() {
        for (first, second) in [
            ("urn:http:get", "urn:httpGet"),
            ("urn:httpGet", "urn:http:get"),
        ] {
            let transport = Arc::new(Mock::new(resp(Some("max-age=60"))));
            let kernel = Kernel::new(Arc::new(space(transport.clone())))
                .with_clock(Arc::new(TestClock::at(0)));
            let cap = Capability::root();
            let url = "https://example.com/x";
            let a = futures::executor::block_on(kernel.issue(get_at(first, url), &cap)).unwrap();
            let b = futures::executor::block_on(kernel.issue(get_at(second, url), &cap)).unwrap();
            assert_eq!(a.bytes, b.bytes, "{first} then {second}");
            assert_eq!(a.repr_type, b.repr_type, "{first} then {second}");
            assert_eq!(
                transport.gets(),
                1,
                "{first} then {second}: one cache entry for both names"
            );
        }
    }

    /// A write through a deprecated name cuts the thread a read through the new
    /// name hangs on, and the other way round.
    #[test]
    fn a_deprecated_name_cuts_and_is_cut_by_its_new_name() {
        for (read, write) in [
            ("urn:http:get", "urn:httpPost"),
            ("urn:httpGet", "urn:http:post"),
        ] {
            let transport = Arc::new(Mock::new(resp(Some("max-age=600"))));
            let kernel = Kernel::new(Arc::new(space(transport.clone())))
                .with_clock(Arc::new(TestClock::at(0)));
            let cap = Capability::root();
            let url = "https://example.com/x";
            futures::executor::block_on(kernel.issue(get_at(read, url), &cap)).unwrap();
            let post = Request::new(Verb::Sink, Iri::parse(write).unwrap())
                .with_arg("url", ArgRef::Inline(url.as_bytes().to_vec()))
                .with_arg("content", ArgRef::Inline(b"data".to_vec()));
            futures::executor::block_on(kernel.issue(post, &cap)).unwrap();
            futures::executor::block_on(kernel.issue(get_at(read, url), &cap)).unwrap();
            assert_eq!(
                transport.gets(),
                2,
                "{write} cut the thread {read} hangs on"
            );
        }
    }

    /// One exact rule per method, old name to new; every old name describes itself
    /// by the NEW id; the space enumerates the six new names and no old one.
    #[test]
    fn the_deprecated_names_alias_the_new_ones_and_stay_out_of_the_catalog() {
        use ikigai_core::{RuleKind, Space};
        let table = deprecated_aliases();
        let rules: Vec<(RuleKind, &str, &str)> = table
            .rules()
            .iter()
            .map(|r| (r.kind(), r.from(), r.to()))
            .collect();
        for method in Method::ALL.into_iter().filter(|m| m.has_deprecated_iri()) {
            assert!(
                rules.contains(&(RuleKind::Exact, method.deprecated_iri(), method.iri())),
                "{method:?}: {rules:?}"
            );
        }
        // Six rules: the original six methods. PROPFIND and REPORT (0.2.2) never had
        // an old name, and no rule may point at, or come from, one of them.
        assert_eq!(rules.len(), 6, "{rules:?}");
        for method in [Method::Propfind, Method::Report] {
            assert!(!method.has_deprecated_iri(), "{method:?}");
            assert!(
                rules
                    .iter()
                    .all(|(_, from, to)| *from != method.iri() && *to != method.iri()),
                "{method:?}: {rules:?}"
            );
        }

        let space = Arc::new(space(Arc::new(Mock::new(resp(None)))));
        let kernel = Kernel::new(space.clone());
        for method in Method::ALL {
            let old = kernel
                .describe(&Iri::parse(method.deprecated_iri()).unwrap())
                .unwrap_or_else(|| panic!("{} resolves", method.deprecated_iri()));
            assert_eq!(old.id, method.id(), "{method:?}: the backing id");
        }
        let mut patterns: Vec<String> = space
            .entries()
            .unwrap_or_default()
            .into_iter()
            .map(|e| e.pattern)
            .collect();
        patterns.sort_unstable();
        let mut expected: Vec<String> = Method::ALL.iter().map(|m| m.iri().to_string()).collect();
        expected.sort_unstable();
        assert_eq!(patterns, expected, "only the new names are enumerated");

        // The unaliased space misses an old name outright.
        let bare = Kernel::new(Arc::new(endpoints(Arc::new(Mock::new(resp(None))))));
        assert!(bare.describe(&Iri::parse("urn:httpGet").unwrap()).is_none());
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
        let req = Request::new(Verb::Source, Iri::parse("urn:http:get").unwrap())
            .with_arg("url", ArgRef::Inline(b"https://example.com/x".to_vec()))
            .with_arg("accept", ArgRef::Inline(b"application/json".to_vec()))
            .with_arg("range", ArgRef::Inline(b"bytes=0-1023".to_vec()))
            .with_arg("if_range", ArgRef::Inline(b"\"v1\"".to_vec()))
            .with_arg("headers", ArgRef::Inline(b"X-Foo: bar\nX-Empty:".to_vec()));
        futures::executor::block_on(kernel.issue(req, &cap)).unwrap();

        let sent = transport.0.lock().unwrap().clone();
        assert!(sent.contains(&("Accept".to_string(), "application/json".to_string())));
        assert!(sent.contains(&("Range".to_string(), "bytes=0-1023".to_string())));
        assert!(sent.contains(&("If-Range".to_string(), "\"v1\"".to_string())));
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
                body: b"body".to_vec().into(),
            })
        }
    }

    fn get_result(status: u16) -> Result<Representation> {
        let kernel = Kernel::new(Arc::new(space(Status::new(status, None))));
        futures::executor::block_on(kernel.issue(get("https://example.com/x"), &Capability::root()))
    }

    fn head_body(status: u16) -> Result<String> {
        let kernel = Kernel::new(Arc::new(space(Status::new(status, None))));
        let req = Request::new(Verb::Exists, Iri::parse("urn:http:head").unwrap())
            .with_arg("url", ArgRef::Inline(b"https://example.com/x".to_vec()));
        futures::executor::block_on(kernel.issue(req, &Capability::root()))
            .map(|r| String::from_utf8(r.bytes).unwrap())
    }

    /// The endpoint answers through the one table ([`status`]), whose own tests cover every
    /// row; this pins that a GET reaches it, and the rows 0.3.0 changed.
    #[test]
    fn get_maps_status_onto_the_typed_error_taxonomy() {
        assert!(get_result(200).is_ok(), "2xx is a representation");
        assert!(matches!(get_result(404).unwrap_err(), Error::NotFound(_)));
        assert!(matches!(get_result(410).unwrap_err(), Error::NotFound(_)));
        // 0.3.0: an origin's 401/403 is `Refused` (was `Denied`).
        for status in [401, 403] {
            let err = get_result(status).unwrap_err();
            assert!(matches!(err, Error::Refused(_)), "{status}: {err:?}");
            assert_eq!(err.class(), FailureClass::Refused);
            assert_eq!(err.to_string(), format!("refused: HTTP {status}"));
        }
        assert!(matches!(get_result(408).unwrap_err(), Error::Timeout(_)));
        assert!(matches!(get_result(504).unwrap_err(), Error::Timeout(_)));
        // 502 and a 503 without Retry-After stay transient.
        for status in [502, 503] {
            let err = get_result(status).unwrap_err();
            assert!(
                matches!(err, Error::Unavailable(_)) && err.is_transient(),
                "{status}"
            );
        }
        // 0.3.0: a 500 (and any unnamed 5xx) is `Endpoint`, unknown, not transient (was
        // `Unavailable`).
        for status in [500, 505] {
            let err = get_result(status).unwrap_err();
            assert!(matches!(err, Error::Endpoint(_)), "{status}: {err:?}");
            assert!(!err.is_transient());
            assert_eq!(err.class(), FailureClass::Unknown);
        }
        // 0.3.0: a 429 is `RetryAfter` (was `Unavailable`), and NOT transient: an overlay
        // built before the variant existed treats it as permanent.
        let e429 = get_result(429).unwrap_err();
        assert!(
            matches!(e429, Error::RetryAfter { delay: None, .. }),
            "{e429:?}"
        );
        assert!(!e429.is_transient());
        // 0.3.0: 409/412 → Conflict, 413 → OverBudget, 501 → Unsupported (were Endpoint).
        assert!(matches!(get_result(409).unwrap_err(), Error::Conflict(_)));
        assert!(matches!(get_result(412).unwrap_err(), Error::Conflict(_)));
        assert!(matches!(
            get_result(413).unwrap_err(),
            Error::OverBudget { .. }
        ));
        assert!(matches!(
            get_result(501).unwrap_err(),
            Error::Unsupported { verb: None, .. }
        ));
        // A permanent client error we don't type specifically → Endpoint.
        let e422 = get_result(422).unwrap_err();
        assert!(matches!(e422, Error::Endpoint(_)) && !e422.is_transient());
    }

    /// A transport answering with a status and a `Retry-After` value.
    struct RetryAfterOrigin {
        status: u16,
        retry_after: &'static str,
    }
    #[async_trait]
    impl HttpTransport for RetryAfterOrigin {
        async fn send(&self, _req: HttpRequest) -> std::result::Result<HttpResponse, String> {
            Ok(HttpResponse {
                status: self.status,
                headers: vec![("Retry-After".to_string(), self.retry_after.to_string())],
                body: Vec::new().into(),
            })
        }
    }

    /// The endpoint reads `Retry-After` in both forms, the HTTP-date on the KERNEL's
    /// injected clock (not the wall clock), for a 429 and a 503 alike.
    #[test]
    fn a_get_reads_retry_after_in_both_forms_on_the_kernel_clock() {
        // 2015-10-21T07:28:00Z, and a kernel clock 45 s before it.
        let date = "Wed, 21 Oct 2015 07:28:00 GMT";
        let clock = TestClock::at(1_445_412_480_000 - 45_000);
        for (status, retry_after, want) in [
            (429, "12", Some(12_000)),
            (429, date, Some(45_000)),
            (503, "12", Some(12_000)),
            (503, date, Some(45_000)),
            (429, "whenever", None),
        ] {
            let origin = Arc::new(RetryAfterOrigin {
                status,
                retry_after,
            });
            let kernel = Kernel::new(Arc::new(space(origin))).with_clock(Arc::new(clock.clone()));
            let err = futures::executor::block_on(
                kernel.issue(get("https://example.com/x"), &Capability::root()),
            )
            .unwrap_err();
            assert!(
                matches!(err, Error::RetryAfter { .. }),
                "{status} {retry_after}: {err:?}"
            );
            assert_eq!(err.retry_after_millis(), want, "{status} {retry_after}");
        }
        // A 503 whose header does not parse is the ordinary transient Unavailable.
        let origin = Arc::new(RetryAfterOrigin {
            status: 503,
            retry_after: "whenever",
        });
        let kernel = Kernel::new(Arc::new(space(origin))).with_clock(Arc::new(clock));
        let err = futures::executor::block_on(
            kernel.issue(get("https://example.com/x"), &Capability::root()),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unavailable(_)), "{err:?}");
    }

    /// Every action declares what it can fail with. HEAD sees no status as an error, so
    /// it declares only the transport's transient failure and the unknown redirect
    /// refusals; every other method can see the whole table.
    #[test]
    fn each_action_declares_its_failure_classes() {
        let all = [
            FailureClass::Transient,
            FailureClass::RetryAfter,
            FailureClass::OverBudget,
            FailureClass::Refused,
            FailureClass::Unknown,
        ];
        for method in Method::ALL {
            let ep = HttpEndpoint::new(method, Arc::new(Mock::new(resp(None))));
            let description = ep.describe();
            let specs = description.action_specs();
            assert_eq!(specs.len(), 1, "{method:?}");
            let spec = &specs[0];
            let expect: &[FailureClass] = if method == Method::Head {
                &[FailureClass::Transient, FailureClass::Unknown]
            } else {
                &all
            };
            for class in all {
                assert_eq!(
                    spec.admits_failure(class),
                    Some(expect.contains(&class)),
                    "{method:?} {class:?}"
                );
            }
            // Implied: permanent always, denied because the action requires a net scope.
            assert_eq!(spec.admits_failure(FailureClass::Permanent), Some(true));
            assert_eq!(spec.admits_failure(FailureClass::Denied), Some(true));
        }
    }

    /// A transport that gave up waiting is `Timeout` (a wait on the origin), any other
    /// transport failure `Unavailable`; both transient.
    #[test]
    fn a_transport_timeout_is_a_timeout() {
        struct Slow;
        #[async_trait]
        impl HttpTransport for Slow {
            async fn send(&self, _r: HttpRequest) -> std::result::Result<HttpResponse, String> {
                Err("error sending request: operation timed out".into())
            }
        }
        let kernel = Kernel::new(Arc::new(space(Arc::new(Slow))));
        let err = futures::executor::block_on(
            kernel.issue(get("https://example.com/x"), &Capability::root()),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::Timeout(_)) && err.is_transient(),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            "timeout: http transport: error sending request: operation timed out"
        );
        // A URL that says "timeout" does not make a refusal one.
        struct Refused;
        #[async_trait]
        impl HttpTransport for Refused {
            async fn send(&self, r: HttpRequest) -> std::result::Result<HttpResponse, String> {
                Err(format!("connection refused: {}", r.url))
            }
        }
        let kernel = Kernel::new(Arc::new(space(Arc::new(Refused))));
        let err = futures::executor::block_on(
            kernel.issue(get("https://timeout.example/x"), &Capability::root()),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unavailable(_)), "{err:?}");
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
        Request::new(Verb::Source, Iri::parse("urn:http:get").unwrap())
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
        headers: std::sync::Mutex<Vec<Vec<(String, String)>>>,
    }
    impl Seq {
        fn new(responses: Vec<HttpResponse>) -> Arc<Self> {
            Arc::new(Seq {
                responses: std::sync::Mutex::new(responses),
                urls: std::sync::Mutex::new(Vec::new()),
                headers: std::sync::Mutex::new(Vec::new()),
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
            self.headers.lock().unwrap().push(request.headers.clone());
            let mut scripted = self.responses.lock().unwrap();
            Ok(if scripted.len() > 1 {
                scripted.remove(0)
            } else {
                clone_buffered_response(&scripted[0])
            })
        }
    }

    #[test]
    #[ignore = "blocked: core 0.2.6 declines entries whose deadline is already reached"]
    fn validator_only_response_revalidates_and_serves_stored_body() {
        let mut initial = ok_body("stored body");
        initial.headers.push(("ETag".into(), "W/\"v1\"".into()));
        let mut unchanged = ok_body("must not be served");
        unchanged.status = 304;
        unchanged
            .headers
            .push(("Cache-Control".into(), "max-age=60".into()));
        let transport = Seq::new(vec![initial, unchanged]);
        let clock = TestClock::at(1000);
        let kernel =
            Kernel::new(Arc::new(space(transport.clone()))).with_clock(Arc::new(clock.clone()));
        let issue = || {
            futures::executor::block_on(
                kernel.issue(get("https://example.com/revalidate"), &Capability::root()),
            )
            .unwrap()
        };
        assert_eq!(issue().bytes, b"stored body");
        clock.set(1001);
        assert_eq!(issue().bytes, b"stored body");
        assert_eq!(
            transport.urls().len(),
            2,
            "one transport call for revalidation"
        );
        assert!(transport.headers.lock().unwrap()[1]
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("If-None-Match") && v == "W/\"v1\""));
        clock.set(2000);
        assert_eq!(issue().bytes, b"stored body");
        assert_eq!(transport.urls().len(), 2, "304's freshness is used");
    }

    struct UnreadBody;
    impl futures_io::AsyncRead for UnreadBody {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut [u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            panic!("304 body must never be read")
        }
    }

    fn response_with(status: u16, headers: &[(&str, &str)], body: &str) -> HttpResponse {
        let mut response = ok_body(body);
        response.status = status;
        response
            .headers
            .extend(headers.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        response
    }

    #[test]
    fn expired_get_and_head_revalidate_with_each_origin_validator_and_replace_on_200() {
        const MODIFIED: &str = "Wed, 28 Oct 2026 12:00:00 GMT";
        for method in [Method::Get, Method::Head] {
            for validators in [
                vec![("ETag", "W/\"v1\"")],
                vec![("Last-Modified", MODIFIED)],
                vec![("ETag", "W/\"v1\""), ("Last-Modified", MODIFIED)],
            ] {
                let mut headers = validators.clone();
                headers.push(("Cache-Control", "max-age=1"));
                let initial = response_with(200, &headers, "old body");
                let mut unchanged = response_with(304, &[("Cache-Control", "max-age=2")], "");
                unchanged.body = HttpBody::from_reader(UnreadBody);
                let replacement = response_with(
                    200,
                    &[("ETag", "\"v2\""), ("Cache-Control", "max-age=3")],
                    "new body",
                );
                let transport = Seq::new(vec![initial, unchanged, replacement]);
                let clock = TestClock::at(1000);
                let kernel = Kernel::new(Arc::new(space(transport.clone())))
                    .with_clock(Arc::new(clock.clone()));
                let request = Request::new(method.verb(), Iri::parse(method.iri()).unwrap())
                    .with_arg(
                        "url",
                        ArgRef::Inline(b"https://example.com/revalidate".to_vec()),
                    );
                let issue = || {
                    futures::executor::block_on(kernel.issue(request.clone(), &Capability::root()))
                        .unwrap()
                };
                let old = issue();
                assert_eq!(
                    old.origin_validator().unwrap().etag.as_deref(),
                    validators
                        .iter()
                        .find(|(k, _)| *k == "ETag")
                        .map(|(_, v)| *v)
                );
                clock.set(2001);
                let refreshed = issue();
                assert_eq!(refreshed.bytes, old.bytes);
                assert_eq!(refreshed.repr_type, old.repr_type);
                assert_eq!(
                    refreshed.expiry,
                    ikigai_core::Expiry::At(Time::from_millis(4001))
                );
                assert_eq!(refreshed.origin_validator(), old.origin_validator());
                let sent = transport.headers.lock().unwrap()[1].clone();
                for (name, value) in &validators {
                    let condition = if *name == "ETag" {
                        "If-None-Match"
                    } else {
                        "If-Modified-Since"
                    };
                    assert!(sent
                        .iter()
                        .any(|(k, v)| k.eq_ignore_ascii_case(condition) && v == value));
                }
                assert_eq!(
                    sent.iter().filter(|(k, _)| k.starts_with("If-")).count(),
                    validators.len()
                );
                clock.set(3000);
                issue();
                assert_eq!(transport.urls().len(), 2);
                clock.set(4002);
                let new = issue();
                assert_eq!(
                    new.bytes,
                    if method == Method::Head {
                        b"true".as_slice()
                    } else {
                        b"new body".as_slice()
                    }
                );
                assert_eq!(
                    new.origin_validator().unwrap().etag.as_deref(),
                    Some("\"v2\"")
                );
                assert_eq!(new.origin_validator().unwrap().last_modified, None);
                issue();
                assert_eq!(transport.urls().len(), 3, "replacement cached");
            }
        }
    }

    #[test]
    fn revalidation_uses_304_freshness_and_merges_updated_validators() {
        const DATE: &str = "Wed, 28 Oct 2026 12:00:00 GMT";
        const OLD: &str = "Wed, 28 Oct 2026 11:00:00 GMT";
        const LATER: &str = "Wed, 28 Oct 2026 14:00:00 GMT";
        for (headers, seconds) in [
            (vec![("Cache-Control", "max-age=60")], Some(60)),
            (vec![("Date", DATE), ("Expires", LATER)], Some(7200)),
            (vec![("Date", DATE), ("Last-Modified", OLD)], Some(360)),
            (vec![("Date", DATE), ("Expires", "invalid")], Some(0)),
            (vec![("Date", DATE), ("Expires", OLD)], Some(0)),
            (vec![("Cache-Control", "no-cache, max-age=60")], Some(0)),
            (vec![("Cache-Control", "no-store, max-age=60")], None),
            (vec![], Some(0)),
        ] {
            let initial = response_with(
                200,
                &[("Cache-Control", "max-age=1"), ("ETag", "\"v1\"")],
                "stored",
            );
            let mut unchanged = response_with(304, &headers, "not content");
            unchanged.headers.push(("ETag".into(), "\"v2\"".into()));
            let transport = Seq::new(vec![initial, unchanged]);
            let clock = TestClock::at(1000);
            let kernel =
                Kernel::new(Arc::new(space(transport.clone()))).with_clock(Arc::new(clock.clone()));
            let issue = || {
                futures::executor::block_on(
                    kernel.issue(get("https://example.com/dates"), &Capability::root()),
                )
                .unwrap()
            };
            issue();
            clock.set(2001);
            let repr = issue();
            assert_eq!(repr.bytes, b"stored");
            assert_eq!(
                repr.expiry,
                seconds.map_or(ikigai_core::Expiry::Always, |seconds| {
                    ikigai_core::Expiry::At(Time::from_millis(2001 + seconds * 1000))
                })
            );
            assert_eq!(
                repr.origin_validator().unwrap().etag.as_deref(),
                Some("\"v2\"")
            );
        }
    }

    #[test]
    #[ignore = "blocked: core 0.2.6 declines entries whose deadline is already reached"]
    fn zero_lifetime_policies_revalidate_on_every_read_even_at_the_same_time() {
        for policy in ["no-cache, max-age=60", "max-age=0, must-revalidate"] {
            let initial = response_with(
                200,
                &[("ETag", "\"v1\""), ("Cache-Control", policy)],
                "stored",
            );
            let unchanged = response_with(304, &[("Cache-Control", policy)], "not content");
            let transport = Seq::new(vec![initial, unchanged]);
            let kernel = Kernel::new(Arc::new(space(transport.clone())))
                .with_clock(Arc::new(TestClock::at(1000)));
            let request = get("https://example.com/always")
                .with_arg("max_age", ArgRef::Inline(b"3600".to_vec()));
            for _ in 0..3 {
                let repr =
                    futures::executor::block_on(kernel.issue(request.clone(), &Capability::root()))
                        .unwrap();
                assert_eq!(repr.bytes, b"stored");
            }
            let sent = transport.headers.lock().unwrap();
            assert_eq!(sent.len(), 3);
            assert!(sent[1..].iter().all(|headers| headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("If-None-Match") && v == "\"v1\"")));
        }
    }

    #[test]
    fn zero_lifetime_directives_override_caller_freshness() {
        for policy in ["no-cache, max-age=60", "max-age=0, must-revalidate"] {
            let response = response_with(
                200,
                &[("ETag", "\"v1\""), ("Cache-Control", policy)],
                "content",
            );
            let kernel = Kernel::new(Arc::new(space(Seq::new(vec![response]))))
                .with_clock(Arc::new(TestClock::at(1000)));
            let repr =
                futures::executor::block_on(kernel.issue(max_age_get(), &Capability::root()))
                    .unwrap();
            assert_eq!(
                repr.expiry,
                ikigai_core::Expiry::At(Time::from_millis(1000))
            );
            assert_eq!(
                repr.origin_validator().unwrap().etag.as_deref(),
                Some("\"v1\"")
            );
        }
    }

    #[test]
    fn unsolicited_304_after_expiration_remains_a_typed_result() {
        let initial = response_with(200, &[("Cache-Control", "max-age=1")], "content");
        let unchanged = response_with(304, &[("Cache-Control", "max-age=60")], "not content");
        let transport = Seq::new(vec![initial, unchanged]);
        let clock = TestClock::at(1000);
        let kernel =
            Kernel::new(Arc::new(space(transport.clone()))).with_clock(Arc::new(clock.clone()));
        futures::executor::block_on(
            kernel.issue(get("https://example.com/status"), &Capability::root()),
        )
        .unwrap();
        clock.set(2001);
        let repr = futures::executor::block_on(
            kernel.issue(get("https://example.com/status"), &Capability::root()),
        )
        .unwrap();
        assert!(repr.bytes.is_empty());
        assert_eq!(repr.expiry, ikigai_core::Expiry::Always);
        assert_eq!(
            repr.repr_type.params.get("http-status").map(String::as_str),
            Some("304")
        );
        assert!(!transport.headers.lock().unwrap()[1]
            .iter()
            .any(|(k, _)| k.starts_with("If-")));
    }

    #[test]
    fn no_store_with_validators_never_makes_a_conditional_request() {
        let response = response_with(
            200,
            &[
                ("ETag", "\"v1\""),
                ("Cache-Control", "no-store, max-age=60"),
            ],
            "content",
        );
        let transport = Seq::new(vec![response]);
        let kernel = Kernel::new(Arc::new(space(transport.clone())))
            .with_clock(Arc::new(TestClock::at(1000)));
        for _ in 0..3 {
            futures::executor::block_on(kernel.issue(max_age_get(), &Capability::root())).unwrap();
        }
        let sent = transport.headers.lock().unwrap();
        assert_eq!(sent.len(), 3);
        assert!(sent.iter().all(|headers| !headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("If-None-Match"))));
    }

    fn redirect_to(status: u16, location: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: vec![("location".to_string(), location.to_string())],
            body: Vec::new().into(),
        }
    }

    fn ok_body(body: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: body.as_bytes().to_vec().into(),
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
    fn cross_origin_redirect_drops_credentials() {
        let transport = Seq::new(vec![redirect_to(302, "https://b.example/"), ok_body("ok")]);
        let kernel = Kernel::new(Arc::new(space(transport.clone())));
        let cap = Capability::root().attenuate([
            "urn:cap:net:a.example".to_string(),
            "urn:cap:net:b.example".to_string(),
        ]);
        let request = get("https://a.example/")
            .with_arg("authorization", ArgRef::Inline(b"Bearer secret".to_vec()))
            .with_arg(
                "headers",
                ArgRef::Inline(b"Cookie: session=secret".to_vec()),
            );
        futures::executor::block_on(kernel.issue(request, &cap)).unwrap();
        let headers = transport.headers.lock().unwrap();
        assert_eq!(headers[0].len(), 2);
        assert!(
            headers[1].is_empty(),
            "credentials leaked: {:?}",
            headers[1]
        );
    }

    #[test]
    fn redirect_credentials_follow_origin_boundaries() {
        let cases: &[(&[&str], &[bool])] = &[
            (
                &["https://b.example/", "https://a.example/back"],
                &[true, false, false],
            ),
            (&["http://a.example/"], &[true, false]),
            (&["https://a.example:8443/"], &[true, false]),
            (
                &["/relative", "https://A.EXAMPLE:443/final"],
                &[true, true, true],
            ),
        ];
        for method in [Method::Get, Method::Head] {
            for (targets, credentials_expected) in cases {
                let mut responses: Vec<_> =
                    targets.iter().map(|url| redirect_to(302, url)).collect();
                responses.push(ok_body("ok"));
                let transport = Seq::new(responses);
                let kernel = Kernel::new(Arc::new(space(transport.clone())));
                let cap = Capability::root().attenuate([
                    "urn:cap:net:a.example".to_string(),
                    "urn:cap:net:b.example".to_string(),
                ]);
                let request = Request::new(method.verb(), Iri::parse(method.iri()).unwrap())
                    .with_arg("url", ArgRef::Inline(b"https://a.example/".to_vec()))
                    .with_arg("authorization", ArgRef::Inline(b"Bearer convenience".to_vec()))
                    .with_arg("headers", ArgRef::Inline(
                        b"aUtHoRiZaTiOn: Bearer custom\nAUTHORIZATION: duplicate\npRoXy-AuThOrIzAtIoN: proxy\ncOoKiE: session=secret\nCookie: duplicate\nAccept: text/plain\nRange: bytes=0-9".to_vec()
                    ));
                futures::executor::block_on(kernel.issue(request, &cap)).unwrap();
                let headers = transport.headers.lock().unwrap();
                assert_eq!(headers.len(), credentials_expected.len());
                let original = &headers[0];
                let public: Vec<_> = original
                    .iter()
                    .filter(|(name, _)| name == "Accept" || name == "Range")
                    .cloned()
                    .collect();
                assert_eq!(public.len(), 2);
                for (hop, expected) in headers.iter().zip(*credentials_expected) {
                    assert_eq!(
                        hop,
                        if *expected { original } else { &public },
                        "{method:?}: {targets:?}"
                    );
                }
            }
        }
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
        let req = Request::new(Verb::Source, Iri::parse("urn:http:get").unwrap()).with_arg(
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
        let req = Request::new(Verb::Sink, Iri::parse("urn:http:post").unwrap())
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

    // --- WebDAV: PROPFIND and REPORT (ledger #1875) -------------------------

    /// A transport that records every request it receives and answers each with
    /// the same response.
    struct Record {
        requests: std::sync::Mutex<Vec<HttpRequest>>,
        response: std::sync::Mutex<HttpResponse>,
    }
    impl Record {
        fn new(response: HttpResponse) -> Arc<Self> {
            Arc::new(Record {
                requests: std::sync::Mutex::new(Vec::new()),
                response: std::sync::Mutex::new(response),
            })
        }
        fn requests(&self) -> Vec<HttpRequest> {
            self.requests.lock().unwrap().clone()
        }
    }
    #[async_trait]
    impl HttpTransport for Record {
        async fn send(&self, request: HttpRequest) -> std::result::Result<HttpResponse, String> {
            self.requests.lock().unwrap().push(request);
            Ok(clone_buffered_response(&self.response.lock().unwrap()))
        }
    }

    fn multistatus() -> HttpResponse {
        HttpResponse {
            status: 207,
            headers: vec![(
                "Content-Type".to_string(),
                "application/xml; charset=utf-8".to_string(),
            )],
            body: b"<d:multistatus xmlns:d=\"DAV:\"/>".to_vec().into(),
        }
    }

    const PROPFIND_BODY: &str =
        "<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:displayname/></d:prop></d:propfind>";

    fn dav(method: Method, url: &str) -> Request {
        Request::new(Verb::Sink, Iri::parse(method.iri()).unwrap())
            .with_arg("url", ArgRef::Inline(url.as_bytes().to_vec()))
            .with_arg("content", ArgRef::Inline(PROPFIND_BODY.as_bytes().to_vec()))
            .with_arg(
                "content_type",
                ArgRef::Inline(b"application/xml; charset=utf-8".to_vec()),
            )
            .with_arg("headers", ArgRef::Inline(b"Depth: 1".to_vec()))
    }

    #[test]
    fn propfind_and_report_are_safe_body_carrying_sinks() {
        for (method, token, iri, id) in [
            (
                Method::Propfind,
                "PROPFIND",
                "urn:http:propfind",
                "http-propfind",
            ),
            (Method::Report, "REPORT", "urn:http:report", "http-report"),
        ] {
            assert_eq!(method.as_str(), token);
            assert_eq!(method.iri(), iri);
            assert_eq!(method.id(), id);
            assert_eq!(
                method.verb(),
                Verb::Sink,
                "{token}: the verb that takes content="
            );
            assert!(!method.is_cacheable(), "{token}: never cached");
            assert!(
                !method.is_mutating(),
                "{token}: a safe method cuts no thread"
            );
            assert!(method.sends_body(), "{token}: content= is the body");
            assert!(Method::ALL.contains(&method), "{token}: bound by space()");
        }
    }

    /// The method token, the XML body, `Content-Type` and the `Depth` header from
    /// `headers=` all reach the transport, and a 207 Multi-Status is the result,
    /// passed through with the origin's bare media type.
    #[test]
    fn propfind_and_report_send_method_body_and_depth_and_return_the_multistatus() {
        for method in [Method::Propfind, Method::Report] {
            let transport = Record::new(multistatus());
            let kernel = Kernel::new(Arc::new(space(transport.clone())));
            let out = futures::executor::block_on(kernel.issue(
                dav(method, "https://dav.example.com/cal/"),
                &Capability::root(),
            ))
            .unwrap_or_else(|e| panic!("{method:?}: {e}"));
            assert_eq!(
                out.bytes, b"<d:multistatus xmlns:d=\"DAV:\"/>",
                "{method:?}"
            );
            assert_eq!(out.repr_type.media_type, "application/xml", "{method:?}");

            let sent = transport.requests();
            assert_eq!(sent.len(), 1, "{method:?}");
            let sent = &sent[0];
            assert_eq!(sent.method, method);
            assert_eq!(sent.method.as_str(), method.as_str());
            assert_eq!(sent.url, "https://dav.example.com/cal/");
            assert_eq!(sent.body, PROPFIND_BODY.as_bytes(), "{method:?}: the body");
            assert!(
                sent.headers
                    .contains(&("Depth".to_string(), "1".to_string())),
                "{method:?}: {:?}",
                sent.headers
            );
            assert!(
                sent.headers.contains(&(
                    "Content-Type".to_string(),
                    "application/xml; charset=utf-8".to_string()
                )),
                "{method:?}: {:?}",
                sent.headers
            );
        }
    }

    /// Never cached: the same PROPFIND twice reaches the wire twice, even on a
    /// clocked kernel with a caller `max_age` and an origin `max-age`.
    #[test]
    fn propfind_and_report_are_never_cached() {
        for method in [Method::Propfind, Method::Report] {
            let mut response = multistatus();
            response
                .headers
                .push(("Cache-Control".to_string(), "max-age=600".to_string()));
            let transport = Record::new(response);
            let kernel = Kernel::new(Arc::new(space(transport.clone())))
                .with_clock(Arc::new(TestClock::at(0)));
            for _ in 0..2 {
                let req = dav(method, "https://dav.example.com/cal/")
                    .with_arg("max_age", ArgRef::Inline(b"600".to_vec()));
                futures::executor::block_on(kernel.issue(req, &Capability::root())).unwrap();
            }
            assert_eq!(transport.requests().len(), 2, "{method:?}");
        }
    }

    /// A safe method is not a write: a PROPFIND or REPORT to a URL leaves a cached
    /// GET of that URL cached, where a POST would have cut it.
    #[test]
    fn propfind_and_report_do_not_cut_the_url_thread() {
        for method in [Method::Propfind, Method::Report] {
            let transport = Arc::new(Mock::new(resp(Some("max-age=600"))));
            let kernel = Kernel::new(Arc::new(space(transport.clone())))
                .with_clock(Arc::new(TestClock::at(0)));
            let cap = Capability::root();
            let url = "https://example.com/x";
            futures::executor::block_on(kernel.issue(get(url), &cap)).unwrap();
            futures::executor::block_on(kernel.issue(dav(method, url), &cap)).unwrap();
            futures::executor::block_on(kernel.issue(get(url), &cap)).unwrap();
            assert_eq!(
                transport.gets(),
                1,
                "{method:?}: the cached GET survived the safe method"
            );
        }
    }

    /// Never follows a redirect, even to a granted host and even under root: the
    /// body is not replayed, and the error names the target.
    #[test]
    fn propfind_and_report_never_follow_redirects() {
        for method in [Method::Propfind, Method::Report] {
            for status in [301, 302, 303, 307, 308] {
                let transport = Seq::new(vec![
                    redirect_to(status, "https://a.example.com/elsewhere/"),
                    multistatus(),
                ]);
                let kernel = Kernel::new(Arc::new(space(transport.clone())));
                let err = futures::executor::block_on(kernel.issue(
                    dav(method, "https://a.example.com/cal/"),
                    &Capability::root(),
                ))
                .unwrap_err();
                assert!(
                    matches!(err, Error::Endpoint(_)),
                    "{method:?} {status}: {err:?}"
                );
                let text = err.to_string();
                assert!(
                    text.contains("never follow redirects")
                        && text.contains(method.as_str())
                        && text.contains("https://a.example.com/elsewhere/"),
                    "{method:?} {status}: {text}"
                );
                assert_eq!(
                    transport.urls().len(),
                    1,
                    "{method:?} {status}: one request"
                );
            }
        }
    }

    /// The same capability ACL as every other method: an ungranted host, or a
    /// denied path on a granted host, is a typed `Denied` before any I/O; a granted
    /// one is sent.
    #[test]
    fn propfind_and_report_are_gated_by_the_net_acl() {
        let cap = Capability::scoped([
            "urn:cap:net:dav.example.com",
            "urn:cap:net:-dav.example.com/private",
        ]);
        for method in [Method::Propfind, Method::Report] {
            for url in [
                "https://other.example.com/cal/",
                "https://dav.example.com/private/cal/",
            ] {
                let transport = Record::new(multistatus());
                let ep = HttpEndpoint::new(method, transport.clone());
                let req = dav(method, url);
                let bindings = ikigai_core::Bindings::new();
                let inv = Invocation::detached(&req, &bindings, &cap);
                let err = futures::executor::block_on(ep.invoke(&inv)).unwrap_err();
                assert!(matches!(err, Error::Denied(_)), "{method:?} {url}: {err:?}");
                assert!(!err.is_transient(), "{method:?} {url}");
                assert!(err.to_string().contains(method.as_str()), "{err}");
                assert!(transport.requests().is_empty(), "{method:?} {url}: no I/O");
            }
            let transport = Record::new(multistatus());
            let ep = HttpEndpoint::new(method, transport.clone());
            let req = dav(method, "https://dav.example.com/cal/");
            let bindings = ikigai_core::Bindings::new();
            let inv = Invocation::detached(&req, &bindings, &cap);
            futures::executor::block_on(ep.invoke(&inv)).unwrap();
            assert_eq!(transport.requests().len(), 1, "{method:?}: granted");
        }
    }

    /// An error status maps onto the same typed taxonomy as every other method.
    #[test]
    fn propfind_maps_status_onto_the_typed_error_taxonomy() {
        let result = |status: u16| {
            let kernel = Kernel::new(Arc::new(space(Status::new(status, None))));
            futures::executor::block_on(kernel.issue(
                dav(Method::Propfind, "https://dav.example.com/cal/"),
                &Capability::root(),
            ))
        };
        assert!(result(207).is_ok());
        assert!(matches!(result(404).unwrap_err(), Error::NotFound(_)));
        assert!(matches!(result(401).unwrap_err(), Error::Refused(_)));
        assert!(matches!(result(503).unwrap_err(), Error::Unavailable(_)));
        assert!(matches!(result(429).unwrap_err(), Error::RetryAfter { .. }));
        assert!(matches!(result(500).unwrap_err(), Error::Endpoint(_)));
        assert!(matches!(result(422).unwrap_err(), Error::Endpoint(_)));
    }
}
