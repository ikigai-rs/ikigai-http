# ikigai-http

An outbound **HTTP-client** module for the [ikigai](https://crates.io/crates/ikigai-core)
resolution kernel: dereference the web as ROC resources, with the kernel's caching
and capabilities applied to HTTP.

A standalone module crate (like [`ikigai-fs`](https://crates.io/crates/ikigai-fs)):
a host links it in and mounts [`space`], rather than the kernel shipping HTTP itself.
It depends only on the published `ikigai-core`.

## One endpoint per method; the verb mirrors HTTP idempotency

Each method is its own resource, resolved with the verb whose cacheability matches
the method — so "is this cached?" falls straight out of the verb:

| resolve  | IRI                 | id              | HTTP     | cacheable |
|----------|---------------------|-----------------|----------|-----------|
| `source` | `urn:http:get`      | `http-get`      | GET      | yes       |
| `exists` | `urn:http:head`     | `http-head`     | HEAD     | yes       |
| `sink`   | `urn:http:post`     | `http-post`     | POST     | no        |
| `sink`   | `urn:http:put`      | `http-put`      | PUT      | no        |
| `sink`   | `urn:http:patch`    | `http-patch`    | PATCH    | no        |
| `delete` | `urn:http:delete`   | `http-delete`   | DELETE   | no        |
| `sink`   | `urn:http:propfind` | `http-propfind` | PROPFIND | no        |
| `sink`   | `urn:http:report`   | `http-report`   | REPORT   | no        |

The URL is an argument (`url=`, an `xsd:anyURI`, the only required input), so one
binding serves every URL and the cache keys on the URL. Optional args set request
headers: `accept`, `authorization`, `range`, and a generic `headers=` block (one
`Name: Value` per line); every method but GET and HEAD also takes `content=` (the
body) and `content_type=`. Every input is typed in the manifold, so `urn:kernel:actions`
and the MCP projection state the contract an agent can form a call from.

The result carries the origin's `Content-Type`; the declared output
(`application/octet-stream`) is what an unlabeled response is served as. `HEAD`
always serves `text/plain` (`true`/`false`) and declares exactly that.

### WebDAV: PROPFIND and REPORT

`urn:http:propfind` (RFC 4918) and `urn:http:report` (RFC 3253) are what CalDAV and
CardDAV clients need: listing a calendar home, a `calendar-query` (RFC 4791), an RFC
6578 `sync-collection`. Both are safe methods that carry an XML body, so they
resolve with `sink` and are never cached, but they are not writes: a success cuts
no golden thread, so a cached GET of the same URL stays cached. `Depth` goes
through `headers=`; a `207 Multi-Status` is the result, with the origin's
`Content-Type`. They are gated by the same `urn:cap:net` ACL as every other
method, and never follow a redirect.

```text
sink urn:http:propfind url=https://dav.example.com/calendars/me/ headers="Depth: 1" content_type=application/xml content=<the propfind XML>
```

### Renamed in 0.2.0; the old IRIs are deprecated aliases, still bound in 0.3.x

Through 0.1.x these bound at `urn:httpGet` … `urn:httpDelete` with camelCase ids
(`httpGet` …). 0.2.0 renamed them to the kebab-case convention ikigai-core states.
**The old IRIs still resolve through 0.3.x**, as deprecated aliases: `urn:httpGet`
answers exactly as `urn:http:get` (one cache entry, one golden thread, the new id
when it describes itself), and the catalog lists only the new names. They were
due to go in 0.3.0 and **stay bound through 0.3.x**: callers still name them
(ikigai-runbook's demo commands, an example in ikigai-throttle's docs), and a removed
name breaks its callers at run time, not at compile time. Their removal is a later
minor of its own. The old ids are not kept: an id is a name, not an IRI, and nothing
resolves by it, so MCP tool names and catalog labels move now. PROPFIND and REPORT
arrived after the rename and have no old name. See
[CHANGELOG.md](CHANGELOG.md) for the full map.

## Status: one table, typed failures (0.3.0)

The endpoints never hand back an error page dressed up as the resource: a
non-success status is a typed `ikigai_core::Error`, and its `class()` (core's)
says who may repeat it. The mapping is ONE public table, `ikigai_http::status`, so
every module that talks HTTP (ikigai-llm, ikigai-meeting) calls it instead of
keeping a copy:

| origin status | error | class |
| --- | --- | --- |
| 404, 410 | `NotFound` | permanent |
| **401, 403** | **`Refused`** (was `Denied` before 0.3.0) | refused |
| 408, 504 | `Timeout` | transient |
| 409, 412 | `Conflict` | permanent |
| 413, 414, 431 | `OverBudget` | over-budget |
| **429** | **`RetryAfter`**, delay from `Retry-After` | retry-after |
| 503 with a usable `Retry-After` | `RetryAfter` | retry-after |
| 502, and 503 without one | `Unavailable` | transient |
| 501 | `Unsupported` | permanent |
| **500, other 5xx**, other statuses | **`Endpoint`** (500 was `Unavailable`) | unknown |

`Retry-After` is read in both forms: delay-seconds, or an HTTP-date measured on the
kernel's injected clock (no clock, or a malformed value, means no delay). A
transport that gives up waiting is `Timeout`; any other transport failure is
`Unavailable`. `Denied` is now only the capability floor's word: our grant did not
cover the URL. Each action declares its failure classes (`Description::fails`), so
the manifold says what can go wrong before anything does. HEAD stays lenient: any
answered status but 404/410 is `true`.

```rust
use ikigai_http::status::status_error;
let err = status_error(429, None, "HTTP 429").unwrap();
assert_eq!(err.to_string(), "retry later: rate-limited: HTTP 429");
```

## Capabilities

Calls are gated by `urn:cap:net:<host>[/<path-prefix>]` scopes (a leading `-`
denies), matched longest-prefix-wins, deny-breaks-ties, segment-aware,
default-deny. A `root` capability allows everything.

The endpoint, not the transport, follows redirects, and only for GET and HEAD,
re-running the ACL on every hop. Every method that sends a body (POST, PUT, PATCH,
DELETE, PROPFIND, REPORT) refuses a 3xx with a typed error naming the target, so
the body is never replayed at an authority the caller did not vet.

## Caching (needs `ikigai-core` ≥ 0.1.12)

A cacheable GET/HEAD is threaded on its URL — a later mutating call to the same URL
cuts that thread and recomputes it — and, when the response carries
`Cache-Control: max-age`, cached until that deadline (enforced by the kernel's
injected `Clock`). With no freshness signal a read stays live (uncacheable).

## Host transport

The crate is I/O-agnostic: it defines an `HttpTransport` trait and the host supplies
the implementation — `reqwest`/`ureq` natively, `fetch` in a browser, a mock in
tests. No HTTP client (and no async runtime) is baked in; the executor is chosen at
the edge, as everywhere in ikigai.

```rust
let space = ikigai_http::space(Arc::new(MyTransport));
// mount `space` in your kernel, then: source urn:http:get url=https://example.com
```

`space` returns core's `Alias` overlay over the eight bindings (that is how the
deprecated names resolve); hold it as an `Arc<dyn Space>`. `endpoints` returns the
bare `EndpointSpace` without the aliases, and `deprecated_aliases` the rewrite table,
for a host that wants it at `urn:kernel:aliases` too (`Kernel::with_aliases`).

## Authorization headers and base64

Two plain-function modules, usable without mounting anything, are the ecosystem's
one implementation of what every HTTP caller needs, so no module formats a
`Basic` header or encodes base64 by hand:

```rust
use ikigai_http::auth;

// RFC 7617: UTF-8, refusing a `:` in the user id and any control character.
let value = auth::basic("Aladdin", "open sesame")?;
assert_eq!(value.as_str(), "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");

// RFC 6750: the token must be a b64token.
let value = auth::bearer("mF_9.B5f-4.1JqM")?;

// An incoming value: the scheme, case-insensitive, and the credentials after it.
assert_eq!(auth::scheme("bearer tok"), Some((auth::Scheme::Bearer, "tok")));

// RFC 4648 base64, standard alphabet, padded, canonical.
assert_eq!(ikigai_http::base64::encode("foobar"), "Zm9vYmFy");
```

A built `Authorization` prints as `Authorization(Basic <redacted>)` in `Debug` and
has no `Display`, and a refusal names the rule, never the credential. The behavior
is pinned by `tests/vectors/auth_vectors.json`, hand-written from the RFCs; the
Python and Deno faces pin a byte-identical copy.

## Conformance

The module **passes
[`ikigai-conformance`](https://github.com/ikigai-rs/ikigai-conformance)**
(`tests/conformance.rs`): every action fires against a loopback origin on an
ephemeral port, through the smallest transport that keeps the "never follow a
redirect" contract. Two walks: over a response with no freshness signal
`http-get`/`http-head` are declared **live** and held to it (a web read is live by
default — the polarity that catches a fresh read quietly becoming cached), and
over a `Cache-Control: max-age` response the same two are declared **cacheable**
and held to a cache hit under the URL's golden thread. What the suite cannot see
is pinned beside it: under no grants — or a grant on another host — every verb is
a typed `Denied` before any socket opens (the origin counts its connections); a
redirect to a host outside the allowlist dies at the ACL before the hop; an
`ETag` alone leaves a read live (no conditional revalidation exists); and each
deprecated name answers exactly as its new one on every verb (the suite walks the
catalog, which lists only the new names, so it never sees an alias). The WebDAV
pair is pinned against the origin too: the method token, the XML body and the
`Depth` header reach the wire, a `207` is the result, two calls are two requests,
a cached GET of the same URL survives, and a redirect is refused.

`space(transport)` carries **no name of its own**, and the suite holds it to that
(`SPACE-NAME`, declared host-named). It is instance-built: its doors close over
the transport the host hands it, and a space's name is a cache claim (same name,
same doors), so only the host knows which instance it is and the host names it.

Every check runs, `NAMES` included (it was skipped through 0.1.x, while the
camelCase ids waited for the coordinated rename). One check is waived, and the
printed report says why: `OUTPUTS` is waived **per endpoint** for the seven
actions that serve the origin's own `Content-Type` — `outputs` is a closed list
in core's `Description`, so there is nothing truthful to declare beyond
`application/octet-stream`, the type served when the origin labels nothing, and
enumerating types an origin might send would pass the check by lying. The waiver
is one check on seven ids, never the whole endpoint: `ENFORCED` and `CACHEABLE`
keep running on all eight. What it gives up is pinned by hand — the origin's label
passes through, an unlabeled response gets the declared fallback, and a label
with parameters is served as its bare media type.

## License

MIT OR Apache-2.0.
