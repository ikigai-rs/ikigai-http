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

| resolve  | IRI               | id            | HTTP   | cacheable |
|----------|-------------------|---------------|--------|-----------|
| `source` | `urn:http:get`    | `http-get`    | GET    | yes       |
| `exists` | `urn:http:head`   | `http-head`   | HEAD   | yes       |
| `sink`   | `urn:http:post`   | `http-post`   | POST   | no        |
| `sink`   | `urn:http:put`    | `http-put`    | PUT    | no        |
| `sink`   | `urn:http:patch`  | `http-patch`  | PATCH  | no        |
| `delete` | `urn:http:delete` | `http-delete` | DELETE | no        |

The URL is an argument (`url=`, an `xsd:anyURI`, the only required input), so one
binding serves every URL and the cache keys on the URL. Optional args set request
headers: `accept`, `authorization`, `range`, and a generic `headers=` block (one
`Name: Value` per line); mutating methods also take `content=` (the body) and
`content_type=`. Every input is typed in the manifold, so `urn:kernel:actions`
and the MCP projection state the contract an agent can form a call from.

The result carries the origin's `Content-Type`; the declared output
(`application/octet-stream`) is what an unlabeled response is served as. `HEAD`
always serves `text/plain` (`true`/`false`) and declares exactly that.

### Renamed in 0.2.0; the old IRIs are deprecated aliases until 0.3.0

Through 0.1.x these bound at `urn:httpGet` … `urn:httpDelete` with camelCase ids
(`httpGet` …). 0.2.0 renamed them to the kebab-case convention ikigai-core states.
**The old IRIs still resolve through 0.2.x**, as deprecated aliases: `urn:httpGet`
answers exactly as `urn:http:get` (one cache entry, one golden thread, the new id
when it describes itself), and the catalog lists only the new names. **0.3.0
removes them.** The old ids are not kept: an id is a name, not an IRI, and nothing
resolves by it, so MCP tool names and catalog labels move now. See
[CHANGELOG.md](CHANGELOG.md) for the full map.

## Capabilities

Calls are gated by `urn:cap:net:<host>[/<path-prefix>]` scopes (a leading `-`
denies), matched longest-prefix-wins, deny-breaks-ties, segment-aware,
default-deny. A `root` capability allows everything.

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

`space` returns core's `Alias` overlay over the six bindings (that is how the
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
catalog, which lists only the new names, so it never sees an alias).

`space(transport)` carries **no name of its own**, and the suite holds it to that
(`SPACE-NAME`, declared host-named). It is instance-built: its doors close over
the transport the host hands it, and a space's name is a cache claim (same name,
same doors), so only the host knows which instance it is and the host names it.

Every check runs, `NAMES` included (it was skipped through 0.1.x, while the
camelCase ids waited for the coordinated rename). One check is waived, and the
printed report says why: `OUTPUTS` is waived **per endpoint** for the five
actions that serve the origin's own `Content-Type` — `outputs` is a closed list
in core's `Description`, so there is nothing truthful to declare beyond
`application/octet-stream`, the type served when the origin labels nothing, and
enumerating types an origin might send would pass the check by lying. The waiver
is one check on five ids, never the whole endpoint: `ENFORCED` and `CACHEABLE`
keep running on all six. What it gives up is pinned by hand — the origin's label
passes through, an unlabeled response gets the declared fallback, and a label
with parameters is served as its bare media type.

## License

MIT OR Apache-2.0.
