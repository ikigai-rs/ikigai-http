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

| resolve  | IRI              | HTTP   | cacheable |
|----------|------------------|--------|-----------|
| `source` | `urn:httpGet`    | GET    | yes       |
| `exists` | `urn:httpHead`   | HEAD   | yes       |
| `sink`   | `urn:httpPost`   | POST   | no        |
| `sink`   | `urn:httpPut`    | PUT    | no        |
| `sink`   | `urn:httpPatch`  | PATCH  | no        |
| `delete` | `urn:httpDelete` | DELETE | no        |

The URL is an argument (`url=`, an `xsd:anyURI`, the only required input), so one
binding serves every URL and the cache keys on the URL. Optional args set request
headers: `accept`, `authorization`, `range`, and a generic `headers=` block (one
`Name: Value` per line); mutating methods also take `content=` (the body) and
`content_type=`. Every input is typed in the manifold, so `urn:kernel:actions`
and the MCP projection state the contract an agent can form a call from.

The result carries the origin's `Content-Type`; the declared output
(`application/octet-stream`) is what an unlabeled response is served as. `HEAD`
always serves `text/plain` (`true`/`false`) and declares exactly that.

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
// mount `space` in your kernel, then: source urn:httpGet url=https://example.com
```

## Conformance

The module **passes
[`ikigai-conformance`](https://github.com/ikigai-rs/ikigai-conformance)**
(`tests/conformance.rs`): every action fires against a loopback origin on an
ephemeral port, through the smallest transport that keeps the "never follow a
redirect" contract. Two walks: over a response with no freshness signal
`httpGet`/`httpHead` are declared **live** and held to it (a web read is live by
default — the polarity that catches a fresh read quietly becoming cached), and
over a `Cache-Control: max-age` response the same two are declared **cacheable**
and held to a cache hit under the URL's golden thread. What the suite cannot see
is pinned beside it: under no grants — or a grant on another host — every verb is
a typed `Denied` before any socket opens (the origin counts its connections); a
redirect to a host outside the allowlist dies at the ACL before the hop; an
`ETag` alone leaves a read live (no conditional revalidation exists).

Two checks do not apply, and both say why in the printed report. `NAMES` is
skipped suite-wide: the six camelCase ids are live MCP tool names, renamed in one
coordinated pass (wave two). `OUTPUTS` is waived **per endpoint** for the five
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
