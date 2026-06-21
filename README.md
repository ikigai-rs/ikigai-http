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

The URL is an argument (`url=`), so one binding serves every URL and the cache keys
on the URL.

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

## License

MIT OR Apache-2.0.
