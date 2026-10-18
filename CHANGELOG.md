# Changelog

## Unreleased

### Added: WebDAV `PROPFIND` and `REPORT` (ledger #1875)

- **`urn:http:propfind`** (id `http-propfind`) and **`urn:http:report`** (id
  `http-report`), the methods CalDAV and CardDAV need (calendar listing, RFC 4791
  `calendar-query`, RFC 6578 `sync-collection`). Both resolve with `sink`, so the
  XML request is `content=` (and `content_type=`); `Depth` goes through `headers=`.
- **Never cached, and never a write.** They are uncacheable, like every `sink`, but
  they are safe methods: a success cuts no golden thread, so a cached `GET` of the
  same URL stays cached (`Method::is_mutating` is `false` for both).
- **Never follow a redirect**, exactly like `POST`/`PUT`/`PATCH`/`DELETE`: a 3xx with
  a `Location` is a typed `Endpoint` error naming the target, and the body is not
  replayed. Redirect-following stays GET/HEAD only. The refusal message now says
  "methods that send a body never follow redirects" (it said "mutating methods").
- **The same `urn:cap:net:<host>` ACL** as every other method, declared as
  `urn:cap:net:*` and checked per request; the same status mapping (a `207
  Multi-Status` is a success, its body passed through with the origin's bare media
  type).
- `Method::Propfind` and `Method::Report`; `Method::ALL` is now 8 long; new
  `Method::has_deprecated_iri` (`false` for the two, which never had a pre-0.2.0
  name, so `deprecated_aliases()` still holds exactly six rules and
  `Method::deprecated_iri` returns their own IRI).
- The conformance walk covers all eight endpoints; `OUTPUTS` is waived on the two new
  pass-through actions for the same reason as the other five.

⚠ **Semver, stated plainly.** `Method` is an exhaustive public enum, and the Cargo
SemVer reference counts a new variant on one as a major change: a consumer that
`match`es on `Method` without a wildcard arm stops compiling, and so does code that
names `Method::ALL`'s type as `[Method; 6]`. Every consumer was checked: the five
crates.io reverse dependencies (ikigai-browse, ikigai-dev-server, ikigai-embedded,
ikigai-llm, ikigai-meeting) and the unpublished ones (web-demo, cms-web, tutorial,
gonk). Each uses `as_str()`, `==`/`!=` or a variant as a value; none matches
exhaustively, and none names the array type.
This ships as a 0.2.x release on that evidence, so ikigai-personal can use it
without a cascade.
## 0.2.1

### Added: one Authorization-header and base64 helper (ledger #1857)

Additive; nothing existing changes.

- **`ikigai_http::auth`**: `basic(user, password)` builds an RFC 7617 `Basic` value
  (UTF-8; refuses a `:` in the user id and any control character, with a typed
  `AuthError`), `bearer(token)` an RFC 6750 `Bearer` value (refuses anything that is
  not a `b64token`), and `scheme(value)` splits an incoming `Authorization` value into
  its case-insensitive scheme and credentials. A built `Authorization` redacts itself
  in `Debug` and has no `Display`; no error carries a credential.
- **`ikigai_http::base64`**: `encode` and `decode`, RFC 4648 §4 (standard alphabet,
  padded, canonical), over the vetted `base64` crate (0.22, already in the graph of
  the adopters). The module docs give the reasoning.
- **Shared vectors** in `tests/vectors/auth_vectors.json`, hand-written from RFC 7617,
  RFC 6750, RFC 9110 and RFC 4648, with stable refusal codes; Python and Deno pin a
  byte-identical copy.

### Fixed

- The `space()` doctest compared `urn:http:get` with itself; it now describes the
  deprecated `urn:httpGet` beside `urn:http:get`, so it fails if the alias table is
  empty (ledger #1852).

## 0.2.0

### Renamed (BREAKING for anything matching on ids or tool names)

The six endpoints follow the naming convention ikigai-core's crate docs state: a
resource name is a short `kebab-case` noun, and the `Description::id` is what the MCP
projection turns into an agent's tool name (ledger #11).

| old id → new id | old IRI → new IRI |
| --- | --- |
| `httpGet` → `http-get` | `urn:httpGet` → `urn:http:get` |
| `httpHead` → `http-head` | `urn:httpHead` → `urn:http:head` |
| `httpPost` → `http-post` | `urn:httpPost` → `urn:http:post` |
| `httpPut` → `http-put` | `urn:httpPut` → `urn:http:put` |
| `httpPatch` → `http-patch` | `urn:httpPatch` → `urn:http:patch` |
| `httpDelete` → `http-delete` | `urn:httpDelete` → `urn:http:delete` |

- **The ids change outright.** An id is a name, not an IRI, and nothing resolves by
  it: MCP tool names and catalog labels move with this release.
- **The old IRIs are deprecated aliases through 0.2.x.** `urn:httpGet` resolves
  exactly as `urn:http:get`: one cache entry and one golden thread for both names,
  the new id when it describes itself, and only the new names in the catalog. So
  consumers, route configs and books migrate on their own schedule, with no flag day.
  `Method::deprecated_iri` names each one.
- **`space()` now returns core's `Alias` overlay** over the six bindings, which is how
  the aliases resolve. A host that holds it as `Arc<dyn Space>` (every known
  consumer does) is unaffected; one that names the type `EndpointSpace` changes that
  line. New: `endpoints()` (the bare `EndpointSpace`, no aliases),
  `deprecated_aliases()` (the rewrite table, for `Kernel::with_aliases` and the
  `urn:kernel:aliases` readout) and `Method::ALL`.
- `ikigai-conformance`'s `NAMES` check now runs, and is clean.

### Removal scheduled

**0.3.0 removes the deprecated aliases**, `Method::deprecated_iri` and
`deprecated_aliases()`; `urn:httpGet` … `urn:httpDelete` then miss, and `space()`
returns the `EndpointSpace` again.
