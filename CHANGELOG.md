# Changelog

## Unreleased

### Fixed: malformed net denies fail closed (ledger #2091)

A deny with an out-of-range, nonnumeric, or empty port, or an empty host,
now refuses the whole capability check, just like a malformed host glob.
Previously these exclusions silently matched nothing, leaving other grants active.
Malformed allows still grant nothing; valid ports and bracketed IPv6 rules are unchanged.

### Added: a host glob in the net ACL, `urn:cap:net:*.<suffix>` (ledger #35)

`urn:cap:net:*.edu` grants every host strictly under `.edu` (`mit.edu`, `a.b.mit.edu`;
never `edu`, `xedu` or `mit.edu.evil.com`), as an allow or a deny, with the usual
optional `:port` and `/path-prefix`. Only a whole leftmost `*` label is a glob; any
other `*` in a host is malformed: a malformed allow grants nothing, and a malformed
deny refuses every request under that capability, so a malformed rule never widens.
A glob never matches an IP literal. Specificity: an exact host outranks every glob,
a longer glob suffix outranks a shorter one, then the longer port/path, and a deny
still breaks ties. The module docs ("The capability ACL", "Host globs") state it all.

### ⚠ Changed: hosts are compared normalized, exact rules included

The request host and every rule host are normalized by the `url` crate's WHATWG host
parser before comparison: ASCII case, one trailing dot dropped, an IDN in its A-label
(punycode) form, an IP literal canonical. So `urn:cap:net:mit.edu` now also grants
`mit.edu.`, and `urn:cap:net:bücher.de` grants `xn--bcher-kva.de`. This WIDENS exact
allows to the other spellings of the same host. It is what keeps an exact DENY whole
beside a glob: `*.edu` matches `mit.edu.`, so without it `-mit.edu` would be bypassed
by a trailing dot. A host that does not parse is compared as before (ASCII
case-insensitive), and matches no glob.

## 0.3.0

### ⚠ Changed: an origin's 401/403 is now `Error::Refused`, not `Error::Denied`

**A caller that matches `Error::Denied` to notice that an origin refused its
credential no longer sees it.** From 0.3.0 an origin's 401 or 403 is
`Error::Refused("HTTP 401")` (displayed `refused: HTTP 401`, class `refused`), and
`Error::Denied` means only what it means everywhere else in ikigai: the CAPABILITY
did not grant the call (an ungranted host, port or path, before any socket opens,
including on a redirect hop). The two have different retry rules (a denial is never
repeated; a refused credential may be renewed, once, by its holder), which is why
core 0.1.108 split them (ledger #297, #1546). At an HTTP edge a `Refused` is 502,
where a `Denied` was 403.

### Changed: one public status table, on core 0.1.108's failure classes

The status mapping is now ONE public module, `ikigai_http::status`, for every
module that talks HTTP to call instead of keeping a copy (ikigai-llm's had already
drifted). Each row, before and after:

| origin status | before (0.2.x) | 0.3.0 |
| --- | --- | --- |
| 401, 403 | `Denied` | **`Refused`** |
| 429 | `Unavailable` (transient, retried at once) | **`RetryAfter`**, `delay` from `Retry-After`; not transient |
| 503 with a usable `Retry-After` | `Unavailable` | **`RetryAfter`** with that delay |
| 503 without one | `Unavailable` | `Unavailable` (unchanged) |
| 500, 505 and every unnamed 5xx | `Unavailable` (transient) | **`Endpoint`** (class unknown, not transient) |
| 502 | `Unavailable` | `Unavailable` (unchanged) |
| 501 | `Unavailable` | **`Unsupported { verb: None }`** |
| 409, 412 | `Endpoint` | **`Conflict`** |
| 413, 414, 431 | `Endpoint` | **`OverBudget`** |
| 404, 410 | `NotFound` | unchanged |
| 408, 504 | `Timeout` | unchanged |
| other statuses | `Endpoint` | unchanged |
| a transport failure that timed out | `Unavailable` | **`Timeout`** (both transient) |
| any other transport failure | `Unavailable` | unchanged |

- `status::status_error(status, retry_after, detail)` and
  `status::response_error(&response, now, detail)` return the error for a non-success
  answer (`None` for 2xx/3xx). A 429's message is prefixed `rate-limited: `.
- `status::retry_after(value, now)` parses `Retry-After` (RFC 9110 §10.2.3):
  delay-seconds, or an HTTP-date (all three forms of §5.6.7, through the vetted
  `httpdate` crate, a new dependency) relative to the kernel's injected clock. No
  delay when the header is absent or malformed, or when an HTTP-date has no clock to
  be measured on; a past date is a zero delay.
- `status::transport_error(error, url, detail)`: the transport's failure string is
  `Timeout` when it says it timed out (the URL removed first, so a host named
  `timeout.example` cannot type its own refusals), else `Unavailable`. The client has
  no timeout of its own; the host transport's is a wait on the origin, so `Timeout`,
  not `OverBudget` (no bound of ours was exceeded).
- **Retry overlays**: a 429 and a 500 are no longer transient, so an ikigai-throttle
  `Retry`, `CircuitBreaker` or `Failover` built before core 0.1.108 stops re-issuing
  them. That is the intent: a 429 re-issued at once goes straight back into the limit,
  and an origin's 500 is no promise a repeat helps.
- HEAD (`urn:http:head`) is unchanged: any answered status but 404/410 is `true`.

### Added: declared failure classes

Every action now states what it can fail with beyond the implied classes
(`Description::fails`, core 0.1.108): GET and every method that sends a body declare
`transient`, `retry-after`, `over-budget`, `refused` and `unknown`; HEAD declares
`transient` and `unknown`. `permanent` and `denied` are implied. The manifold carries
them as `ik:mayFail`, so every action's content-addressed contract IRI moves with this
release.

### Kept: the pre-0.2.0 `urn:httpGet` … `urn:httpDelete` aliases

They were due to go in 0.3.0 and are **still bound**: ikigai-runbook's demo commands
still issue `source urn:httpGet …`, and ikigai-throttle's `RateLimit` docs use the old
name. A removed name breaks its callers at run time, not at compile time, so the
removal is a later minor of its own, once those move.

### Dependencies

- `ikigai-core` `0.1.86` → `0.1.108` (the failure-class variants and `fails`).
- new: `httpdate` `1.0.3` (already in ikigai-cli's graph).

## 0.2.2

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
