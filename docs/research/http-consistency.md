# One HTTP behavior across every ikigai implementation

Status: research note (ledger #1601). No code changes. This note covers what each
implementation does today when it serves HTTP and when it calls HTTP, which features we need to
decide on, how to keep N implementations consistent, and where the rules should live. It ends
with proposed follow-up items.

The goal: an ikigai host should behave the same whether it is written in Rust, Python, TypeScript
(Deno, Node, Bun), .NET or Clojure. That covers what it serves (PATCH, content negotiation,
conditional requests, error bodies, 429) and what it can call (PKCE, OAuth 2 and OpenID Connect,
DPoP, HTTP Message Signatures). It should hold for the features that exist, and for which
features exist at all.

## How this was read

Everything below was read on 2026-11-21 from the `main` branch of public repositories in the
ikigai-rs organization. Nothing in them was changed. The commits were ikigai-cli `ca3a50b`
(which contains the `ikigai-web` library crate), the standalone ikigai-web server `95c2459`, and
the heads of ikigai-gonk, ikigai-layers, ikigai-python, ikigai-ts, ikigai-dotnet,
ikigai-clojure, ikigai-core, ikigai-conformance and ikigai-sign on that date, plus this
repository at `91a97a7`. A link points at `main`, so line anchors can drift. A verdict of
**absent** means a search of the repository for the feature's header names, media types and RFC
numbers found nothing.

Abbreviations used in the tables:

- **web-lib**: the `ikigai-web` library crate in ikigai-cli (`crates/ikigai-web`). It includes
  the endpoint response headers added by ikigai-cli PR 516.
- **web-srv**: the standalone ikigai-web server (crate `ikigai-web-server`).
- **gonk**: ikigai-gonk's HTTP door on port 1062. It is `ikigai-web` 0.5.0 from crates.io with
  gonk's own admission, session and refusal-page layers on top.
- **layers**: ikigai-layers, the layer host.
- **http**: this repository, the outbound client module.
- **py**, **ts**: ikigai-python and ikigai-ts.

## 1. Inventory

### Who speaks HTTP at all

| Implementation | Serves HTTP | Calls HTTP | Transport otherwise |
|---|---|---|---|
| web-lib (Rust) | yes, hyper HTTP/1.1 | no | none |
| web-srv (Rust) | yes, its own parser and router; imports only `OriginCheck`, `SecurityHeaders` and the HTML CSP from `ikigai-web` 0.4.3 | no | IPC mounts to a kernel |
| gonk (Rust) | yes, through `ikigai-web` 0.5.0 on loopback | one `ureq` call (the layers descriptor on Join) | Unix socket, QUIC with mutual TLS |
| layers (Rust) | no. Its README says the HTTPS front is not built; a binary serves one static descriptor | no | QUIC with mutual TLS, through ikigai-cli |
| http (Rust) | no | yes, through a host-supplied `HttpTransport` (reqwest, ureq, fetch or a mock) | none |
| py | only in examples (Litestar, Falcon, FastHTML, `http.server`) | no (httpx in tests only) | wire protocol over Unix sockets; optional QUIC client |
| ts | only in examples (Hono, Oak, Fresh, `Deno.serve`) | no | wire protocol over Unix sockets on Deno, Node and Bun |
| dotnet, clojure | no | no | Unix sockets. .NET plans an HTTP transport to a host's HTTP front |

Today, consistency is a Rust problem on the serving side, and that Rust code is split in two:
web-lib, which gonk also uses, and web-srv, which has its own copy. The Python and TypeScript
faces serve HTTP only in example apps. No face other than this repository calls HTTP as a
library feature. What the faces already share is narrow: the status mapping from core's
`failure_class_vectors.json`, and the `Authorization` and base64 helpers copied from this
repository's `auth_vectors.json`.

### Feature by implementation

S = supported, P = partial, A = absent, n/a = the implementation has no HTTP on that side.
"ex." means only in the example apps, not in the library.

**Serving (inbound)**

| Feature | web-lib | web-srv | gonk | layers | py | ts |
|---|---|---|---|---|---|---|
| PATCH | P: JSON Merge Patch only, read-modify-write; anything else gets 415 | A: 405 | P: inherits web-lib; gonk endpoints treat PATCH as a plain write | A | P ex.: always 415 | P ex.: always 415 |
| Accept with q-values | S: ranks specificity, q=0 excludes | P: first recognized type wins, q ignored | S (web-lib) | P: `as=` only | A | A |
| `Vary` | S: Accept plus credential headers | S: `Vary: Accept` | S (web-lib) | n/a | A | A |
| No acceptable type | 406, body lists the served types | serves the default type | 406 (web-lib) | n/a | A | A |
| `as=` override | S; a repeated `as` is 400 | S | S | S | A | A |
| ETag and `If-None-Match` to 304 | S: strong content-hash tag | S: `"b3:<hex>"`, weak comparison | S | A | A | A |
| `If-Match` and 412 | S, plus `If-None-Match: *` for create-only writes | A | S (web-lib) | A: a lost race is `Conflict` | A | A |
| `Last-Modified`, `If-Modified-Since` | A, on purpose | A | A | A | A | A |
| HEAD | S: GET without the body, on error paths too | P: an existence check, so its headers differ from GET's | S | n/a | P ex. | P ex. |
| OPTIONS and `Allow` | S: derived from the declared verbs | P: hard-coded `Allow`; OPTIONS gets 405 | S | n/a | P ex. | P ex. |
| 405 | S | S | S | n/a | P ex. | P ex. |
| `Cache-Control` | S: from the kernel's expiry; credentialed reads are `private` | S: same mapping | S; private pages `no-store` | n/a | A | A |
| Error body | text, minimal HTML for browsers, typed JSON, a page hook | text only | text, plus an HTML refusal page offering passkey sign-in | typed kernel error (kind and message) | text ex. | text and HTML ex. |
| `application/problem+json` (RFC 9457) | A | A | A | A | A | A |
| 429 with `Retry-After` | S: per-rule budgets; 503 with `Retry-After` when full | A | S | P: "try again later" with no delay | S ex. | S ex. |
| CORS | S: `CorsPolicy`, closed by default | A | A, on purpose: foreign `Origin` on a write is 403 | n/a | A | A |
| Cross-site write check (Origin, `Sec-Fetch-Site`) | S | S | S, plus a `Host` check (421) | n/a | A | A |
| Range, 206, 416, `If-Range` | P: one range, over seekable bodies with a strong tag | A | P (web-lib) | n/a | A | A |
| Compression | A | A | A | n/a | A | A |
| TLS | P: none built in; trusts `X-Forwarded-*` behind a proxy; HSTS only on HTTPS | A: plain HTTP | plain loopback HTTP; QUIC has mutual TLS | QUIC mutual TLS | A | A |
| Session cookie | P: endpoint `Set-Cookie`, off by default | A | S: `HttpOnly; SameSite=Strict` | n/a | A | A |
| Passkeys (WebAuthn) | hook only (`CapFn`, `PrincipalFn`, `AdmitFn`) | A, deferred | S: assertion only, invite-anchored registration | A: client certificates instead | A | A |
| Bearer tokens accepted | hook only | A | A | A | A | A |
| OAuth 2 resource server, OIDC | A | A | A | A | A | A |
| DPoP verification (RFC 9449) | A | A | A | A | A | A |
| HTTP Message Signatures verification (RFC 9421) | A | A | A | A | A | A |

**Calling (outbound)**

| Feature | http | gonk | py | ts | dotnet, clojure |
|---|---|---|---|---|---|
| Methods | GET, HEAD, POST, PUT, PATCH, DELETE, PROPFIND, REPORT | GET only (`ureq`) | n/a | n/a | n/a |
| Capability-gated egress (`urn:cap:net:*`) | S: per hop, default deny | P: HTTPS-only, no redirects | n/a | n/a | n/a |
| Status to typed error, one table | S: `ikigai_http::status` | A | S: core's failure-class table, reverse direction | S, same | S, same (clojure) |
| `Retry-After`, both forms | S | n/a | n/a | n/a | n/a |
| Caching and freshness (`max-age`, `Expires`, heuristic) | S | A | n/a | n/a | n/a |
| Conditional revalidation (`If-None-Match`, `If-Modified-Since`, 304) | S | A | n/a | n/a | n/a |
| Credential stripping on cross-origin redirect | S | n/a (no redirects) | n/a | n/a | n/a |
| Range helpers (RFC 9110) | S, with `range_vectors.json` | n/a | A: no copy of the vectors, although this README says they pin Python and Deno | A, same | A |
| Basic and Bearer header helpers | S, with `auth_vectors.json` | n/a | S (copy) | S (copy) | S (clojure copy) |
| base64url for JOSE | S: `encode_url`, `decode_url` | n/a | S: `encode_url`, `decode_url` | S: `encode_url`, `decode_url` | clojure has `base64.clj`; not checked for base64url |
| PATCH body formats (build a merge patch or JSON Patch) | A: the body is opaque `content=` | n/a | n/a | n/a | n/a |
| PKCE (RFC 7636) | A (base64url is the building block) | A | A | A | A |
| OAuth 2 client, OIDC relying party | A. The egress credential door design (`docs/egress-credentials.md`) defers OAuth | A | A | A | A |
| DPoP proofs (RFC 9449) | A | A | A | A | A |
| HTTP Message Signatures (RFC 9421) | A | A | A | A | A |
| Response compression (`Accept-Encoding`) | left to the transport | `ureq` default | n/a | n/a | n/a |

Elsewhere in the organization: ikigai-meeting runs Zoom server-to-server OAuth with its own token
cache, and ikigai-runtime already answers a wasm component's error as
`application/problem+json`. Both are outbound or internal and outside the tables above, but they
are prior art the shared rules have to absorb.

### Divergences that matter now

1. **web-srv is not built on web-lib's request handling**, so none of web-lib's newer behavior
   reaches it: q-values, 406, `If-Match`/412, OPTIONS, CORS, Range, HTML errors, 429, endpoint
   headers. This is the largest inconsistency, and it is within one language.
2. **HEAD means two things.** In web-lib, HEAD is GET without the body (RFC 9110 section 9.3.2).
   In web-srv, HEAD is an existence check, so its `ETag` and `Content-Type` do not match the
   GET's. This repository's `urn:http:head` is an existence answer too, but on the client side,
   where that is a declared contract rather than a protocol claim.
3. **Negotiation disagrees.** For `Accept: text/plain;q=0.1, text/turtle`, web-lib serves
   Turtle and web-srv serves plain text.
4. **ETag comparison differs.** web-lib compares `If-None-Match` weakly and `If-Match` strongly,
   as RFC 9110 section 13.1 requires. web-srv implements only the weak `If-None-Match`.
5. **The PATCH comment cites RFC 7386**, which RFC 7396 obsoleted. The behavior is the same, but
   the citation should be fixed.
6. **Recorded vector commits disagree between faces**: python and dotnet record core `df867e4`,
   clojure records `d232fd7`. Each face checks its copy against itself, so this drift is
   invisible to any public check.

## 2. The features to decide on

Each feature below has a proposed rule, the spec it comes from, and whether shared vectors can
pin it. "Vectorizable" means the rule is a pure function, so a JSON case of input and expected
output decides it, the way `range_vectors.json` does.

| Feature | Spec | Proposed rule | Vectorizable |
|---|---|---|---|
| PATCH, JSON | RFC 7396 (Merge Patch); RFC 6902 (JSON Patch) with RFC 6901 pointers | Serve both media types. Advertise them in `Accept-Patch` (RFC 5789 section 3.1). An unknown patch type gets 415 with `Accept-Patch`. A failed JSON Patch `test` op gets 409; an unapplicable patch gets 422. Apply under `If-Match` when the client sends one. | Yes. RFC 7396 appendix A and the RFC 6902 examples are ready-made cases. |
| PATCH, RDF | No IETF standard. Candidates: SPARQL 1.1 Update (`application/sparql-update`), the Solid N3 Patch, RDF Patch. | Pick one format for graph resources and state it in `Accept-Patch`. SPARQL Update is the least new surface, because the hosts already speak SPARQL. | Yes, as graph in, patch in, graph out (compare isomorphic). |
| Content negotiation | RFC 9110 sections 12.4 and 12.5.1 | Rank by q, then specificity. q=0 excludes. When nothing matches, answer 406 with the served types listed, except for a browser navigation that sent `*/*`. `as=` beats `Accept`; a repeated `as` is 400. Always send `Vary: Accept` on a negotiated response. | Yes: an Accept header plus offered types in, chosen type or 406 out. |
| Conditional requests | RFC 9110 section 13 | Strong comparison for `If-Match` and `If-Range`, weak comparison for `If-None-Match`. Evaluate the preconditions in the order RFC 9110 section 13.2.2 gives. 304 on a safe method, 412 on an unsafe one. Decide whether `Last-Modified` is in or out on purpose, and write the reason down. | Yes: a tag list, current tag and method in, status out. |
| HEAD, OPTIONS, `Allow`, 405 | RFC 9110 sections 9.3.2, 9.3.7, 10.2.1, 15.5.6 | HEAD is GET without the body, with the same headers. OPTIONS answers 204 with `Allow`. Every 405 carries `Allow`. | Mostly. A request-in, response-out harness can pin it. |
| Caching headers | RFC 9111 | Keep web-lib's mapping (kernel expiry to `Cache-Control`; "never expires" to `no-cache`; credentialed reads `private`) and make it the rule. | Yes: expiry and credential flag in, header out. |
| Error bodies | RFC 9457 (Problem Details) | Negotiate the error body like any other face: `text/plain` by default, HTML for a browser, `application/problem+json` when asked. `type` is a stable URI per core failure class; `title` is words, never a bare status number. Never echo a credential. | Yes: failure class plus Accept in, status, media type and body fields out. Extends core's failure-class vectors. |
| 429 and `Retry-After` | RFC 6585 section 4; RFC 9110 section 10.2.3 | Server: whole seconds, rounded up, never 0. Client: accept both forms (already this repository's rule). Ledger #1485. | Yes, and the client half already exists in `status::retry_after`. |
| CORS | Fetch standard | Closed by default. When opened, preflight is answered from the declared verbs. A cross-site write check (Origin, `Sec-Fetch-Site`) is required whether or not CORS is open. | Yes: request headers plus policy in, response headers out. |
| Range | RFC 9110 section 14 | Already shared on the client side through `range_vectors.json`. Server rule: one range, strong validator only, 416 with `Content-Range: bytes */len`. | Yes, extend the existing vectors. |
| PKCE | RFC 7636 | Client: S256 only, never `plain`. The verifier is 43 to 128 characters from a CSPRNG. Server role: none until a host issues tokens. | The transform, yes (RFC 7636 appendix B). The randomness, no: test its length and alphabet instead. |
| OAuth 2 and OpenID Connect | RFC 6749, RFC 9700 (OAuth 2.0 security BCP), OpenID Connect Core 1.0, RFC 8414, RFC 8628 (device grant) | Client: authorization code with PKCE; device grant for terminals. Resource server: validate the JWT (RFC 9068) or introspect (RFC 7662). Map the scope to `urn:cap:*` grants. Tokens are references held by the egress credential door, never caller arguments. | Partly. Token validation can be pinned with fixed keys and fixed clock vectors. Flows need a harness with a mock authorization server. |
| DPoP | RFC 9449 | Client: ES256 proofs with `htm`, `htu`, `iat`, `jti`, and `ath` when a token is bound. Server: verify the proof, keep a `jti` replay cache, and answer `DPoP-Nonce` challenges. | Verification, yes, with fixed keys and clock. ECDSA proofs are not deterministic, so generation is tested by verifying, not by byte comparison. |
| HTTP Message Signatures | RFC 9421; RFC 9530 (`Content-Digest`) | Sign and verify with `ed25519` and `ecdsa-p256-sha256`, the two algorithms ikigai-sign already has. A shared rule names the covered components (`@method`, `@target-uri`, `content-digest` and so on). | Yes. RFC 9421 appendix B gives test keys and signature bases; Ed25519 output is deterministic. |
| Compression | RFC 9110 section 8.4 | Decide whether to serve it at all (absent everywhere today). If yes, gzip only, never on credentialed responses that echo secrets (BREACH). | Yes. |
| Security headers | CSP, `nosniff`, `Referrer-Policy`, HSTS | Keep web-lib's preset as the rule. HSTS only over HTTPS. | Yes. |

## 3. The mechanism

### The options

**(a) Capture the rules once and reimplement them N times, pinned by shared vectors and a
behavioral suite.** This is how the organization already works: core's contract, capability,
validation and failure-class vectors, and this repository's auth and range vectors. Every face
copies them verbatim and runs every case. Each face's cost is linear in its features, but every
case is mechanical. A new face finds out what "done" means by running the vectors.

**(b) One Rust implementation, exposed as a wasm component or through FFI.** It gives one
behavior by construction. It also conflicts with how the faces are built: ikigai-python is
pure Python, ikigai-ts runs unchanged on Deno, Node and Bun, and ikigai-clojure targets
babashka. Each would gain a native or wasm runtime dependency to send a header. HTTP serving in
those faces happens inside the language's own framework (Litestar, Hono and so on), so a Rust
core would have to sit between the framework and the handler, which is more glue than the rule
itself. ikigai-runtime makes a wasm component possible, but it does not make it cheap.

**(c) A specification document only.** It drifts the moment one implementation changes, as
web-lib and web-srv already show within one language.

### Recommendation: (a), in two layers, with vetted libraries for security protocols

1. **Rule vectors** for every rule that is a pure function: Accept selection, ETag comparison and
   precondition evaluation, `Cache-Control` projection, `Retry-After` both ways, Range,
   problem-details mapping, CORS preflight, Merge Patch and JSON Patch, PKCE S256, RFC 9421
   signature bases. They use the same format as `auth_vectors.json`: hand-written from the RFC,
   each case citing its section, `version`, ASCII, LF only, and decimal strings for any number
   above 2^53.
2. **A behavioral suite** for serving: an ordered list of `{request, expected status, required
   headers, forbidden headers, body predicate}` cases, run against a reference resource set that
   each implementation mounts (a negotiable resource with three faces, a writable JSON resource,
   a graph resource, a rate-limited resource). Each implementation supplies a small adapter that
   starts its server on an ephemeral port. A runner in each language replays the cases over
   real sockets. This is what catches the HEAD and negotiation divergences above, because those
   are wiring bugs, not bugs in a pure function.

**Security-sensitive features are not reimplemented.** OAuth 2, OpenID Connect, DPoP and HTTP
Message Signatures are each implemented with a maintained library per language, chosen after a
review. The shared vectors still apply to them, as verification cases with fixed keys and a
fixed clock, so a face that picks a library proves that library agrees with every other face.
JWT and JOSE validation is where homegrown code fails in ways that tests do not find (algorithm
confusion, `none`, key confusion, missing `aud` or `exp` checks). Candidate libraries to
evaluate, not yet chosen:

| Concern | Rust | Python | TypeScript | .NET |
|---|---|---|---|---|
| OAuth 2 client, PKCE, DPoP | `oauth2`, `openidconnect` | Authlib | `oauth4webapi` | `Duende.IdentityModel` |
| JOSE, JWT | `jsonwebtoken` or `josekit` | Authlib JOSE, `joserfc` | `jose` | `Microsoft.IdentityModel.JsonWebTokens` |
| RFC 9421 | to be found; the Rust ecosystem is thin, so a small implementation over ikigai-sign, pinned by the RFC's appendix B vectors, may be the honest option | `http-message-signatures` | to be found | to be found |

PKCE itself is small enough to share as a rule (S256 of a CSPRNG verifier). It is listed with
the security protocols only because it comes bundled in the OAuth libraries.

ikigai-sign already signs with Ed25519 and ES256 and outputs a raw `r||s`, which is the JWS ES256
signature encoding. For DPoP and RFC 9421 it lacks a JWK encoding of the public key, the JWS
compact form, the RFC 9421 signature base, and a way to get bare signature bytes rather than an
RDF graph. Signing through ikigai-sign keeps keys kernel-resolved, so the protocol framing can
come from a library while the key never leaves ikigai-sign.

### Deliberately not decided here

- Whether the faces should ever serve HTTP as a library feature, or only in examples. The
  vectors are useful either way: they pin the example apps today and a library tomorrow.
- Which RDF patch format. A recommendation is above, but it needs a design of its own.

## 4. Placement and the daily drift gate

### Where the rules live

The organization already puts a protocol's vectors in the repository that owns the protocol,
not in a central one. Core owns the failure-class table, and this repository owns `auth` and
`range`. ikigai-conformance owns "what done means for a module": the module contract, not wire
behavior. It ships no vector files, so it is the wrong home for HTTP semantics.

Proposed placement:

- **ikigai-http `tests/vectors/`** holds the rule vectors that are not specific to serving:
  Accept selection, ETag comparison and preconditions, `Retry-After`, Range, PKCE, patch
  application, RFC 9421 signature bases, DPoP and JWT verification. This repository is
  runtime-free, compiles for wasm, already ships `ikigai_http::status`, `range`, `auth` and
  `base64` as the ecosystem's one copy, and is already a vector source for the faces. web-lib
  already depends on it: gonk's lock file pulls `ikigai-http` in through `ikigai-web`. Its Rust
  tests are the generator check: every case runs against `ikigai_http`, and a case the crate
  fails is a failing test.
- **The `ikigai-web` library in ikigai-cli** holds the behavioral suite and the serving-only
  vectors (problem-details mapping, `Cache-Control` projection, CORS preflight), because it is
  the reference server. web-srv and gonk run the suite against themselves.
- **core** keeps the failure-class rows. Problem-details `type` URIs extend those rows rather
  than starting a second table.
- **A short rules page** (`docs/http-rules.md` here) names every rule, its RFC section and the
  vector file that pins it, so a reader does not have to read the JSON.

### How drift is gated daily

The drift check today is not public, and no public workflow in the organization has a
`schedule:` trigger. Each face checks only that its own copy is unchanged: ikigai-dotnet and
ikigai-clojure compare `SHA256SUMS`; ikigai-python and ikigai-ts check only line endings. That
is how two faces came to record different core commits.

Proposal:

1. Every face that copies a vector file records it in one `vectors.lock` beside the copies:
   source repository, path, source commit and SHA-256. Its own test fails if a digest does not
   match. This standardizes what dotnet and clojure already do, and it replaces the prose
   provenance in python and ts.
2. A scheduled workflow (daily `cron` in the organization's `.github` repository, reusing the
   existing `rust.yml` pattern) reads every face's `vectors.lock`, fetches each source file at
   the source's `main`, and fails when a digest differs. The failure names the face, the file,
   the recorded commit and the current one. It opens or updates one issue per face rather than
   failing silently.
3. The behavioral suite runs in each serving implementation's ordinary CI on every pull request,
   pinned to the suite version it last passed, so a newer suite version shows up as drift in
   step 2 rather than as a surprise CI failure.

## 5. Proposed follow-up items

One item per feature gap and implementation. Each has a title and a short body.

1. **web-srv: adopt web-lib's request handling, or document why not.**
   web-srv has its own parser and router and misses q-values, 406, `If-Match`/412, OPTIONS,
   CORS, Range, HTML errors and 429. Move it onto web-lib's door, or list each divergence as a
   decision.
2. **web-srv: make HEAD equal GET without the body.**
   HEAD is an existence check today, so its `ETag` and `Content-Type` differ from GET's.
   RFC 9110 section 9.3.2.
3. **web-srv: rank Accept by q-value and answer 406.**
   For `text/plain;q=0.1, text/turtle` it serves plain text, and it never answers 406. Match
   web-lib's rule.
4. **web-srv: support `If-Match` and 412, and strong comparison where RFC 9110 requires it.**
5. **web-lib: fix the RFC 7386 citations to RFC 7396, and send `Accept-Patch`.**
   The behavior is right; the citation names an obsoleted RFC, and 415 answers should advertise
   the accepted patch types (RFC 5789 section 3.1).
6. **web-lib: add JSON Patch (RFC 6902) as a second patch type.**
   Pinned by vectors from the RFC 6902 examples; 409 for a failed `test` op, 422 for an
   unapplicable patch.
7. **Design: one RDF patch format for graph resources.**
   Compare SPARQL Update, N3 Patch and RDF Patch against the PATCH resource design, and pick one
   for `Accept-Patch`.
8. **web-lib and core: problem+json as a negotiated error face (RFC 9457).**
   Map each core failure class to a stable `type` URI, extend the failure-class vectors, and
   serve it when the client asks for `application/problem+json`.
9. **layers: carry a `Retry-After` delay on join-lobby rate limits.**
   The answer says "try again later" with no delay, so a client cannot back off correctly.
   Ledger #1485.
10. **Decide on `Last-Modified` and `If-Modified-Since` across servers.**
    web-lib omits them on purpose. Record the reason as a rule so other implementations do not
    add them inconsistently.
11. **Decide on response compression.**
    Absent everywhere. Either rule it out in the HTTP rules page, or specify gzip with the BREACH
    exclusion.
12. **ikigai-http: HTTP rule vectors for content negotiation and preconditions.**
    Add `conneg_vectors.json` and `precondition_vectors.json`, hand-written from RFC 9110,
    checked by Rust tests here. The first step of the shared mechanism.
13. **ikigai-http: `docs/http-rules.md`, the rules index.**
    One table of rule, RFC section and vector file, maintained with the vectors.
14. **web-lib: a behavioral HTTP conformance suite with a reference resource set.**
    Request in, expected status and headers out, over real sockets. Run it against web-lib,
    web-srv and gonk.
15. **ikigai-python: run the behavioral suite against the example apps.**
    Fixes the gaps it finds (always-415 PATCH, no negotiation, no ETags) in the examples.
16. **ikigai-ts: run the behavioral suite against the example apps, on all three runtimes.**
17. **ikigai-python and ikigai-ts: copy `range_vectors.json` and implement the range rules.**
    This README says the range vectors pin Python and Deno, but neither face has a copy. Both
    already copy `auth_vectors.json` and have base64url helpers.
18. **All faces: one `vectors.lock` with commit and SHA-256 per copied file.**
    Standardize the dotnet and clojure practice. Resolves the current disagreement between
    core `df867e4` and `d232fd7`.
19. **Organization: a public daily vector-drift workflow.**
    A scheduled job that compares every face's `vectors.lock` with the source and files one issue
    per drifting face.
20. **ikigai-http: PKCE S256 helper and vectors (RFC 7636).**
    Verifier length and alphabet checks, the S256 transform, and the RFC 7636 appendix B vector.
    The verifier's randomness comes from the host.
21. **Select vetted OAuth 2, OIDC and JOSE libraries per language.**
    Review the candidates in this note for maintenance, algorithm restrictions and DPoP support,
    and record the choice and the reasons.
22. **ikigai-http: OAuth 2 client through the egress credential door.**
    Authorization code with PKCE, and the device grant, using the chosen Rust library. Tokens
    stay references held by the door. Builds on `docs/egress-credentials.md`.
23. **web-lib: OAuth 2 resource-server role.**
    Validate JWT access tokens (RFC 9068) or introspect them (RFC 7662), and map the scope to
    `urn:cap:*` grants through the existing `CapFn` hook.
24. **DPoP (RFC 9449) proofs and verification, with shared verification vectors.**
    Client proofs in ikigai-http, verification and the `jti` replay cache in web-lib. ES256 keys
    are resolved through ikigai-sign.
25. **ikigai-sign: bare signature bytes and JWK export.**
    The building blocks DPoP and RFC 9421 need. Keys stay kernel-resolved.
26. **HTTP Message Signatures (RFC 9421) over ikigai-sign, pinned by the RFC's appendix B.**
    Signature-base construction and `Content-Digest` (RFC 9530), for `ed25519` and
    `ecdsa-p256-sha256`, client and server.
27. **gonk: move the layers-descriptor fetch from `ureq` onto ikigai-http.**
    The one outbound call sits behind a `Fetch` trait; moving it brings it under the capability
    ACL and the shared status table.
28. **Design: whether the faces serve HTTP as a library feature.**
    Today they serve only in examples. Decide before the behavioral suite grows a face-side
    runner that people treat as a library.
