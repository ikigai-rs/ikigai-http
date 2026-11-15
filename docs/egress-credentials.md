# The egress credential door

Status: design spike (ledger #3751). Nothing here is built yet. The only code in this change is
`tests/egress_facts.rs`, which pins two current behaviors the design has to override.

## The problem

An agent that calls an API needs the API's credential, and today the only way to send one is
to hold it. The endpoints take the credential as an argument: `authorization=` or a line in
`headers=` (`src/lib.rs:1293-1317`). So the value sits in the caller's context, in its tool
arguments, in the request identity the kernel hashes and caches on, and in anything that logs
or echoes those. The crate docs already say what should happen instead and leave it open: "the
agent gets 'may call host X with credential Y', never the raw token. Credential lookup and
capability-gated injection remain host concerns" (`src/lib.rs:189-191`). `auth.rs` says the
same from the other side: "a caller reads them from `ikigai-secret` by name at call time and
hands them here" (`src/auth.rs:17-18`), so the caller has to hold the value.

This document designs the missing piece: an egress door. The caller sends a REFERENCE
(`urn:secret:<name>`) where the credential goes. The door checks the caller's use grant, finds
a rule that declares this secret for this host, method and path, fetches the value, places it
over TLS through the existing `auth` helpers, and answers without the value reaching the
caller's result, error text, cache or logs. Every use writes one log line. Prior art is fnox's
credential proxy (<https://fnox.jdx.dev>), which enforces this with same-user process
boundaries. This design uses kernel capabilities instead.

## What exists today, and what the design relies on

Every claim below was read in this repository at `ca4e663` or in the published crate
sources Cargo resolved for it: `ikigai-core = "0.3.0"` resolves to ikigai-core 0.3.5, and
the line numbers for ikigai-secret 0.4.0 and ikigai-log 0.11.0 are from their published
crates.

| Fact | Where | What the design does with it |
|---|---|---|
| Endpoints are gated by `urn:cap:net:<host>[:<port>][/<path>]`, checked against every hop. The check takes a host, port and path. It does not take a scheme. | `src/lib.rs:492-497`, `src/lib.rs:876-888` | The door runs the same check under the caller's capability. Because the check cannot see the scheme, the door enforces `https` itself. |
| The endpoint, not the transport, follows redirects, and only for GET and HEAD. Body-sending methods refuse any 3xx. | `src/lib.rs:860-933`, test `mutating_methods_never_follow_redirects` (`src/lib.rs:3008`) | The door keeps that behavior and narrows it further (see "Redirects"). |
| On a cross-origin hop the endpoint strips `Authorization`, `Proxy-Authorization` and `Cookie`, and nothing else. A downgrade from `https` to `http` on the same host counts as cross-origin, so it is followed with those three headers removed. | `src/lib.rs:934-942`; tests `cross_origin_redirect_drops_credentials` (`src/lib.rs:2902`) and `redirect_credentials_follow_origin_boundaries`, case `http://a.example/` (`src/lib.rs:2932`) | Not enough for the door. A secret placed in a custom header or a query parameter would survive that strip, so the door refuses those redirects. |
| A GET that carries `authorization=` is cached like any other read. The credential is part of the request identity. | Pinned by `a_get_carrying_a_credential_is_cached_today` (`tests/egress_facts.rs`); freshness is applied at `src/lib.rs:1038-1045` | The door cannot reuse the read path as it is. It has to make its own answers uncacheable. |
| A transport failure's text goes into the error unchanged, URL and query included: `format!("http transport: {e}")`. | `src/lib.rs:903-906`, `src/status.rs:225-236`; pinned by `a_transport_failure_repeats_the_url_into_the_error_text` (`tests/egress_facts.rs`) | Every error the door returns passes through the scrubber (see "Echoes"). |
| A non-success status becomes a typed error carrying only `HTTP <status>`. The origin's error body is dropped unread. | `src/lib.rs:1008-1021` | An error page that echoes the credential never reaches the caller. Only successful bodies have to be scanned. |
| `auth::basic` and `auth::bearer` are the one place a `Basic` or `Bearer` header is built. `Authorization` has no `Display`, its `Debug` redacts, and `AuthError` never carries the value. `credentials()` is the encoded form a scrubber must also look for. | `src/auth.rs:10-15`, `src/auth.rs:84-95`, `src/auth.rs:111-115`, `src/auth.rs:149-197`, `src/auth.rs:288-338` | Placement goes through these functions. No second copy is written. |
| `ikigai-secret` gates its read face per name with `urn:cap:secret:read:<name>` and checks it before it consults the keystore. A secret read is never cacheable. | ikigai-secret 0.4.0 `src/lib.rs:36-45`, `src/lib.rs:465-470`, `src/lib.rs:488-504` | Reading a secret's value is the authority the caller must NOT need. |
| A sub-request runs under the invoking endpoint's own capability, unchanged. Nothing lets an endpoint issue under a stronger one: `issue_under` is private, and that is documented as a security property. | ikigai-core 0.3.5 `src/endpoint.rs:1500-1506`, `src/endpoint.rs:1565-1580` | The door cannot fetch the value by issuing `urn:secret:<name>`: that would need the caller to hold `read`. See decision 1. |
| `Capability::attenuate` only narrows. `allows` is exact and never grants an exclusion. `satisfies` treats a trailing `*` as "holds some scope under this prefix". | ikigai-core 0.3.5 `src/capability.rs:387-421`, `src/capability.rs:546-556`, `src/capability.rs:592-594` | The use scope is declared as a wildcard and checked exactly in the door, the same pattern ikigai-secret uses. |
| A capability carries at most one principal, through `urn:cap:principal:<iri>`. | ikigai-core 0.3.5 `src/capability.rs:208`, `src/capability.rs:452-457` | The log line's `principal=` comes from here. |
| The kernel's cache is keyed by request identity, capability fingerprint and scope fingerprint. A hit is served before the endpoint runs. | ikigai-core 0.3.5 `src/kernel.rs:727-733`, `src/kernel.rs:4288` | A cached use would be a use with no log line. That is one reason substituted answers are never cacheable. |
| An answer's expiry defaults to `Always`, which means never stored. A sub-request that answers `Always`, or `Denied`, makes its caller's answer `Always` too. A grant change has no golden thread. | ikigai-core 0.3.5 `src/repr.rs:146-149`, `src/endpoint.rs:661-662`, `src/endpoint.rs:686-691` | This is how the door's uncacheability is enforced and how it carries into compositions. |
| The kernel enforces a declared `requires` before dispatch. Writes already declare `urn:cap:kernel:cut` this way. | `src/lib.rs:1119-1121`; test `writes_without_cut_authority_are_denied_before_transport` (`src/lib.rs:2003`); ikigai-log 0.11.0 `src/endpoints.rs:27-31` | The door declares its scopes the same way, so a caller without them never reaches it. |
| ikigai-log appends through `LogHandle::write`, which answers `Ok(None)` when no segment is open. Its door line (`log:Access`) keeps credentials out by construction, and a module adds entry classes with `rdfs:subClassOf`. `urn:log:write` needs `urn:cap:log:write` and refuses a caller-supplied `principal`. | ikigai-log 0.11.0 `src/endpoints.rs:620-641`, `src/access.rs:26-31`, `src/lib.rs:20-23`, `src/endpoints.rs:91`, `src/endpoints.rs:100-115` | The use line is a new class, written by a host-injected seam rather than by a sub-request under the caller. |

## The shape of the solution

There are three parts, and each is a seam the host fills in, like `HttpTransport` (`src/lib.rs:771-775`):

- **`SecretSource`** hands the door a secret's bytes by name. A host adapts it to
  `ikigai_secret::Backend::get` (ikigai-secret 0.4.0 `src/lib.rs:65-71`). The caller never
  touches this path. The door calls it only after every check has passed.
- **`RuleStore`** holds the rules: the atoms below.
- **`EgressAudit`** writes one use line per call. A host adapts it to `LogHandle::write`.

The door endpoints share the existing endpoint's send path for the capability check, the
redirect loop, the status table and bounded collection. Today that path is the body of
`HttpEndpoint::invoke` (`src/lib.rs:820-1047`). The implementation extracts it into a private
function that takes a redirect policy and a cache policy. The plain endpoints keep their
current behavior, and the door uses the stricter policies. This keeps one copy of the ACL and
the redirect code, the same way `auth` keeps one copy of header building.

## Resource map

Names are singular and type-first, and every partition is keyed by name.

| IRI | Kind | Verbs | Declares |
|---|---|---|---|
| `urn:http:egress:get`, `:head`, `:post`, `:put`, `:patch`, `:delete`, `:propfind`, `:report` | composition: the door, which holds no state | each method's existing verb (`Method::verb`, `src/lib.rs:363-372`) | `urn:cap:net:*`, `urn:cap:secret:use:*`, plus `urn:cap:kernel:cut` for the four mutating methods |
| `urn:http:egress:rule:id:{id}` | **atom**: one rule, versioned | `source`, `sink` (create or replace), `delete` | `source`: `urn:cap:egress:rule:read`. `sink` and `delete`: `urn:cap:egress:rule:write` |
| `urn:http:egress:rule:secret:{name}` | composition: the rules naming one secret | `source` | `urn:cap:egress:rule:read` |
| `urn:http:egress:rule:host:{host}` | composition: the rules for one host | `source` | `urn:cap:egress:rule:read` |
| `urn:http:egress:rule` | composition: every rule, listed | `source` | `urn:cap:egress:rule:read` |

The only state this design adds is the rules. The secret stays an atom of ikigai-secret
(`urn:secret:{name}`), and the use lines are ikigai-log's.

### The rule

A rule says: this secret may be placed here, for requests to this endpoint. Its fields:

| Field | Meaning |
|---|---|
| `id` | The `{id}` key. `[a-z0-9][a-z0-9-]*`, and never starting with `-`, so a scope naming it can never be read as an exclusion (ikigai-core 0.3.5 `src/capability.rs:179-195`). |
| `version` | A counter that goes up by one on every write. A replace must name the version it replaces. |
| `secret` | `urn:secret:<name>`. The name follows ikigai-secret's rule that it must not start with `-` (ikigai-secret 0.4.0 `src/lib.rs:440-462`). |
| `placement` | Exactly one of: `{"authorization": "bearer"}`; `{"authorization": "basic", "user": "<literal>"}` (the secret is the password); `{"authorization": "basic", "user_is_secret": true}` (the secret is the user id and the password is empty, as some APIs use an API key); `{"header": "<Name>"}`; `{"query": "<param>"}`. |
| `host` | An exact host, normalized as the net ACL normalizes (`src/lib.rs:588-605`). Globs are not allowed. |
| `port` | Default 443. |
| `methods` | A non-empty set of the `Method` tokens (`src/lib.rs:346-357`). |
| `path` | A path prefix, matched by whole segments as the net ACL matches (`/api` does not match `/apixyz`). |
| `echo` | `refuse` (the default) or `redact`. See "Echoes". |
| `valid_from`, `valid_until` | The validity window, read on the kernel clock. |
| `owner`, `approver`, `reason` | Principal IRIs and a sentence, as the organizational-grants model's assignments carry them. |

The scheme is not a field: it is always `https`. Example:

```json
{
  "id": "github-api-read",
  "version": 3,
  "secret": "urn:secret:github-token",
  "placement": { "authorization": "bearer" },
  "host": "api.github.com",
  "port": 443,
  "methods": ["GET", "HEAD"],
  "path": "/repos/ikigai-rs",
  "echo": "refuse",
  "valid_from": "2026-11-14T00:00:00Z",
  "valid_until": "2027-02-14T00:00:00Z",
  "owner": "urn:agent:brian",
  "approver": "urn:agent:reviewer",
  "reason": "The triage agent reads issues and pull requests in ikigai-rs."
}
```

Rule edits follow the grants model's rules (from the hub spike that drives this work: every
edit is a proposal with a diff, and widening needs a second person):

- **Create** fails with `Conflict` if the id already exists. **Replace** must carry
  `version=<n>` equal to the stored version, or it fails with `Conflict`. That rules out the
  `--force` accident in which one write replaced a whole grant.
- A write **widens** when the new rule covers a request the old one did not: a new host,
  port or method, a shorter path prefix, a longer window, a different secret or placement,
  or `echo` moving from `refuse` to `redact`. A widening write is `Denied` unless `approver`
  names a principal other than the writer's. A narrowing write needs one person.
- `delete` is idempotent and is never a widening.

## The use capability, and how it differs from read

| Scope | Grants |
|---|---|
| `urn:cap:secret:read:<name>` (ikigai-secret's) | The secret's bytes, returned to the caller. |
| `urn:cap:secret:use:<name>` (new) | Having the door place the secret for a request that some rule for `<name>` covers. It never returns the bytes. |

They are independent: `use` does not imply `read`, and `read` does not imply `use`. A caller
that can read a secret could send it by hand anyway, but it goes through the door like
everyone else, so the use is logged and the rule applies. The door declares
`urn:cap:secret:use:*` and checks the exact name with `Capability::allows`. This is the same
two-step pattern as ikigai-secret's read face (ikigai-secret 0.4.0 `src/lib.rs:488-497`). An
exclusion spelled `urn:cap:secret:use:-<name>` keeps working through attenuation, because
exclusions are sticky (ikigai-core 0.3.5 `src/capability.rs:379-386`).

Using a secret also needs the net grant for the target, checked under the caller's capability
exactly as today. A use grant never widens the network: the rule narrows where the secret may
go, and `urn:cap:net` still decides where the caller may go.

A use needs a principal. A capability with no principal (ikigai-core 0.3.5
`src/capability.rs:452-457`) is `Denied`, because a log line that cannot name who used a
secret does not do its job.

## How a reference is spelled

A reference is the exact text `urn:secret:<name>`, used as an entire value. It is never part
of a longer value, and no template syntax exists. It may appear only at the one position the
covering rule's `placement` names:

| Placement | Spelling | What the door sends |
|---|---|---|
| `authorization: bearer` | `authorization=urn:secret:github-token` | `Authorization: ` followed by `auth::bearer(value)` (`src/auth.rs:187`) |
| `authorization: basic` | `authorization=urn:secret:jira-password` | `auth::basic(rule.user, value)` (`src/auth.rs:149`) |
| `header: X-Api-Key` | `headers="X-Api-Key: urn:secret:maps-key"` | `X-Api-Key: <value>` |
| `query: key` | `url=https://maps.example.com/v1/geocode?q=Paris&key=urn:secret:maps-key` | The value of `key`, after percent-decoding, is the reference. The door percent-encodes the secret into that parameter and leaves every other byte of the URL as written. |

The door refuses with `InvalidArgument`:

- a reference anywhere else: in the path, the fragment, the host, another header, another
  query parameter, `content=`, or inside a longer value such as `Bearer urn:secret:x`. The door
  searches every argument for `urn:secret:`, so a reference that would otherwise be sent as
  literal text gets a sentence instead;
- more than one reference in one call (one call uses one secret);
- a literal credential in the same position as a reference, such as a second
  `Authorization` in `headers=` beside `authorization=`. The current header builder would send
  both (`src/lib.rs:1293-1317`);
- a `url` whose scheme is not `https`;
- `max_age=`, which asks for caching the door never does.

**Bodies are not a placement.** `content=` is sent exactly as given and must not contain a
reference. Substituting into a body would need an encoder for each content type (JSON string
escaping, form encoding, XML), and each encoder is one more place where the value can leak or
be mangled. The use case people reach for first, an OAuth client secret, does not need a
body: RFC 6749 §2.3.1 requires authorization servers to accept client credentials through
HTTP Basic, and `authorization: basic` covers that. Token introspection (RFC 7662) sends the
token in a form body and is therefore out of scope for the first version (decision 5).

### Order of checks

The order matters, because a refusal must not reveal more than the caller is entitled to know.

1. Parse the arguments and find the single reference. Errors are `InvalidArgument`.
2. Check `urn:cap:secret:use:<name>` and the principal, and refuse with `Denied` without
   consulting the rule store or the secret source. A caller without the grant cannot learn
   whether the rule or the secret exists, which matches ikigai-secret's own ordering
   (ikigai-secret 0.4.0 `src/lib.rs:465-470`).
3. Find a rule for `<name>` that covers this method, host, port, path and placement and is
   valid now. If no rule names the secret, the answer is `NotFound`. If rules exist but none
   covers the request, it is `Denied`.
4. Run the net ACL for the first hop under the caller's capability (`src/lib.rs:876-888`). A
   failure is `Denied`.
5. Fetch the value from `SecretSource`. An absent secret is `NotFound`.
6. Place it through `auth` or the header and query rules above. A value that does not fit is
   `Conflict` (see below).
7. Send, follow redirects under the door's policy, and map the status through
   `ikigai_http::status`.
8. Scan the answer for echoes, then write the use line and answer.

## Redirects

A redirect is where a placed credential most easily reaches a host nobody vetted. Today the
endpoint strips only three header names on an origin change (`src/lib.rs:934-942`), and only
for GET and HEAD. The door's policy is stricter:

| Redirect | Door's answer |
|---|---|
| Any method that sends a body | Refused, as today (`src/lib.rs:914-923`): `Endpoint`, naming the status and method. The `Location` is scrubbed. |
| GET or HEAD, same scheme, host and port, to a path the **same rule** covers, with an `authorization` or `header` placement | Followed. The secret is placed again on the new hop, the net ACL runs again, and the 5-hop limit applies. |
| The same, but the path is outside the rule | `Denied`: "the egress rule for urn:secret:NAME does not cover GET api.example.com/other, the redirect target". |
| To another host or port | `Denied`. Nothing is sent to the target. |
| Downgrade to `http`, same host or not | `Denied`: "a secret is sent only over https; the redirect target is http". The plain endpoints follow this hop after stripping three headers. The door does not follow it at all. |
| Any redirect when the placement is `query` | `Denied`. The door would have to decide whether to put the secret into a query the origin wrote, and it never does that. |

Every redirect refusal names the method, the host and the path of the target, and never its
query, because an origin that echoes the credential can echo it into a `Location`.

## Echoes

An origin can send the credential back in a token-introspection reply, a "who am I" endpoint,
a debug page or a reflected header. Error statuses are already safe, because their bodies are
dropped unread (`src/lib.rs:1008-1021`). Successful answers are scanned.

**What is scanned.** The response headers, and the body collected under the endpoint's byte
limit (`src/lib.rs:1036`). HEAD has no body to scan. The door sends `Accept-Encoding: identity`,
and an answer with any other `Content-Encoding` is refused with `Conflict`, because a
compressed body cannot be scanned.

**What it looks for.** The raw value, and each encoding of it the door itself produced or an
origin commonly reflects:

- the raw bytes;
- `Authorization::credentials()` for Basic, which is base64 of `user:password`
  (`src/auth.rs:84-95` says a scrubber must include it);
- standard base64 of the raw value (`ikigai_http::base64::encode`);
- the percent-encoded form, which is the one a query placement sent;
- the JSON-escaped form, if escaping changes the value.

**What happens.** With `echo: refuse`, the default, the answer is withheld with `Conflict`.
The message says the request was sent and which status the origin answered, because for a
write the change has already happened. 0.7.0 fixed the same kind of misreport for cut
authority (CHANGELOG.md, "0.7.0"). With `echo: redact`, each occurrence is replaced by
`[redacted urn:secret:NAME]`, and the representation carries the type parameter
`egress-redacted=<count>` so a caller can tell the answer was altered. Redaction is opt-in per
rule, for endpoints whose answers are useful apart from the echoed token.

**Error text.** Every error the door returns passes through the same scrubber, and the
transport's text in particular. `tests/egress_facts.rs` pins that this text currently carries
the full URL, query included. The scrubber also covers the scrubbed `Location`, and the
message of any error raised by the shared send path.

A secret shorter than 16 bytes is refused when a rule naming it is created, and again at use
(`Conflict`). Below that length a substring search gives false positives, and the redaction
markers start to reveal where short values happen to appear.

## HTTP Basic and Bearer through the existing auth code

The door does not format a scheme itself. `authorization: bearer` calls `auth::bearer`, and
`authorization: basic` calls `auth::basic` (`src/auth.rs:149-197`). Both functions already
refuse values that cannot be sent, and their errors name the broken rule and never the value
(`src/auth.rs:288-338`). The door turns an `AuthError` into a `Conflict` that carries the
error's stable code, for example "the stored secret urn:secret:NAME cannot be sent as a Bearer
token (bearer-token-syntax)". It is a `Conflict` and not `InvalidArgument` because the fault
is in the stored state, not in anything the caller passed. A secret that is not UTF-8 is a
`Conflict` for every placement, since every placement is text. The built `Authorization`
leaves only through `into_string()` into the header list, which `src/auth.rs:10-15`
describes as the one place it goes.

## Caching

**A substituted request is never cacheable.** That holds for every method, including GET and
HEAD, and for every answer, including a cached failure. There are four reasons:

1. **Every use must be logged.** The kernel serves a hit before the endpoint runs (ikigai-core
   0.3.5 `src/kernel.rs:727-733`), so a cached answer would be a use with no line.
2. **Revocation has no thread.** Removing a use grant, editing a rule or rotating a secret
   cuts nothing, and "a grant change has no thread" (ikigai-core 0.3.5
   `src/endpoint.rs:661-662`). A cached answer would outlive the authority that produced it
   until its deadline.
3. **The answer is the secret's data.** What an API returns under a credential belongs to the
   credential's owner. Storing it puts it in the kernel's store, where nobody reviews it,
   beside answers computed with no credential at all.
4. **Today's path would cache it.** `tests/egress_facts.rs` pins that a credentialed GET is a
   cache hit on its second call. The door cannot inherit that behavior.

It is enforced in four ways:

- The door builds every answer with `Representation::new`, whose expiry defaults to `Always`
  (ikigai-core 0.3.5 `src/repr.rs:146-149`). The door's cache policy in the shared send path
  never calls `cacheable_until`, `validated_by` or `depends_on` (`src/lib.rs:1338-1350`,
  `src/lib.rs:1411-1417`), never states `failure_expires_in` (`src/lib.rs:805-815`), and
  ignores a stale offer, so it never sends `If-None-Match` (`src/lib.rs:843-858`).
- The door refuses `max_age=` (see "How a reference is spelled").
- A composition over the door is uncacheable without doing anything, because a sub-request
  that answers `Always` makes its caller `Always` (ikigai-core 0.3.5 `src/endpoint.rs:686-691`).
- Tests assert that the expiry is `Always` and that two identical calls reach the wire twice
  and write two lines. The conformance suite declares every door action live, so a door
  answer that quietly becomes cacheable fails `CACHEABLE`, which is the polarity the suite
  already uses for live reads (README.md, "Conformance").

Rule reads are cacheable. A rule answer depends on the thread `urn:http:egress:rule:id:{id}`,
and a rule write cuts that thread. The door reads rules from `RuleStore` directly and never
through the cache, so an edit takes effect on the next use.

## The use line

There is one line per door call that passed step 2, whatever the outcome. A refusal at step
2 is the kernel's or the door's `Denied`, which ikigai-log already records as
`log:CapabilityDenied` (ikigai-log 0.11.0 `src/endpoints.rs:33-51`).

```text
2026-11-14T09:14:22.031Z log:EgressUse urn:secret:github-token principal=urn:agent:triage rule=urn:http:egress:rule:id:github-api-read method=GET host=api.github.com path=/repos/ikigai-rs/ikigai-http/issues outcome=ok status=200
```

`log:EgressUse` is declared as an `rdfs:subClassOf` a log class in the vocabulary extension
(ikigai-log 0.11.0 `src/lib.rs:20-23`). It never carries the value, any encoding of it, the
query string, any request header or the body. `outcome` is `ok`, `redacted`, or the error's
kind token. `EgressAudit` takes a struct with exactly these fields, so there is nowhere to put
anything else, which is how `log:Access` keeps credentials out (ikigai-log 0.11.0
`src/access.rs:26-31`).

The seam is host-injected rather than a sub-request to `urn:log:write`. That endpoint
requires `urn:cap:log:write` (ikigai-log 0.11.0 `src/endpoints.rs:91`), and a caller should
not need log authority to use a secret. If the audit seam fails, or `LogHandle::write` answers
`Ok(None)` because no segment is open (ikigai-log 0.11.0 `src/endpoints.rs:620-641`), the door
refuses before it sends anything. The line is written in two steps: an `outcome=sending`
reservation before the request and the final line after it. A crash in between leaves a
reservation with no close, which is evidence that a use happened.

## Failures and refusals

All messages are sentences without backticks (ACCESSIBILITY.md records backticks in
refusals as a current Fail). Each names the method, host and path when there is one, and
never the value.

| Kind | When | Example text |
|---|---|---|
| `InvalidArgument` | A reference in a position no placement allows, or inside a longer value; two references; a literal credential beside a reference; a non-https `url`; `max_age=`; a malformed or deny-shaped name | "urn:secret:maps-key appears in the path; a secret reference may only be a whole header value or a whole query parameter value" |
| `Denied` | No use grant for the name; no principal; rules for the secret exist but none covers this method, host, port and path, or none is valid now; the net ACL refuses; a redirect the door's policy refuses; a widening rule write with no second person | "no egress rule lets urn:secret:github-token be sent with POST to api.github.com/repos" |
| `NotFound` | The caller holds the use grant but no rule names the secret; the secret is absent from the store; `urn:http:egress:rule:id:{id}` does not exist | "no egress rule names urn:secret:github-token" |
| `Conflict` | The stored value does not fit the placement (an `AuthError`, non-UTF-8, shorter than 16 bytes); an echo under `echo: refuse`; a compressed answer; a rule write whose `version` is stale, or a create whose id exists | "the request was sent and api.example.com answered HTTP 200, but the answer contains the credential, so it is withheld" |
| `Endpoint` | The audit seam failed or logging is closed; a body-sending method got a redirect (as today) | "the use of urn:secret:NAME could not be logged, so the request was not sent" |
| status table | The origin's own status, through `ikigai_http::status` unchanged (`src/status.rs`) | "refused: HTTP 401" |

## Tests that would prove it

Each test runs over a recording transport like the existing `Record` and `Seq` doubles
(`src/lib.rs:2536-2563`, `src/lib.rs:3070-3090`), a counting `SecretSource` and a capturing
`EgressAudit`.

1. **Substituted for an allowed endpoint.** A caller with `use:github-token`, a net grant and
   a principal, matching a bearer rule, sends `authorization=urn:secret:github-token`. The
   transport sees `Authorization: Bearer <value>` built by `auth::bearer`, and the answer is the
   origin's body. The same test runs for the basic, header and query placements.
2. **Refused for another endpoint.** The same caller and rule, with POST, with another host,
   and with a path outside the prefix: each is `Denied`, the transport records nothing, and the
   secret source counts zero fetches for the host case (the rule check happens before the fetch).
3. **The caller sees no secret.** After tests 1 and 2, the value and each encoding the
   scrubber knows are absent from the answer bytes, its type parameters, every error string,
   every `Debug` output, every audit line and the kernel trace.
4. **No use grant is Denied.** A caller holding `urn:cap:secret:read:github-token` but not
   `use` is `Denied`. So is a caller holding `urn:cap:secret:use:github-token` together with
   the exclusion `urn:cap:secret:use:-github-token`. The rule store and the secret source are consulted zero times, and nothing reaches the wire.
5. **Use does not grant read.** A caller with only `use:github-token` sourcing
   `urn:secret:github-token` through ikigai-secret is `Denied`.
6. **Never cached.** Two identical door GETs against an origin answering `max-age=600` give
   two wire requests and two audit lines, and the answer's expiry is `Always`. A composition
   that sources the door twice reaches the wire twice. This is the mirror of
   `a_get_carrying_a_credential_is_cached_today`.
7. **Redirects.** A same-origin redirect inside the rule is followed with the secret placed
   again. Cross-host, out-of-rule-path, downgrade, and any redirect under a query placement are
   `Denied`, with exactly one request on the wire. The error text holds no query from the
   `Location`.
8. **Echoes.** An answer that reflects the raw value, the Basic credentials or the
   percent-encoded value is `Conflict` under `refuse`. Under `redact` it is served with every
   occurrence replaced and `egress-redacted=<n>`. A `Content-Encoding: gzip` answer is
   `Conflict`.
9. **Scrubbed transport errors.** The `NamesTheUrl` transport from `tests/egress_facts.rs`
   behind the door, with a query placement: the error text names the failure and not the value.
10. **Logging is required.** A closed log or a failing seam means nothing is sent, and the
    answer is the `Endpoint` refusal.
11. **Rule edits.** A stale `version` is `Conflict`. A widening write approved by the writer
    is `Denied`, and with a second approver it succeeds. A narrowing write by one person
    succeeds. A rule read is cut by a rule write.
12. **Conformance.** `ikigai-conformance` walks the door space, with every action declared
    live and every declared scope enforced.

## Migration

Nothing published changes. The door is a new family of IRIs, new scopes, a new log class and
three new host seams, all additive, so it ships as a minor release (0.8.0). The existing
`urn:http:*` endpoints keep their behavior, including caching a credentialed GET and
following an https-to-http redirect without its credentials. `tests/egress_facts.rs` keeps
pinning both facts. The internal extraction of the send path from `HttpEndpoint::invoke` must
leave every existing test passing unchanged. When the door ships, ACCESSIBILITY.md's "What it
emits" gains the door's refusals and the use line, and README.md gains a section.

If decision 4 goes the other way and references are accepted by the existing endpoints, a
published behavior changes: an `authorization=urn:secret:x` that is sent literally today would
be substituted. That would need its own CHANGELOG entry and a minor release.

## Decisions for Brian

1. **Where the value comes from.** (a) A host-injected `SecretSource` the door calls after
   its checks, or (b) a sub-request to `urn:secret:<name>`, which runs under the caller's
   capability (ikigai-core 0.3.5 `src/endpoint.rs:1500-1506`) and so needs the caller to hold
   `read`, which is the thing this design exists to avoid, or (c) a new core feature giving an
   endpoint authority its caller lacks, which core currently rules out on purpose
   (`src/endpoint.rs:1565-1580`). **Recommend (a).** It is the same trust a host already gives
   its transport.
2. **The use scope's spelling.** `urn:cap:secret:use:<name>`, where a grant lets a caller use
   the secret wherever any of its rules applies, or `urn:cap:egress:use:<rule-id>` per rule.
   **Recommend per name.** It sits beside ikigai-secret's `read:` and `write:`, an exclusion
   works the same way, and a secret that needs two audiences can be stored twice under two
   names.
3. **Does use also need the net grant?** **Recommend yes.** The rule narrows where the secret
   may go, and `urn:cap:net` still decides where the caller may go. Neither widens the other.
4. **A separate door, or references on the existing endpoints?** **Recommend a separate
   `urn:http:egress:*` family.** Its contract differs: never cacheable, a stricter redirect
   policy, echo scanning and a required principal. Keeping it apart changes nothing published
   and lets a host mount one without the other.
5. **Bodies.** **Recommend no body placement in the first version.** OAuth client credentials
   go through Basic (RFC 6749 §2.3.1). Token introspection and other body-only APIs wait for
   a separate design with one encoder per content type.
6. **Redirects.** **Recommend the table in "Redirects"**: follow only same-origin https GET
   and HEAD redirects that stay inside the same rule with a header placement, and refuse the
   rest with `Denied`. The simpler alternative, following no redirect at all, breaks APIs that
   redirect for a trailing slash.
7. **The echo default.** **Recommend `refuse`**, with `redact` opt-in per rule and counted as
   a widening.
8. **A minimum secret length.** **Recommend 16 bytes**, enforced when a rule is created and
   again at use.
9. **Logging is required.** **Recommend fail-closed**: no audit seam, or a closed log, means
   no substitution. It also means using the `sending` reservation line.
10. **A principal is required.** **Recommend yes.** An anonymous capability can never use a
    secret.
11. **Rule hosts are exact and https-only.** **Recommend no globs.** A secret should go to
    hosts someone named one by one. Port 443 is the default.
12. **Rule storage and review.** A host-injected `RuleStore` now, with a version precondition
    and a second person for widening. When the grants graph lands, a rule becomes an
    assignment-like node and its edits become that model's proposals. **Recommend building the
    store seam now and not waiting for the graph.**
13. **Budgets.** Later, a rule may carry a quantity that each use spends, refused at the door
    when it reaches zero, as the grants model's budgets are. **Recommend leaving this out of
    the first version** and keeping a place for it in the rule's shape.
