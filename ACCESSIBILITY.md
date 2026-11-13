# Accessibility

What `ikigai-http` emits that people read, the rules that output follows, how it is tested, and
how to report a barrier. It is an outbound HTTP-client module: what it answers on success is the
origin's own content (except HEAD's existence answer), and it also writes error text, which a
host prints or serves. It is not a conformance claim. Adapted from the [ACCESSIBILITY.md
template](https://github.com/mgifford/ACCESSIBILITY.md) (MIT).

| Field | Value |
|---|---|
| Target | WCAG 2.2 Level AA, for any page that presents this output; this repository writes text only |
| Status | Evaluation in progress. No conformance claim. |
| Owner | the maintainers of this repository |
| Report a barrier | [a GitHub issue](https://github.com/ikigai-rs/ikigai-http/issues/new?labels=accessibility) with the `accessibility` label; anything security-sensitive through [private vulnerability reporting](https://github.com/ikigai-rs/ikigai-http/security/advisories/new) |
| Last reviewed | 2026-11-12 |

## What it emits that people read

- **Failures of a request** (`src/lib.rs`, `src/status.rs`), as typed `ikigai_core::Error`s: a
  non-success status (`not found: HTTP 404`, `retry later: rate-limited: HTTP 429`, from the one
  table in `ikigai_http::status`), a transport failure (`http transport: …`), a capability denial
  that names the method and the host and path (and says when it was a redirect target), a
  redirect a body-sending method does not follow (naming the status, the method and the
  `Location`), too many redirects, and a URL argument that does not parse or has no host.
- **Header and encoding errors**: `AuthError` (`src/auth.rs`), sentences that cite RFC 7617 or
  RFC 6750 and never echo the credential; `Base64Error` (`src/base64.rs`); and the range
  `ParseError` (`src/range.rs`), whose `Display` is a short code (`invalid`, `too-large`,
  `unsupported-unit`) that echoes no input.
- **Existence answers**: HEAD returns the plain-text word `true` or `false` for presence
  (`src/lib.rs`); a 304 without a conditional revalidation returns empty metadata instead.
- **Documentation**: `README.md`, this file, contributor guidance and Rust API documentation,
  read on GitHub, in an editor or through rustdoc.
- **Endpoint descriptions**: the titles and summaries of the eight method endpoints, read in the
  catalog.

Not this repository's: the body an origin answers with, which is served as the origin labeled
it, and the page or terminal a host shows any of this in. Nothing here writes HTML, SVG, color or
a terminal screen.

## The rules that output follows

These are contribution rules, not a claim that every output meets them. Current results and
limitations are recorded below.

- A failure is typed, and its displayed text should explain its kind in words, never a status
  number alone; an origin's error page must not be served as if it were the resource.
- A denial names what was refused: the method, the host and the path.
- An error about a credential never repeats the credential.
- Meaning is in words, without relying on color, escape sequences or markup. Hosts must decide
  how to safely present interpolated transport errors and origin-supplied values.

## How it is tested

Every named check has a result: Pass, Fail or Blocked, with evidence. A Pass covers only the
stated check, not overall accessibility. Fail records an observed limitation, not a WCAG
conformance determination. Blocked means the check has not been completed.

The current tests and source review below ran on 2026-11-12 against main commit
[`13b8cd84fb830f121a0472cba265f40fcf20656a`](https://github.com/ikigai-rs/ikigai-http/tree/13b8cd84fb830f121a0472cba265f40fcf20656a),
before this documentation change. `cargo test` passed with Cargo 1.99.1 and rustc 1.99.1.
The repository's pull-request CI runs Rust checks via
[the CI workflow](.github/workflows/ci.yml); it does not repeat the manual source review or
assistive technology checks. The 2026-10-31 source review is historical context, not a current
Pass; the source-review rows below record a fresh inspection.

| Check | Result | Evidence |
|---|---|---|
| Historical source review (2026-10-31) | Blocked | The previous record described source inspection only; no invocation or tool version was recorded, and CI does not repeat that review. Current checks below supersede it. |
| Typed HTTP status errors and displayed kinds | Pass | `cargo test`: `src/status.rs` unit tests, including `every_row_of_the_table`, and status doctests pin typed mappings and displayed examples such as `refused: HTTP 403` and retry timing. `src/lib.rs`'s `get_maps_status_onto_the_typed_error_taxonomy` checks endpoint errors. Covers tested mappings and strings, not comprehension in a host. |
| Redirect denial identifies the refused request | Pass | `cargo test`: `src/lib.rs`'s `a_redirect_to_an_ungranted_host_is_a_typed_denial` checks the type and `redirect target` wording. Manual source review of `HttpEndpoint::invoke` confirms the denial includes method, host and path. The test does not assert all those fields or evaluate spoken output. |
| Credential errors do not echo credentials | Pass | `cargo test`: `tests/auth_vectors.rs`'s `basic_refuses_with_the_pinned_code_and_never_echoes_the_password` and `bearer_refuses_everything_else_without_echoing_it`, plus `src/base64.rs`'s `a_decode_error_never_echoes_its_input`. Manual review of `AuthError::fmt` and `Base64Error::fmt` confirms fixed explanations. Covers these helpers, not arbitrary host transport error strings. |
| Range error codes remain stable and omit input | Pass | `cargo test`: `tests/range_vectors.rs` checks shared vectors in `tests/vectors/range_vectors.json`; manual review of `src/range.rs`'s `ParseError::fmt` confirms it writes only `code()`. Does not establish that the codes are understandable. |
| HEAD existence answer uses words | Pass | `cargo test`: `src/lib.rs`'s `head_existence_is_lenient_only_404_410_are_absent`; manual review of the HEAD branch confirms plain `true` / `false` output. Does not check how a host labels that answer or presents 304 metadata. |
| Module-authored text conveys meaning without color or terminal controls | Pass | Manual source review of error construction and endpoint descriptions in `src/lib.rs`, `src/status.rs`, `src/auth.rs`, `src/base64.rs` and `src/range.rs` on 2026-11-12. Fixed text uses words and adds no color or terminal controls. This does not cover interpolated host errors, URLs, headers, origin bodies or host rendering. |
| Status errors identify which request failed and explain why | Fail | Manual review of `HttpEndpoint::invoke` on 2026-11-12: it passes only `HTTP <status>` as detail to `status::response_error` and discards the origin error body. `get_maps_status_onto_the_typed_error_taxonomy` pins examples such as `refused: HTTP 403`; no request URL or origin explanation is included. |
| Range errors explain the problem in a sentence | Fail | Manual review of `ParseError::fmt` on 2026-11-12: only a bare code such as `invalid` or `weak-validator` is displayed, as pinned by `tests/range_vectors.rs`. |
| Plain-language punctuation and redirect readability | Fail | Manual review on 2026-11-12: denial and authentication strings contain backticks; the body-sending redirect refusal in `HttpEndpoint::invoke` is one long line with a parenthetical. No spoken-output evaluation was performed. |
| Documentation and catalog presentation | Blocked | No rendered GitHub, rustdoc or host catalog evaluation was performed. Source inspection of endpoint descriptions does not establish accessible headings, navigation or reading order in those interfaces. |
| Automated accessibility checker | Blocked | No axe or equivalent checker was run. No rendered host interface was selected for this library evaluation; Rust tests do not evaluate rendered accessibility. |
| Browser and terminal rendering, zoom, reflow and contrast | Blocked | No browser or terminal presentation evaluation was performed. A host interface and rendering setup must be selected to evaluate this text in context. |
| Manual keyboard | Blocked | No person performed a keyboard pass through a host interface presenting this output; no interactive host session was used. |
| Screen reader | Blocked | No screen reader was used on this output; no screen reader session with a host was available for this review. |
| Screen magnifier | Blocked | No screen magnifier was used on this output; no magnifier session with a host was available for this review. |
| Speech input | Blocked | No speech-input software was used on this output; no speech-input session with a host was available for this review. |
| Switch access | Blocked | No switch-access software was used on this output; no switch-access session with a host was available for this review. |
| Braille display | Blocked | No braille display was used on this output; no braille display was available for this review. |

## Known limitations

The Fail rows above record the current source-level limitations: status errors omit request
context, range errors are bare codes, and some messages use backticks or long parentheticals.
The Blocked rows are evaluation gaps. No assistive technology results are inferred from Rust
tests or source inspection. Origin content and the host's page or terminal need their own
accessibility evaluation.

## Contributing

Read this file before changing any output listed above: the status table's errors, a denial, a
header or range error. Keep meaning in words, name the request a message is about, never echo a
credential, and give each check in the pull request a `Check | Result | Evidence` table row:
Pass, Fail or Blocked, with the command or test, tool and version, or why it could not run.
Keep unrun checks Blocked, including assistive technology nobody used. A historical run that
CI does not repeat is Blocked with its date, not Pass.

## Reporting a barrier

[Open an issue](https://github.com/ikigai-rs/ikigai-http/issues/new?labels=accessibility) with the
`accessibility` label (the link sets it when GitHub lets you add labels; otherwise a maintainer
adds it): what you were doing, what happened, and your terminal or browser and any assistive
technology, if you are comfortable sharing them. Anything security-sensitive goes through
[private vulnerability reporting](https://github.com/ikigai-rs/ikigai-http/security/advisories/new).
**We acknowledge a report within 7 days**, and promise nothing further.

## Change history

| Date | Change |
|---|---|
| 2026-10-31 | First version. |
| 2026-11-12 | Record current tests and source review as Pass / Fail / Blocked; make unrun host and assistive technology checks explicit. |
