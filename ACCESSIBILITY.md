# Accessibility

What `ikigai-http` emits that people read, the rules that output follows, how it is tested, and
how to report a barrier. It is an outbound HTTP-client module: what it answers on success is the
origin's own content, and what it writes itself is error text, which a host prints or serves. It
is not a conformance claim. Adapted from the [ACCESSIBILITY.md
template](https://github.com/mgifford/ACCESSIBILITY.md) (MIT).

| Field | Value |
|---|---|
| Target | WCAG 2.2 Level AA, for any page that presents this output; this repository writes text only |
| Status | Evaluation in progress. No conformance claim. |
| Owner | the maintainers of this repository |
| Report a barrier | [a GitHub issue](https://github.com/ikigai-rs/ikigai-http/issues/new?labels=accessibility) with the `accessibility` label; anything security-sensitive through [private vulnerability reporting](https://github.com/ikigai-rs/ikigai-http/security/advisories/new) |
| Last reviewed | 2026-10-31 |

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
- **Endpoint descriptions**: the titles and summaries of the eight method endpoints, read in the
  catalog.

Not this repository's: the body an origin answers with, which is served as the origin labeled
it, and the page or terminal a host shows any of this in. Nothing here writes HTML, SVG, color or
a terminal screen.

## The rules that output follows

Verified by reading the source on 2026-10-31:

- A failure is typed, and its displayed text begins with its kind in words (`not found:`,
  `refused:`, `timeout:`, `retry later:`), never a status number alone; an origin's error page is
  never served as if it were the resource.
- A denial names what was refused: the method, the host and the path.
- An error about a credential never repeats the credential.
- No color, escape sequence or markup is written.

## How it is tested

- `src/status.rs`'s unit tests (`every_row_of_the_table` and others) pin each status's typed
  error, and its doctests pin displayed forms (`refused: HTTP 403`, `retry later: rate-limited:
  HTTP 429`, `retry after 120000 ms: rate-limited: HTTP 429`).
- `src/lib.rs`: `a_redirect_to_an_ungranted_host_is_a_typed_denial` pins that the denial names
  the redirect.
- `tests/auth_vectors.rs`: `basic_refuses_with_the_pinned_code_and_never_echoes_the_password`.
- `tests/range_vectors.rs` pins the range error codes against `tests/vectors/range_vectors.json`.
- **No automated accessibility checker, browser or assistive technology has been used on this
  output.**

## Known limitations

Found by reading the source on 2026-10-31, not by testing:

- A status failure's text is only its kind and `HTTP <status>`: it names no URL, and the origin's
  own explanation in its error body is dropped, so a person reading it in a composite cannot tell
  which request failed or why.
- A range `ParseError` displays as a bare code (`invalid`, `weak-validator`), not a sentence.
- Some messages wrap names in backticks, Markdown punctuation that a screen reader may read aloud
  in a plain-text face; the redirect refusal is written as a parenthetical inside one long line.

## Contributing

Read this file before changing any output listed above: the status table's errors, a denial, a
header or range error. Keep meaning in words, name the request a message is about, never echo a
credential, and say in the pull request what was tested and what was not.

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
