//! The host glob in the net ACL, `urn:cap:net:*.<suffix>` (ledger #35).
//!
//! Three layers: one table of (rules, host, port, path, expected) rows covering every
//! decision the module docs state, a deterministic generator checking properties over
//! label sets (there is no property-test crate in the dev graph, so a seeded xorshift
//! stands in), and the redirect path through the real endpoint.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ikigai_core::{ArgRef, Capability, Error, Iri, Kernel, Request, Verb};
use ikigai_http::{net_allows_port, space, HttpRequest, HttpResponse, HttpTransport};

fn cap(rules: &[&str]) -> Capability {
    Capability::root().attenuate(rules.iter().map(|r| format!("urn:cap:net:{r}")))
}

/// One row: the rules (without the `urn:cap:net:` prefix), the request, the answer.
struct Row {
    rules: &'static [&'static str],
    host: &'static str,
    port: Option<u16>,
    path: &'static str,
    allowed: bool,
    why: &'static str,
}

const fn row(
    rules: &'static [&'static str],
    host: &'static str,
    port: Option<u16>,
    path: &'static str,
    allowed: bool,
    why: &'static str,
) -> Row {
    Row {
        rules,
        host,
        port,
        path,
        allowed,
        why,
    }
}

const T: bool = true;
const F: bool = false;

#[rustfmt::skip] // one row per line reads as a table; rustfmt would explode each one
const TABLE: &[Row] = &[
    // 1. Label boundary.
    row(&["*.edu"], "mit.edu", None, "/", T, "one label under the suffix"),
    row(&["*.edu"], "a.b.mit.edu", None, "/", T, "several labels under the suffix"),
    row(&["*.edu"], "edu", None, "/", F, "not the suffix itself"),
    row(&["*.edu"], "notedu", None, "/", F, "same letters, no dot"),
    row(&["*.edu"], "xedu", None, "/", F, "same letters, no dot"),
    row(&["*.edu"], "mit.edu.evil.com", None, "/", F, "the suffix must END the host"),
    row(&["*.edu"], "edu.com", None, "/", F, "the suffix in the wrong place"),
    row(&["*.example.com"], "www.example.com", None, "/", T, "a multi-label suffix"),
    row(&["*.example.com"], "badexample.com", None, "/", F, "labels match whole"),
    row(&["*.example.com"], "example.com", None, "/", F, "not the suffix itself"),
    row(&["*.example.com"], "a.badexample.com", None, "/", F, "labels match whole, deeper"),
    // 2. Malformed globs grant nothing.
    row(&["foo*.com"], "foox.com", None, "/", F, "a mid-label star"),
    row(&["foo*.com"], "foo*.com", None, "/", F, "a mid-label star is not a literal either"),
    row(&["*foo.com"], "xfoo.com", None, "/", F, "a leading partial-label star"),
    row(&["*foo.com"], "a.foo.com", None, "/", F, "`*foo` is not `*.foo`"),
    row(&["a.*.com"], "a.b.com", None, "/", F, "an inner star"),
    row(&["*.*.com"], "a.b.com", None, "/", F, "more than one star"),
    row(&["*"], "example.com", None, "/", F, "a bare star"),
    row(&["*."], "example.com", None, "/", F, "a star and a dot"),
    row(&["**.com"], "a.com", None, "/", F, "a double star"),
    row(&["*.edu*"], "mit.edu", None, "/", F, "a star in the suffix"),
    row(&["*..edu"], "mit.edu", None, "/", F, "an empty label in the suffix"),
    row(&["mit.edu", "foo*.com"], "mit.edu", None, "/", T, "a malformed ALLOW is ignored; the rest still grants"),
    // 2b. A malformed DENY refuses the whole check, since skipping it would widen.
    row(&["mit.edu", "-foo*.mit.edu"], "mit.edu", None, "/", F, "malformed deny: refuse everything"),
    row(&["mit.edu", "-a.*.com"], "mit.edu", None, "/", F, "malformed deny elsewhere still refuses"),
    row(&["*.edu", "-*"], "mit.edu", None, "/", F, "a bare-star deny refuses"),
    row(&["*.edu", "-**.edu"], "mit.edu", None, "/", F, "a double-star deny refuses"),
    row(&["example.com", "-example.com:99999"], "example.com", Some(443), "/", F, "an out-of-range deny port refuses everything"),
    row(&["example.com", "-example.com:nope"], "example.com", Some(443), "/", F, "a nonnumeric deny port refuses everything"),
    row(&["example.com", "-:443"], "example.com", Some(443), "/", F, "an empty deny host refuses everything"),
    row(&["example.com", "-"], "example.com", None, "/", F, "an empty deny rule refuses everything"),
    row(&["example.com", "-example.com:"], "example.com", None, "/", F, "an empty deny port refuses everything"),
    row(&["example.com", "-elsewhere.com:99999/admin"], "example.com", None, "/", F, "a malformed deny refuses unrelated requests too"),
    row(&["example.com", "-*.com:99999"], "example.com", None, "/", F, "a glob deny with an invalid port refuses"),
    row(&["example.com", "example.com:99999"], "example.com", None, "/", T, "an out-of-range allow port is ignored"),
    row(&["example.com", "example.com:nope"], "example.com", None, "/", T, "a nonnumeric allow port is ignored"),
    row(&["example.com", ":443"], "example.com", None, "/", T, "an empty allow host is ignored"),
    row(&["example.com", ""], "example.com", None, "/", T, "an empty allow rule is ignored"),
    row(&["example.com", "example.com:"], "example.com", None, "/", T, "an empty allow port is ignored"),
    row(&["example.com:0"], "example.com", Some(0), "/", T, "port zero still parses"),
    row(&["example.com:65535"], "example.com", Some(65535), "/", T, "the largest port still parses"),
    // 3. Normalization, request host and rule suffix alike.
    row(&["*.edu"], "MIT.EDU", None, "/", T, "request host case"),
    row(&["*.EDU"], "mit.edu", None, "/", T, "rule suffix case"),
    row(&["*.edu"], "mit.edu.", None, "/", T, "request trailing dot"),
    row(&["*.edu."], "mit.edu", None, "/", T, "rule trailing dot"),
    row(&["*.edu"], "edu.", None, "/", F, "the suffix itself with a trailing dot"),
    row(&["*.bücher.de"], "shop.xn--bcher-kva.de", None, "/", T, "an IDN suffix as its A-label"),
    row(&["*.xn--bcher-kva.de"], "shop.bücher.de", None, "/", T, "an IDN request host as its A-label"),
    row(&["*.BÜCHER.de"], "shop.bücher.de", None, "/", T, "IDN case mapping"),
    row(&["*.bücher.de"], "xn--bcher-kva.de", None, "/", F, "an IDN suffix itself"),
    row(&["bücher.de"], "xn--bcher-kva.de", None, "/", T, "an exact IDN rule normalizes too"),
    row(&["*.edu", "-mit.edu"], "mit.edu.", None, "/", F, "no trailing-dot bypass of an exact deny"),
    row(&["*.edu", "-MIT.edu"], "mit.edu", None, "/", F, "no case bypass of an exact deny"),
    row(&["*.de", "-bücher.de"], "xn--bcher-kva.de", None, "/", F, "no punycode bypass of an exact deny"),
    row(&["*.edu"], "*.edu", None, "/", F, "a request host with a star matches no glob"),
    row(&["*.edu"], "a*.mit.edu", None, "/", F, "a request host with a star matches no glob"),
    // 4. IP literals.
    row(&["*.1"], "10.0.0.1", None, "/", F, "`*.1` is not a glob: its suffix is a number"),
    row(&["*.0.0.1"], "10.0.0.1", None, "/", F, "an IPv4 tail is not a suffix"),
    row(&["*.0.1"], "10.0.0.1", None, "/", F, "an IPv4 tail is not a suffix"),
    row(&["*.edu"], "[::1]", None, "/", F, "a glob never matches IPv6"),
    row(&["*.[::1]"], "[::1]", None, "/", F, "an IPv6 suffix is malformed"),
    row(&["*.1", "10.0.0.1"], "10.0.0.1", None, "/", T, "an exact IP still grants"),
    row(&["*.com"], "169.254.169.254", None, "/", F, "a broad glob still never matches an IP"),
    // 5. Precedence.
    row(&["*.edu", "-*.cs.mit.edu"], "mit.edu", None, "/", T, "outside the deny's suffix"),
    row(&["*.edu", "-*.cs.mit.edu"], "ai.cs.mit.edu", None, "/", F, "the longer suffix decides"),
    row(&["*.edu", "-*.cs.mit.edu"], "cs.mit.edu", None, "/", T, "a glob deny does not cover its own suffix"),
    row(&["-*.edu", "mit.edu"], "mit.edu", None, "/", T, "an exact host outranks a glob"),
    row(&["-*.edu", "mit.edu"], "www.mit.edu", None, "/", F, "an exact host covers only itself"),
    row(&["-*.edu", "mit.edu"], "harvard.edu", None, "/", F, "the glob deny holds elsewhere"),
    row(&["*.edu/api", "-*.edu/api/admin"], "mit.edu", None, "/api/x", T, "a glob with a path"),
    row(&["*.edu/api", "-*.edu/api/admin"], "mit.edu", None, "/api/admin/u", F, "the longer path decides"),
    row(&["*.edu/api", "-*.edu/api/admin"], "mit.edu", None, "/other", F, "outside the path: default deny"),
    row(&["*.edu/api"], "mit.edu", None, "/apixyz", F, "path segments match whole"),
    row(&["*.edu:443"], "mit.edu", Some(443), "/", T, "a port on a glob"),
    row(&["*.edu:443"], "mit.edu", Some(80), "/", F, "a port on a glob is exact"),
    row(&["*.edu:443"], "mit.edu", None, "/", T, "an unknown port matches a rule port"),
    row(&["*.edu:443", "-mit.edu"], "mit.edu", Some(443), "/", F, "an exact deny beats a glob with a port"),
    row(&["*.edu", "-evil.edu"], "evil.edu", None, "/", F, "a glob plus an exact deny"),
    row(&["*.edu", "-evil.edu"], "good.edu", None, "/", T, "the exact deny is that host only"),
    row(&["*.edu", "-evil.edu"], "a.evil.edu", None, "/", T, "an exact deny does not cover subdomains"),
    row(&["*.edu", "-*.edu"], "mit.edu", None, "/", F, "a tie: deny wins"),
    row(&["*.edu", "-*.EDU."], "mit.edu", None, "/", F, "a tie after normalization: deny wins"),
    row(&["*.mit.edu", "-*.edu"], "a.mit.edu", None, "/", T, "the longer allow suffix wins"),
    row(&["-*.mit.edu", "*.edu"], "a.mit.edu", None, "/", F, "the longer deny suffix wins"),
    row(&["mit.edu", "-*.edu/admin"], "mit.edu", None, "/admin", T, "the host decides first (documented)"),
    row(&["mit.edu", "-mit.edu/admin", "*.edu"], "mit.edu", None, "/admin", F, "the exact host's own path deny"),
    row(&["*.edu", "-*.edu:8080"], "mit.edu", Some(8080), "/", F, "a glob deny with a port"),
    row(&["*.edu", "-*.edu:8080"], "mit.edu", Some(443), "/", T, "the port deny covers only its port"),
    // 6. Public suffixes are allowed, and broad.
    row(&["*.co.uk"], "bbc.co.uk", None, "/", T, "a glob over a public suffix"),
    row(&["*.com"], "example.com", None, "/", T, "a TLD glob"),
    row(&["*.com"], "com", None, "/", F, "but never the TLD itself"),
    // Unchanged forms.
    row(&[], "mit.edu", None, "/", F, "no rules: default deny"),
    row(&[""], "mit.edu", None, "/", F, "a bare `urn:cap:net:` grants nothing"),
    row(&["*.edu:99999"], "mit.edu", None, "/", F, "a port out of range matches nothing"),
    row(&["mit.edu"], "mit.edu", Some(443), "/x", T, "an exact host, unchanged"),
];

#[test]
fn the_glob_table() {
    assert!(TABLE.len() >= 40, "the brief asks for at least 40 rows");
    let mut failures = Vec::new();
    for (i, r) in TABLE.iter().enumerate() {
        let got = net_allows_port(&cap(r.rules), r.host, r.port, r.path);
        if got != r.allowed {
            failures.push(format!(
                "row {i}: {:?} host={} port={:?} path={} expected {} got {got} ({})",
                r.rules, r.host, r.port, r.path, r.allowed, r.why
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn rule_order_never_matters() {
    for r in TABLE {
        let mut reversed: Vec<&str> = r.rules.to_vec();
        reversed.reverse();
        assert_eq!(
            net_allows_port(&cap(&reversed), r.host, r.port, r.path),
            r.allowed,
            "reversed {:?} for {}",
            r.rules,
            r.host
        );
    }
}

// --- A deterministic generator over label sets ---------------------------------

/// xorshift64*: deterministic, so a failure reproduces from its seed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

const LABELS: &[&str] = &["a", "b", "mit", "cs", "edu", "com", "evil", "xn--bcher-kva"];
const PATHS: &[&str] = &["", "/api", "/api/admin", "/other"];

fn host(rng: &mut Rng) -> String {
    let n = 1 + rng.below(4);
    (0..n)
        .map(|_| rng.pick(LABELS))
        .collect::<Vec<_>>()
        .join(".")
}

/// A random rule body (no prefix, no `-`): an exact host, a glob, or (rarely) a
/// malformed glob, with an optional port and path.
fn rule(rng: &mut Rng) -> String {
    let h = host(rng);
    let host_part = match rng.below(10) {
        0..=3 => h,
        4..=8 => format!("*.{h}"),
        _ => format!("{}*.{h}", rng.pick(LABELS)), // malformed
    };
    let port = if rng.below(4) == 0 { ":443" } else { "" };
    format!("{host_part}{port}{}", rng.pick(PATHS))
}

fn rules(rng: &mut Rng) -> Vec<String> {
    (0..rng.below(5))
        .map(|_| {
            let body = rule(rng);
            if rng.below(3) == 0 {
                format!("-{body}")
            } else {
                body
            }
        })
        .collect()
}

fn caps(rules: &[String]) -> Capability {
    Capability::root().attenuate(rules.iter().map(|r| format!("urn:cap:net:{r}")))
}

fn port(rng: &mut Rng) -> Option<u16> {
    [None, Some(443), Some(80)][rng.below(3)]
}

const CASES: usize = 4000;

#[test]
fn a_single_glob_matches_exactly_the_hosts_strictly_under_its_suffix() {
    let mut rng = Rng(0x35_0001);
    for _ in 0..CASES {
        let suffix = host(&mut rng);
        let target = host(&mut rng);
        let granted = net_allows_port(&caps(&[format!("*.{suffix}")]), &target, None, "/");
        // Computed independently, over labels rather than bytes.
        let t: Vec<&str> = target.split('.').collect();
        let s: Vec<&str> = suffix.split('.').collect();
        let under = t.len() > s.len() && t[t.len() - s.len()..] == s[..];
        assert_eq!(granted, under, "*.{suffix} against {target}");
    }
}

#[test]
fn adding_a_deny_never_widens() {
    let mut rng = Rng(0x35_0002);
    for _ in 0..CASES {
        let base = rules(&mut rng);
        let mut with_deny = base.clone();
        with_deny.push(format!("-{}", rule(&mut rng)));
        let (h, p, path) = (host(&mut rng), port(&mut rng), rng.pick(PATHS));
        let before = net_allows_port(&caps(&base), &h, p, path);
        let after = net_allows_port(&caps(&with_deny), &h, p, path);
        assert!(
            !after || before,
            "a deny widened: {base:?} + {:?} on {h} {p:?} {path}",
            with_deny.last()
        );
    }
}

#[test]
fn adding_a_well_formed_allow_never_narrows() {
    let mut rng = Rng(0x35_0003);
    for _ in 0..CASES {
        let base = rules(&mut rng);
        let mut added = rule(&mut rng);
        while added.contains("*.") && !added.starts_with("*.") {
            added = rule(&mut rng); // keep it well-formed: a malformed allow is a no-op anyway
        }
        let mut with_allow = base.clone();
        with_allow.push(added.clone());
        let (h, p, path) = (host(&mut rng), port(&mut rng), rng.pick(PATHS));
        let before = net_allows_port(&caps(&base), &h, p, path);
        let after = net_allows_port(&caps(&with_allow), &h, p, path);
        assert!(
            after || !before,
            "an allow narrowed: {base:?} + {added} on {h}"
        );
    }
}

#[test]
fn a_glob_never_matches_an_ip_literal() {
    let mut rng = Rng(0x35_0004);
    for _ in 0..CASES {
        let ip = format!(
            "{}.{}.{}.{}",
            rng.below(256),
            rng.below(256),
            rng.below(256),
            rng.below(256)
        );
        // Every glob a label set can make, plus numeric tails of the address itself.
        let tail = ip.split_once('.').map(|(_, t)| t.to_string()).unwrap();
        let globs = vec![format!("*.{}", host(&mut rng)), format!("*.{tail}")];
        assert!(
            !net_allows_port(&caps(&globs), &ip, None, "/"),
            "{globs:?} matched {ip}"
        );
        assert!(!net_allows_port(&caps(&globs), "[::1]", None, "/"));
    }
}

#[test]
fn normalization_never_changes_the_answer() {
    // The same request in upper case or with a trailing dot gets the same answer.
    let mut rng = Rng(0x35_0005);
    for _ in 0..CASES {
        let rs = caps(&rules(&mut rng));
        let (h, p, path) = (host(&mut rng), port(&mut rng), rng.pick(PATHS));
        let plain = net_allows_port(&rs, &h, p, path);
        assert_eq!(
            net_allows_port(&rs, &h.to_uppercase(), p, path),
            plain,
            "{h}"
        );
        assert_eq!(
            net_allows_port(&rs, &format!("{h}."), p, path),
            plain,
            "{h}."
        );
    }
}

// --- Redirects: every hop is re-checked against the glob ------------------------

/// A transport scripted with a response per call, recording each requested URL.
struct Seq {
    responses: Mutex<Vec<HttpResponse>>,
    urls: Mutex<Vec<String>>,
}

#[async_trait]
impl HttpTransport for Seq {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        self.urls.lock().unwrap().push(request.url.clone());
        Ok(self.responses.lock().unwrap().remove(0))
    }
}

fn redirect_then_ok(location: &str) -> Arc<Seq> {
    Arc::new(Seq {
        responses: Mutex::new(vec![
            HttpResponse {
                status: 302,
                headers: vec![("location".to_string(), location.to_string())],
                body: Vec::new(),
            },
            HttpResponse {
                status: 200,
                headers: vec![("content-type".to_string(), "text/plain".to_string())],
                body: b"reached".to_vec(),
            },
        ]),
        urls: Mutex::new(Vec::new()),
    })
}

fn get_through_glob(location: &str) -> (Result<Vec<u8>, Error>, usize) {
    let transport = redirect_then_ok(location);
    let kernel = Kernel::new(Arc::new(space(transport.clone())));
    let req = Request::new(Verb::Source, Iri::parse("urn:http:get").unwrap()).with_arg(
        "url",
        ArgRef::Inline(b"https://a.example.edu/start".to_vec()),
    );
    let out = futures::executor::block_on(kernel.issue(req, &cap(&["*.example.edu"])));
    let sent = transport.urls.lock().unwrap().len();
    (out.map(|r| r.bytes.to_vec()), sent)
}

#[test]
fn a_redirect_inside_the_glob_is_followed() {
    let (out, sent) = get_through_glob("https://b.c.example.edu/data");
    assert_eq!(out.unwrap(), b"reached");
    assert_eq!(sent, 2);
}

#[test]
fn a_redirect_outside_the_glob_is_refused() {
    for location in [
        "https://example.edu.evil.com/x", // the suffix, not at the end
        "https://example.edu/x",          // the suffix itself
        "https://badexample.edu/x",       // a partial label
        "http://169.254.169.254/latest/meta-data",
    ] {
        let (out, sent) = get_through_glob(location);
        let err = out.unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "{location}: got {err:?}");
        assert!(
            err.to_string().contains("redirect target"),
            "{location}: {err}"
        );
        assert_eq!(sent, 1, "{location}: the refused hop sent nothing");
    }
}
