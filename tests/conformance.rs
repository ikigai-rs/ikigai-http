//! The module recipe as one test: `ikigai-conformance` walks the six endpoints
//! [`ikigai_http::space`] binds and reports every violation at once.
//!
//! ## The fixture kernel: a loopback origin, and a transport that keeps the contract
//!
//! CI cannot reach the network, and a module whose every action is an outbound
//! request has nothing to fire without one. So [`Origin`] is an HTTP/1.1 listener
//! on `127.0.0.1` at an ephemeral port, scripted by path (`/live`, `/fresh`,
//! `/etag`, `/no-store`, `/untyped`, `/json`, `/hop`, `/hop-in`), recording every request
//! it receives and counting every connection it accepts — the count is how a
//! test proves a socket was NEVER opened. [`Client`] is the smallest
//! [`HttpTransport`] that speaks to it: one blocking exchange per request, and it
//! does not follow redirects, because the trait says a transport must not (the
//! endpoint follows, re-running the ACL per hop — see [`ikigai_http`]'s docs).
//! Every fixture points `url=` at that origin, and the fired actions run under
//! root, which the ACL admits everywhere.
//!
//! ## Declarations, and why each
//!
//! - Nothing is `pure`: every result is a read of a remote resource.
//! - [`conforms`] walks the origin's `/live` path — a `200` with no freshness
//!   signal — and declares `httpGet` and `httpHead` **`live`**: a web read with no
//!   freshness is a live fact, served uncacheable, and `Suite::live` (0.1.1) holds
//!   the kernel to `Expiry::Always` there. That is the polarity nothing else can
//!   see: were a dependency or a stray `.cacheable()` to make this read cached, no
//!   type would change and no other check would speak. The four mutating verbs are
//!   not declared live — `Check::Cacheable` returns before looking at a verb that
//!   is not cacheable, so the declaration would be silently inert.
//! - [`conforms_and_caches_under_a_freshness_window`] walks `/fresh`
//!   (`Cache-Control: max-age=60`) over a clocked kernel and declares `httpGet`
//!   and `httpHead` `cacheable`: held to a cache hit on the second resolution and
//!   a non-empty thread set (the URL's golden thread, which a mutating call to the
//!   same URL cuts). The declaration is true over THIS origin's answer, not the
//!   module in isolation (PENDING #18/#30): the same code over `/live` is live.
//! - `NAMES` is skipped suite-wide, not opted out per id: the six ids (`httpGet`,
//!   `httpHead`, `httpPost`, `httpPut`, `httpPatch`, `httpDelete`) are live MCP
//!   tool names, renamed in one coordinated pass (wave two, owned by
//!   `ikigai-core-PENDING.md` §1). `Suite::opt_out` cannot carry this — it drops
//!   the INVOKING checks and leaves NAMES running — so the check is dropped and
//!   [`names_are_wave_two`] pins the six findings the pass will flip.
//! - `OUTPUTS` is **waived per endpoint** for the five pass-through actions
//!   ([`PASS_THROUGH`]), with [`Suite::opt_out_check`] and the reason printed in
//!   the report. It cannot be satisfied: `httpGet`/`httpPost`/`httpPut`/
//!   `httpPatch`/`httpDelete` serve whatever `Content-Type` the origin sends, and
//!   `outputs` is a closed list in core's `Description` — there is no pass-through
//!   spelling (core PENDING §20 is the condition for removing this waiver). The
//!   declared `application/octet-stream` is true, and is the ONLY thing that can be
//!   declared: it is what the action serves when the origin labels nothing. Naming
//!   the types an origin might send would be a lie that happens to pass.
//!   ⚠ The waiver is per CHECK, not per endpoint: `Suite::opt_out` would drop
//!   `ENFORCED` and `CACHEABLE` on the same five, which is this module's most
//!   valuable coverage. What the waiver gives up is pinned by hand in
//!   [`declared_outputs_are_the_media_types_served`].
//!
//! No whole-endpoint opt-outs: every action fires against the loopback origin. No
//! module namespace: there is no RDF face — so the walk prints no `probed:` line,
//! and the positive evidence that it looked at anything is the `fixture:` lines,
//! the endpoint/action counts [`assert_shape`] pins, and the origin's own record
//! ([`assert_fired_once_each`]).
//!
//! ## What the suite cannot see, pinned by hand
//!
//! - **ENFORCED never reaches a socket** ([`every_verb_is_denied_before_any_socket_opens`]):
//!   the suite's ENFORCED check sees the typed `Denied`; it cannot see that no
//!   connection was made. The origin's connection count can. Three capability
//!   shapes: no grants, a grant on ANOTHER host (the wildcard `urn:cap:net:*` is
//!   offered to any holder of some net grant, and the rules still refuse), and a
//!   grant on the origin's host (one connection).
//! - **A redirect off the allowlist** ([`a_redirect_off_the_allowlist_is_denied_before_the_hop`]):
//!   `/hop` sends the request to `localhost` — the same machine under a name the
//!   capability does not grant. The hop dies at the ACL, typed `Denied`, one
//!   connection. `/hop-in` redirects within the grant and is followed.
//! - **What the code does with freshness today**
//!   ([`a_get_is_live_unless_the_response_says_otherwise`]): no `Cache-Control` →
//!   live; `max-age` → cached until the deadline; `no-store` → live; a caller's
//!   `max_age=` → cached; an `ETag` alone → live (no conditional revalidation
//!   exists — pinned as what the code does, not designed here); `max-age` on a
//!   clockless kernel → live.
//! - **What the `OUTPUTS` waiver gives up**
//!   ([`declared_outputs_are_the_media_types_served`]): `httpHead` serves
//!   `text/plain` (`true`/`false`), declares it, and is NOT waived — the check runs
//!   on it. For the five that are waived, the hand test pins all three cases the
//!   check would have seen: the origin's label passes through (`/live` →
//!   `text/plain`), an origin that labels nothing gets the declared fallback
//!   (`/untyped` → `application/octet-stream`), and a label with parameters is
//!   served as its bare media type (`/json` → `application/json`, the
//!   `;charset=utf-8` dropped — the same normalization `OUTPUTS` applies before
//!   comparing).
//! - **The mutating verbs' `content` reaches the wire** ([`the_mutating_verbs_send_content_as_the_body`]):
//!   PIPELINE can only say `content` did not raise `MissingArgument`; the origin
//!   can say the bytes arrived, for all four — `DELETE` included.
//! - **The manifold states the contract** ([`the_manifold_states_the_contract`]):
//!   only `url` is required (no check can see "required but actually optional",
//!   PENDING #5), every input has a class, every action declares `urn:cap:net:*`.

use async_trait::async_trait;
use ikigai_conformance::{Check, Checks, Fixture, Report, Suite};
use ikigai_core::{
    ArgRef, Capability, Clock, Error, Iri, Kernel, Representation, Request, Time, Verb,
};
use ikigai_http::{HttpRequest, HttpResponse, HttpTransport};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use url::Url;

/// The six endpoints `space()` binds: description id, bound IRI, verb.
const METHODS: [(&str, &str, Verb); 6] = [
    ("httpGet", "urn:httpGet", Verb::Source),
    ("httpHead", "urn:httpHead", Verb::Exists),
    ("httpPost", "urn:httpPost", Verb::Sink),
    ("httpPut", "urn:httpPut", Verb::Sink),
    ("httpPatch", "urn:httpPatch", Verb::Sink),
    ("httpDelete", "urn:httpDelete", Verb::Delete),
];

/// The five actions that serve the ORIGIN's `Content-Type` — everything but
/// `httpHead`, whose `true`/`false` is always `text/plain`. `OUTPUTS` is waived
/// for exactly these, and for no other check.
const PASS_THROUGH: [&str; 5] = ["httpGet", "httpPost", "httpPut", "httpPatch", "httpDelete"];

/// Why `OUTPUTS` cannot be satisfied here, printed in every report the suite
/// produces. It is a condition, not an excuse: the day core can spell a
/// pass-through output, this waiver comes out.
const PASS_THROUGH_REASON: &str =
    "serves the origin's Content-Type: `outputs` is a closed list in core's \
     `Description` and has no pass-through spelling (core PENDING §20), so the \
     declared `application/octet-stream` — the type served when the origin labels \
     nothing — is the only true declaration. Enumerating types an origin might send \
     would pass this check by lying. What it gives up is pinned in \
     `declared_outputs_are_the_media_types_served`";

/// The scope that admits the origin, and one that admits a host it is not.
const ORIGIN_SCOPE: &str = "urn:cap:net:127.0.0.1";
const OTHER_SCOPE: &str = "urn:cap:net:example.com";

/// The wildcard every action must declare: "holds some grant under this prefix".
const NET_WILDCARD: &str = "urn:cap:net:*";

/// One request as the origin received it.
#[derive(Clone, Debug)]
struct Received {
    method: String,
    path: String,
    body: Vec<u8>,
}

/// One HTTP/1.x message off a stream: the start line, the headers, and a body
/// of `Content-Length` bytes (or to EOF). A request to the origin, a response to
/// the client.
struct Message {
    start: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn read_message(stream: &mut TcpStream) -> Option<Message> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.lines();
    let start = lines.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < len {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(len);
    Some(Message {
        start,
        headers,
        body,
    })
}

/// A loopback HTTP/1.1 origin on an ephemeral port, scripted by path, recording
/// what it receives and counting what it accepts.
struct Origin {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    received: Arc<Mutex<Vec<Received>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Origin {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (connections, received, stop) =
                (connections.clone(), received.clone(), stop.clone());
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    connections.fetch_add(1, Ordering::SeqCst);
                    let Some(Message { start, body, .. }) = read_message(&mut stream) else {
                        continue;
                    };
                    let mut parts = start.split_whitespace();
                    let method = parts.next().unwrap_or("").to_string();
                    let path = parts.next().unwrap_or("/").to_string();
                    let (status, reason, headers, body_out) = respond(&path, addr.port());
                    let body_out = if method == "HEAD" {
                        Vec::new()
                    } else {
                        body_out
                    };
                    received
                        .lock()
                        .unwrap()
                        .push(Received { method, path, body });
                    let mut head = format!(
                        "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: {}\r\n",
                        body_out.len()
                    );
                    for (k, v) in headers {
                        head.push_str(&format!("{k}: {v}\r\n"));
                    }
                    head.push_str("\r\n");
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(&body_out);
                    let _ = stream.flush();
                }
            })
        };
        Origin {
            addr,
            connections,
            received,
            stop,
            thread: Some(thread),
        }
    }

    /// The absolute URL of `path` on this origin, by the address the ACL is
    /// granted on.
    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.addr.port())
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }

    /// How many requests reached `path`.
    fn hits(&self, path: &str) -> usize {
        self.received().iter().filter(|r| r.path == path).count()
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Unblock the accept loop so the thread sees the flag.
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The origin's script: what each path answers.
fn respond(path: &str, port: u16) -> (u16, &'static str, Vec<(&'static str, String)>, Vec<u8>) {
    let text = |extra: Vec<(&'static str, String)>| {
        let mut h = vec![("Content-Type", "text/plain".to_string())];
        h.extend(extra);
        h
    };
    match path {
        // A 200 with no freshness signal: live.
        "/live" => (200, "OK", text(vec![]), b"live".to_vec()),
        // The origin grants a freshness window.
        "/fresh" => (
            200,
            "OK",
            text(vec![("Cache-Control", "max-age=60".to_string())]),
            b"fresh".to_vec(),
        ),
        // A validator and nothing else.
        "/etag" => (
            200,
            "OK",
            text(vec![("ETag", "\"v1\"".to_string())]),
            b"tagged".to_vec(),
        ),
        // The origin forbids storing.
        "/no-store" => (
            200,
            "OK",
            text(vec![("Cache-Control", "no-store".to_string())]),
            b"private".to_vec(),
        ),
        // No Content-Type at all.
        "/untyped" => (200, "OK", vec![], b"bytes".to_vec()),
        // A Content-Type carrying a parameter: the bare media type is what is served.
        "/json" => (
            200,
            "OK",
            vec![(
                "Content-Type",
                "application/json; charset=utf-8".to_string(),
            )],
            br#"{"ok":true}"#.to_vec(),
        ),
        // A redirect to the SAME machine under a name the capability does not grant.
        "/hop" => (
            302,
            "Found",
            vec![("Location", format!("http://localhost:{port}/live"))],
            Vec::new(),
        ),
        // A redirect within the grant.
        "/hop-in" => (
            302,
            "Found",
            vec![("Location", "/live".to_string())],
            Vec::new(),
        ),
        _ => (404, "Not Found", text(vec![]), b"no such path".to_vec()),
    }
}

/// The smallest transport that speaks to the origin: one blocking HTTP/1.1
/// exchange per request. It sends the endpoint's headers and body verbatim and
/// returns a 3xx as-is — the contract [`HttpTransport`] states.
struct Client;

#[async_trait]
impl HttpTransport for Client {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        let url = Url::parse(&request.url).map_err(|e| e.to_string())?;
        let host = url.host_str().ok_or("no host")?;
        let port = url.port_or_known_default().ok_or("no port")?;
        let mut target = url.path().to_string();
        if let Some(q) = url.query() {
            target.push('?');
            target.push_str(q);
        }
        let mut stream = TcpStream::connect((host, port)).map_err(|e| e.to_string())?;
        let mut head = format!(
            "{} {target} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nContent-Length: {}\r\n",
            request.method.as_str(),
            request.body.len()
        );
        for (k, v) in &request.headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\n");
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(&request.body))
            .map_err(|e| e.to_string())?;
        let Message {
            start,
            headers,
            body,
        } = read_message(&mut stream).ok_or("no response")?;
        let status = start
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("bad status line `{start}`"))?;
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

/// A clock that does not move: a freshness window granted at this instant is
/// open on the next read.
struct Fixed;

impl Clock for Fixed {
    fn now(&self) -> Time {
        Time::from_millis(1_000_000)
    }
}

fn kernel() -> Kernel {
    Kernel::new(Arc::new(ikigai_http::space(Arc::new(Client))))
}

fn clocked_kernel() -> Kernel {
    kernel().with_clock(Arc::new(Fixed))
}

/// The suite for this module: every action's `url=` on one path of the origin,
/// NAMES dropped suite-wide (wave two — see the file docs), OUTPUTS waived for
/// the five pass-through actions and running everywhere else.
fn suite(origin: &Origin, path: &str) -> Suite {
    let mut suite = Suite::new().checks(Checks::all() - Checks::NAMES);
    for (id, _, verb) in METHODS {
        suite = suite.fixture(Fixture::new(id, verb).arg("url", origin.url(path)));
    }
    for id in PASS_THROUGH {
        suite = suite.opt_out_check(id, Check::Outputs, PASS_THROUGH_REASON);
    }
    suite
}

/// The walk saw six endpoints, one action each, skipped exactly NAMES suite-wide,
/// waived exactly OUTPUTS on exactly the five pass-through ids, and opted no
/// endpoint out wholesale. A seventh endpoint bound without a line here, or a
/// sixth check quietly waived, is held to a weaker standard.
fn assert_shape(report: &Report) {
    assert_eq!(report.endpoints, METHODS.len(), "{report}");
    assert_eq!(report.actions, METHODS.len(), "one action each: {report}");
    assert_eq!(
        report.checks.skipped().collect::<Vec<_>>(),
        vec![Check::Names],
        "only NAMES is skipped: {report}"
    );
    assert!(
        report.declared.opted_out.is_empty(),
        "no endpoint is opted out wholesale — that would drop ENFORCED and \
         CACHEABLE with it: {report}"
    );
    let waived: Vec<(&str, Check)> = report
        .declared
        .opted_out_checks
        .iter()
        .map(|o| (o.endpoint.as_str(), o.check))
        .collect();
    let expected: Vec<(&str, Check)> = PASS_THROUGH
        .iter()
        .map(|id| (*id, Check::Outputs))
        .collect();
    assert_eq!(
        waived, expected,
        "OUTPUTS is waived for the five pass-through actions and nothing else — \
         `httpHead` declares what it serves and is checked: {report}"
    );
}

/// Every action was fired exactly once under root, in walk order — the second
/// GET/HEAD of the cache probe, when it runs, is a cache hit that never reaches
/// the origin.
fn assert_fired_once_each(origin: &Origin) {
    let methods: Vec<String> = origin.received().into_iter().map(|r| r.method).collect();
    assert_eq!(
        methods,
        ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
        "each action reaches the origin once"
    );
}

/// Over `/live` — a `200` with no freshness signal — the two cacheable verbs are
/// declared **live**, and the suite holds them to `Expiry::Always` even on a
/// clocked kernel that could have granted a window. Declared, not merely absent:
/// "nobody said anything and it silently became cacheable" is the one direction
/// `CACHEABLE` is otherwise blind to, and a web read that starts being served from
/// the cache changes no type and fails no other test.
#[test]
fn conforms() {
    let origin = Origin::start();
    let report = suite(&origin, "/live")
        .live("httpGet")
        .live("httpHead")
        .run_blocking(&clocked_kernel());
    // Printed even when clean (`--nocapture`): the report is the record.
    eprintln!("{report}");
    report.assert_clean();
    assert_shape(&report);
    assert!(report.declared.cacheable.is_empty(), "{report}");
    assert_eq!(report.declared.live, ["httpGet", "httpHead"], "{report}");
    assert_fired_once_each(&origin);
}

#[test]
fn conforms_and_caches_under_a_freshness_window() {
    let origin = Origin::start();
    let report = suite(&origin, "/fresh")
        .cacheable("httpGet")
        .cacheable("httpHead")
        .run_blocking(&clocked_kernel());
    eprintln!("{report}");
    report.assert_clean();
    assert_shape(&report);
    assert_eq!(
        report.declared.cacheable,
        ["httpGet", "httpHead"],
        "{report}"
    );
    assert!(
        report.declared.live.is_empty(),
        "the same two ids are live over `/live` and cacheable over `/fresh`: the \
         declaration is about the ORIGIN's answer, not the endpoint: {report}"
    );
    assert_fired_once_each(&origin);
}

/// The `live` declaration is load-bearing, not decorative: the SAME declaration
/// that is clean over `/live` goes red over `/fresh`, where the origin grants a
/// window and the clocked kernel takes it. Without this, "declared live" would be
/// a comment the suite happens to print — and the failure it exists to catch (a
/// read that must be fresh quietly becoming cached, changing no type and failing
/// no other check) would still be invisible.
#[test]
fn a_live_declaration_goes_red_when_the_read_becomes_cached() {
    let origin = Origin::start();
    let report = suite(&origin, "/fresh")
        .live("httpGet")
        .live("httpHead")
        .run_blocking(&clocked_kernel());
    let flagged: Vec<&str> = report
        .of(Check::Cacheable)
        .map(|f| f.endpoint.as_str())
        .collect();
    assert_eq!(flagged, ["httpGet", "httpHead"], "{report}");
    assert_eq!(report.findings.len(), 2, "only that: {report}");
}

/// The six findings the wave-two rename will flip: one NAMES line per id, and
/// nothing else under that check.
#[test]
fn names_are_wave_two() {
    let origin = Origin::start();
    let report = Suite::new().checks(Checks::NAMES).run_blocking(&kernel());
    let mut flagged: Vec<&str> = report
        .of(Check::Names)
        .map(|f| f.endpoint.as_str())
        .collect();
    flagged.sort_unstable();
    let mut expected: Vec<&str> = METHODS.iter().map(|(id, _, _)| *id).collect();
    expected.sort_unstable();
    assert_eq!(flagged, expected, "{report}");
    assert_eq!(report.findings.len(), METHODS.len(), "{report}");
    assert_eq!(origin.connections(), 0, "NAMES is a static check");
}

fn request(verb: Verb, iri: &str, args: &[(&str, &str)]) -> Request {
    let mut request = Request::new(verb, Iri::parse(iri).unwrap());
    for (name, value) in args {
        request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
    }
    request
}

fn issue(
    kernel: &Kernel,
    verb: Verb,
    iri: &str,
    args: &[(&str, &str)],
    capability: &Capability,
) -> Result<Representation, Error> {
    futures::executor::block_on(kernel.issue(request(verb, iri, args), capability))
}

fn scoped(scopes: &[&str]) -> Capability {
    Capability::scoped(scopes.iter().map(|s| s.to_string()))
}

/// Under no grants — and under a grant on another host — every verb refuses with
/// a typed, permanent `Denied`, and the origin accepts no connection. Two gates
/// are in play: with no net grant at all the KERNEL refuses on the declared
/// `urn:cap:net:*` before the endpoint runs; with a grant on another host the
/// wildcard admits the call and the endpoint's rules refuse it, naming the
/// method and the host. Under a grant on the origin's host the call connects
/// once.
#[test]
fn every_verb_is_denied_before_any_socket_opens() {
    let origin = Origin::start();
    let kernel = kernel();
    let url = origin.url("/live");
    for (capability, gate) in [
        (scoped(&[]), NET_WILDCARD),
        (scoped(&[OTHER_SCOPE]), "127.0.0.1"),
    ] {
        for (id, iri, verb) in METHODS {
            let err = issue(
                &kernel,
                verb,
                iri,
                &[("url", &url), ("content", "never sent")],
                &capability,
            )
            .err()
            .unwrap_or_else(|| panic!("{id} resolved under {capability:?}"));
            assert!(matches!(err, Error::Denied(_)), "{id}: {err:?}");
            assert!(!err.is_transient(), "{id}: {err:?}");
            assert!(
                err.to_string().contains(gate),
                "{id}: the denial names what refused it: {err}"
            );
        }
    }
    assert_eq!(
        origin.connections(),
        0,
        "the gate precedes the socket: nothing connected"
    );
    let ok = issue(
        &kernel,
        Verb::Source,
        "urn:httpGet",
        &[("url", &url)],
        &scoped(&[ORIGIN_SCOPE]),
    )
    .unwrap();
    assert_eq!(ok.bytes, b"live");
    assert_eq!(
        origin.connections(),
        1,
        "a granted host connects exactly once"
    );
}

/// A redirect to a host outside the allowlist dies at the ACL before the hop is
/// requested — for both cacheable verbs, since both follow. A redirect within
/// the grant is followed, and a mutating verb never follows at all.
#[test]
fn a_redirect_off_the_allowlist_is_denied_before_the_hop() {
    let origin = Origin::start();
    let kernel = kernel();
    let cap = scoped(&[ORIGIN_SCOPE]);
    for (verb, iri) in [
        (Verb::Source, "urn:httpGet"),
        (Verb::Exists, "urn:httpHead"),
    ] {
        let before = origin.connections();
        let err = issue(&kernel, verb, iri, &[("url", &origin.url("/hop"))], &cap).unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "{iri}: {err:?}");
        assert!(!err.is_transient(), "{iri}: {err:?}");
        assert!(
            err.to_string().contains("redirect target") && err.to_string().contains("localhost"),
            "{iri}: the denial names the hop: {err}"
        );
        assert_eq!(
            origin.connections(),
            before + 1,
            "{iri}: the first request went out; the hop never did"
        );
    }
    assert_eq!(
        origin.hits("/live"),
        0,
        "the ungranted hop was never requested"
    );

    let before = origin.connections();
    let ok = issue(
        &kernel,
        Verb::Source,
        "urn:httpGet",
        &[("url", &origin.url("/hop-in"))],
        &cap,
    )
    .unwrap();
    assert_eq!(ok.bytes, b"live", "a hop within the grant is followed");
    assert_eq!(origin.connections(), before + 2);

    let before = origin.connections();
    let err = issue(
        &kernel,
        Verb::Sink,
        "urn:httpPost",
        &[("url", &origin.url("/hop-in")), ("content", "payload")],
        &cap,
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::Endpoint(_)) && err.to_string().contains("never follow redirects"),
        "a mutating verb refuses the hop even within the grant: {err:?}"
    );
    assert_eq!(
        origin.connections(),
        before + 1,
        "the body was not replayed"
    );
}

/// What the code does with freshness today, pinned — not designed: a web read
/// is live unless the response (or the caller) grants a window, and an `ETag`
/// alone grants nothing because no conditional revalidation exists.
#[test]
fn a_get_is_live_unless_the_response_says_otherwise() {
    let origin = Origin::start();
    let kernel = clocked_kernel();
    let root = Capability::root();
    let twice = |kernel: &Kernel, path: &str, extra: &[(&str, &str)]| {
        let url = origin.url(path);
        let mut args = vec![("url", url.as_str())];
        args.extend_from_slice(extra);
        for _ in 0..2 {
            issue(kernel, Verb::Source, "urn:httpGet", &args, &root).unwrap();
        }
        origin.hits(path)
    };
    assert_eq!(twice(&kernel, "/live", &[]), 2, "no freshness signal: live");
    assert_eq!(
        twice(&kernel, "/fresh", &[]),
        1,
        "max-age: cached until the deadline"
    );
    assert_eq!(twice(&kernel, "/no-store", &[]), 2, "no-store: live");
    assert_eq!(
        twice(&kernel, "/etag", &[]),
        2,
        "an ETag alone is live: no conditional revalidation is implemented"
    );
    assert_eq!(
        twice(&kernel, "/untyped", &[("max_age", "30")]),
        1,
        "a caller's max_age caches a response that carries no freshness"
    );
    let clockless = self::kernel();
    let origin2 = Origin::start();
    let url = origin2.url("/fresh");
    for _ in 0..2 {
        issue(
            &clockless,
            Verb::Source,
            "urn:httpGet",
            &[("url", &url)],
            &root,
        )
        .unwrap();
    }
    assert_eq!(
        origin2.hits("/fresh"),
        2,
        "a deadline needs a clock: with none, max-age is live"
    );
}

fn declared_outputs(kernel: &Kernel, iri: &str) -> Vec<String> {
    kernel
        .describe_pattern(iri)
        .unwrap_or_else(|| panic!("{iri} describes itself"))
        .outputs
        .iter()
        .map(|o| ikigai_conformance::rdf::bare_media_type(o))
        .collect()
}

/// What the `OUTPUTS` waiver gives up, pinned by hand. `httpHead` is NOT waived:
/// it always serves `text/plain`, declares exactly that, and the check covers it —
/// this test only re-states it so the pair reads together. For the five that are
/// waived, every case the check would have observed is asserted here: the declared
/// `application/octet-stream` IS what an unlabeled response is served as, the
/// origin's own label passes through unchanged, and a label carrying parameters is
/// served as its bare media type — the same `;`-stripping `OUTPUTS` does before
/// comparing, which is where a pass-through and a declaration could silently
/// diverge.
#[test]
fn declared_outputs_are_the_media_types_served() {
    let origin = Origin::start();
    let kernel = kernel();
    let root = Capability::root();
    let head = issue(
        &kernel,
        Verb::Exists,
        "urn:httpHead",
        &[("url", &origin.url("/live"))],
        &root,
    )
    .unwrap();
    assert_eq!(head.repr_type.media_type, "text/plain");
    assert_eq!(head.bytes, b"true");
    assert_eq!(declared_outputs(&kernel, "urn:httpHead"), ["text/plain"]);

    for (id, iri, verb) in METHODS {
        if verb == Verb::Exists {
            continue;
        }
        assert!(PASS_THROUGH.contains(&id), "{id} is one of the waived five");
        assert_eq!(
            declared_outputs(&kernel, iri),
            ["application/octet-stream"],
            "{id}"
        );
        let untyped = issue(
            &kernel,
            verb,
            iri,
            &[("url", &origin.url("/untyped"))],
            &root,
        )
        .unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(
            untyped.repr_type.media_type, "application/octet-stream",
            "{id}: the declared output is what an unlabeled response is served as"
        );
        let typed = issue(&kernel, verb, iri, &[("url", &origin.url("/live"))], &root)
            .unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(
            typed.repr_type.media_type, "text/plain",
            "{id}: the origin's label passes through — outside the declared list, by design"
        );
        let parameterized = issue(&kernel, verb, iri, &[("url", &origin.url("/json"))], &root)
            .unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(
            parameterized.repr_type.media_type, "application/json",
            "{id}: the label's parameters are dropped — the bare media type is served"
        );
    }
}

/// PIPELINE can only say `content` did not raise `MissingArgument`; the origin
/// can say the bytes arrived as the body — for `DELETE` too, which sends one
/// when given one.
#[test]
fn the_mutating_verbs_send_content_as_the_body() {
    let origin = Origin::start();
    let kernel = kernel();
    let root = Capability::root();
    let url = origin.url("/live");
    for (id, iri, verb) in METHODS {
        if !verb.is_mutating() {
            continue;
        }
        let body = format!("body of {id}");
        issue(
            &kernel,
            verb,
            iri,
            &[
                ("url", &url),
                ("content", &body),
                ("content_type", "text/plain"),
            ],
            &root,
        )
        .unwrap_or_else(|e| panic!("{id}: {e}"));
        let last = origin.received().pop().unwrap();
        assert_eq!(
            last.body,
            body.as_bytes(),
            "{id}: the body reached the wire"
        );
        let spec = kernel.describe_pattern(iri).unwrap();
        let content = spec
            .action_specs()
            .into_iter()
            .flat_map(|a| a.inputs)
            .find(|i| i.name == "content")
            .unwrap_or_else(|| panic!("{id} declares `content`"));
        assert!(!content.required, "{id}: a body is optional");
    }
}

/// The contract as the manifold states it: every action declares the net
/// wildcard and nothing else, every input has a class, only `url` is required,
/// the cacheable verbs take `max_age`, the mutating ones take `content` and
/// `content_type`.
#[test]
fn the_manifold_states_the_contract() {
    let kernel = kernel();
    for (id, iri, verb) in METHODS {
        let description = kernel.describe_pattern(iri).unwrap();
        let specs = description.action_specs();
        assert_eq!(specs.len(), 1, "{id}: one action");
        let spec = &specs[0];
        assert_eq!(spec.verb, verb, "{id}");
        assert_eq!(spec.requires, [NET_WILDCARD], "{id}: declared = enforced");
        let names: Vec<&str> = spec.inputs.iter().map(|i| i.name.as_str()).collect();
        let required: Vec<&str> = spec
            .inputs
            .iter()
            .filter(|i| i.required)
            .map(|i| i.name.as_str())
            .collect();
        assert_eq!(required, ["url"], "{id}: only the URL is required");
        for input in &spec.inputs {
            assert!(
                input.class.as_deref().is_some_and(|c| c.contains(':')),
                "{id}: input `{}` has a class",
                input.name
            );
        }
        assert_eq!(
            names.contains(&"max_age"),
            verb.is_cacheable(),
            "{id}: max_age"
        );
        assert_eq!(
            names.contains(&"content"),
            verb.is_mutating(),
            "{id}: content"
        );
        assert_eq!(
            names.contains(&"content_type"),
            verb.is_mutating(),
            "{id}: content_type"
        );
    }
}
