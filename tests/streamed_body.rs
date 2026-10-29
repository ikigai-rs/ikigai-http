use async_trait::async_trait;
use futures::{executor::block_on, io::AsyncRead, task::noop_waker};
use ikigai_core::{Bindings, Capability, Endpoint, Error, Invocation, Iri, Request};
use ikigai_http::{HttpBody, HttpEndpoint, HttpRequest, HttpResponse, HttpTransport, Method};
use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};

#[derive(Default)]
struct Observed {
    read: AtomicUsize,
    dropped: AtomicBool,
}
struct Reader {
    observed: Arc<Observed>,
    left: usize,
    error: Option<io::ErrorKind>,
    pending: bool,
}
impl Drop for Reader {
    fn drop(&mut self) {
        self.observed.dropped.store(true, Ordering::SeqCst);
    }
}
impl AsyncRead for Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending {
            return Poll::Pending;
        }
        if let Some(kind) = self.error {
            return Poll::Ready(Err(io::Error::from(kind)));
        }
        // Deliberately short reads exercise collection across chunk boundaries.
        let count = self.left.min(buf.len()).min(3);
        buf[..count].fill(b'x');
        self.left -= count;
        self.observed.read.fetch_add(count, Ordering::SeqCst);
        Poll::Ready(Ok(count))
    }
}
fn body(length: usize) -> (HttpBody, Arc<Observed>) {
    let observed = Arc::new(Observed::default());
    (
        HttpBody::from_reader(Reader {
            observed: observed.clone(),
            left: length,
            error: None,
            pending: false,
        }),
        observed,
    )
}
fn read_count(observed: &Observed) -> usize {
    observed.read.load(Ordering::SeqCst)
}
fn assert_dropped(observed: &Observed) {
    assert!(observed.dropped.load(Ordering::SeqCst));
}

#[test]
fn collection_bounds_actual_bytes_and_probes_only_one_extra_byte() {
    for (length, limit) in [
        (0, 0),
        (0, 4),
        (4, 4),
        (5, 4),
        (100, 4),
        (1, 0),
        (20_000, 9000),
    ] {
        let (body, observed) = body(length);
        assert_eq!(read_count(&observed), 0, "construction is lazy");
        let result = block_on(body.collect(limit));
        if length <= limit {
            assert_eq!(result.unwrap(), vec![b'x'; length]);
        } else {
            assert!(matches!(result, Err(Error::OverBudget { .. })));
        }
        assert_eq!(read_count(&observed), length.min(limit + 1));
        assert_dropped(&observed);
    }
}

#[test]
fn io_errors_and_cancellation_drop_the_reader() {
    for kind in [io::ErrorKind::TimedOut, io::ErrorKind::ConnectionReset] {
        let observed = Arc::new(Observed::default());
        let body = HttpBody::from_reader(Reader {
            observed: observed.clone(),
            left: 10,
            error: Some(kind),
            pending: false,
        });
        let error = block_on(body.collect(4)).unwrap_err();
        if kind == io::ErrorKind::TimedOut {
            assert!(matches!(error, Error::Timeout(_)));
        } else {
            assert!(matches!(error, Error::Unavailable(_)));
        }
        assert_dropped(&observed);
    }
    let observed = Arc::new(Observed::default());
    let body = HttpBody::from_reader(Reader {
        observed: observed.clone(),
        left: 10,
        error: None,
        pending: true,
    });
    let mut future = Box::pin(body.collect(4));
    let waker = noop_waker();
    assert!(
        std::future::Future::poll(future.as_mut(), &mut Context::from_waker(&waker)).is_pending()
    );
    drop(future);
    assert_dropped(&observed);
}

struct Once(Mutex<Option<HttpResponse>>);
#[async_trait]
impl HttpTransport for Once {
    async fn send(&self, _: HttpRequest) -> Result<HttpResponse, String> {
        Ok(self.0.lock().unwrap().take().expect("one request"))
    }
}
fn invoke(
    method: Method,
    response: HttpResponse,
    limit: usize,
) -> ikigai_core::Result<ikigai_core::Representation> {
    let endpoint = HttpEndpoint::new(method, Arc::new(Once(Mutex::new(Some(response)))))
        .with_max_response_bytes(limit);
    let request = Request::new(method.verb(), Iri::parse(method.iri()).unwrap()).with_arg(
        "url",
        ikigai_core::ArgRef::Inline(b"https://example.com/x".to_vec()),
    );
    let capability = Capability::root().attenuate(["urn:cap:net:example.com".to_string()]);
    let bindings = Bindings::new();
    block_on(endpoint.invoke(&Invocation::detached(&request, &bindings, &capability)))
}
#[test]
fn endpoint_counts_streamed_bytes_independent_of_content_length() {
    for length_header in [None, Some("1"), Some("9999999999999999999999999999")] {
        let (body, observed) = body(100);
        let headers = length_header
            .map(|value| vec![("Content-Length".into(), value.into())])
            .unwrap_or_default();
        let result = invoke(
            Method::Get,
            HttpResponse {
                status: 200,
                headers,
                body,
            },
            4,
        );
        assert!(matches!(result, Err(Error::OverBudget { .. })));
        assert_eq!(read_count(&observed), 5);
        assert_dropped(&observed);
    }
    let (body, observed) = body(4);
    assert!(invoke(
        Method::Get,
        HttpResponse {
            status: 200,
            headers: vec![],
            body
        },
        4
    )
    .is_ok());
    assert_eq!(read_count(&observed), 4);
}
#[test]
fn head_errors_and_refused_redirects_drop_bodies_without_reading() {
    for (method, status, headers) in [
        (Method::Head, 200, vec![]),
        (Method::Get, 404, vec![]),
        (
            Method::Get,
            302,
            vec![("Location".into(), "https://ungranted.example/x".into())],
        ),
    ] {
        let (body, observed) = body(100);
        let result = invoke(
            method,
            HttpResponse {
                status,
                headers,
                body,
            },
            4,
        );
        assert_eq!(result.is_ok(), method == Method::Head);
        assert_eq!(read_count(&observed), 0);
        assert_dropped(&observed);
    }
}

#[test]
fn not_modified_is_metadata_only_and_drops_the_body_unread() {
    for method in Method::ALL {
        let (body, observed) = body(100);
        let repr = invoke(
            method,
            HttpResponse {
                status: 304,
                headers: vec![("Cache-Control".into(), "max-age=600".into())],
                body,
            },
            4,
        )
        .unwrap();
        assert_eq!(
            repr.repr_type.params.get("http-status").map(String::as_str),
            Some("304")
        );
        assert!(repr.bytes.is_empty());
        assert_eq!(repr.expiry, ikigai_core::Expiry::Always);
        assert!(repr.threads().is_empty());
        assert_eq!(read_count(&observed), 0);
        assert_dropped(&observed);
    }
}

#[test]
fn buffered_bodies_obey_the_same_limit() {
    assert_eq!(
        block_on(HttpBody::from(vec![1, 2]).collect(2)).unwrap(),
        vec![1, 2]
    );
    assert!(matches!(
        block_on(HttpBody::from(vec![1, 2]).collect(1)),
        Err(Error::OverBudget { .. })
    ));
}

#[test]
fn direct_consumers_can_read_incrementally() {
    use futures::io::AsyncReadExt;
    let (body, observed) = body(100);
    let mut reader = body.into_reader();
    let mut prefix = [0; 2];
    block_on(reader.read_exact(&mut prefix)).unwrap();
    assert_eq!(&prefix, b"xx");
    assert_eq!(read_count(&observed), 2);
    drop(reader);
    assert_dropped(&observed);

    let mut buffered = HttpBody::from(vec![0, 255, 1]).into_reader();
    let mut bytes = Vec::new();
    block_on(buffered.read_to_end(&mut bytes)).unwrap();
    assert_eq!(bytes, vec![0, 255, 1]);
}
