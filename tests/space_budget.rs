use std::sync::Arc;

use async_trait::async_trait;
use futures::{executor::block_on, io::Cursor};
use ikigai_core::{ArgRef, Capability, Error, Iri, Kernel, Request};
use ikigai_http::{space, space_with, HttpBody, HttpRequest, HttpResponse, HttpTransport, Method};

const MIB: usize = 1024 * 1024;

struct SizedResponse {
    length: usize,
    streamed: bool,
}

#[async_trait]
impl HttpTransport for SizedResponse {
    async fn send(&self, _: HttpRequest) -> Result<HttpResponse, String> {
        let bytes = vec![b'x'; self.length];
        Ok(HttpResponse {
            status: 200,
            // Deliberately understate the body: limits must count actual bytes.
            headers: vec![("Content-Length".into(), "0".into())],
            body: if self.streamed {
                HttpBody::from_reader(Cursor::new(bytes))
            } else {
                bytes.into()
            },
        })
    }
}

fn request(method: Method, iri: &str) -> Request {
    Request::new(method.verb(), Iri::parse(iri).unwrap())
        .with_arg("url", ArgRef::Inline(b"https://example.com/body".to_vec()))
}

#[test]
fn host_can_allow_a_twelve_mib_response_with_a_sixteen_mib_budget() {
    for streamed in [false, true] {
        let kernel = Kernel::new(Arc::new(space_with(
            Arc::new(SizedResponse {
                length: 12 * MIB,
                streamed,
            }),
            16 * MIB,
        )));
        let response =
            block_on(kernel.issue(request(Method::Get, Method::Get.iri()), &Capability::root()))
                .unwrap();
        assert_eq!(response.bytes, vec![b'x'; 12 * MIB]);
    }
}

#[test]
fn every_method_and_alias_uses_the_host_limit_without_truncation() {
    for method in Method::ALL {
        let mut names = vec![method.iri()];
        if !matches!(method, Method::Propfind | Method::Report) {
            names.push(method.deprecated_iri());
        }
        for iri in names {
            for streamed in [false, true] {
                for (length, limit) in [(0, 0), (1, 0), (4, 4), (5, 4), (17 * MIB, 16 * MIB)] {
                    let kernel = Kernel::new(Arc::new(space_with(
                        Arc::new(SizedResponse { length, streamed }),
                        limit,
                    )));
                    let result = block_on(kernel.issue(request(method, iri), &Capability::root()));
                    if method == Method::Head {
                        assert_eq!(result.unwrap().bytes, b"true");
                    } else if length <= limit {
                        assert_eq!(result.unwrap().bytes, vec![b'x'; length]);
                    } else {
                        assert!(
                            matches!(result, Err(Error::OverBudget { .. })),
                            "{iri}: {result:?}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn default_space_keeps_its_eight_mib_limit() {
    for streamed in [false, true] {
        for length in [8 * MIB, 8 * MIB + 1, 12 * MIB] {
            let kernel = Kernel::new(Arc::new(space(Arc::new(SizedResponse {
                length,
                streamed,
            }))));
            let result = block_on(
                kernel.issue(request(Method::Get, Method::Get.iri()), &Capability::root()),
            );
            if length == 8 * MIB {
                assert_eq!(result.unwrap().bytes, vec![b'x'; length]);
            } else {
                assert!(matches!(result, Err(Error::OverBudget { .. })));
            }
        }
    }
}

#[test]
fn run_stream_memory_budget_is_separate_from_buffered_http_responses() {
    let kernel = Kernel::new(Arc::new(space_with(
        Arc::new(SizedResponse {
            length: 12 * MIB,
            streamed: true,
        }),
        16 * MIB,
    )))
    .with_stream_memory(1, 1);
    let response =
        block_on(kernel.issue(request(Method::Get, Method::Get.iri()), &Capability::root()))
            .unwrap();
    assert_eq!(response.bytes.len(), 12 * MIB);

    let kernel = Kernel::new(Arc::new(space_with(
        Arc::new(SizedResponse {
            length: 5,
            streamed: true,
        }),
        4,
    )))
    .with_stream_memory(16 * MIB as u64, 16 * MIB as u64);
    let cap = Capability::scoped([
        "urn:cap:net:example.com".to_string(),
        format!("urn:cap:stream:memory:{}", 16 * MIB),
    ]);
    assert!(matches!(
        block_on(kernel.issue(request(Method::Get, Method::Get.iri()), &cap)),
        Err(Error::OverBudget { .. })
    ));
}
