//! Runtime-independent response bodies. A transport must expose its reader before
//! buffering the response, and must not prefetch an unbounded body internally.
use std::{fmt, pin::Pin};

use futures_io::AsyncRead;
use futures_util::io::{AsyncReadExt, Cursor};
use ikigai_core::{Error, Result};

/// The default limit when an HTTP endpoint materializes a response (8 MiB).
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// An owned, single-consumer body. Dropping it cancels further reads.
///
/// `AsyncRead` lets the consumer bound each read, including the one-byte probe
/// needed to distinguish an exactly-full body from an oversized one. Hosts can
/// adapt their HTTP client's stream to a reader without collecting it first.
pub struct HttpBody {
    inner: Body,
}

enum Body {
    Bytes(Vec<u8>),
    Reader(Pin<Box<dyn AsyncRead + Send>>),
}

impl fmt::Debug for HttpBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HttpBody(<unread>)")
    }
}

impl HttpBody {
    /// Wrap an asynchronous reader without reading or allocating response bytes.
    pub fn from_reader(reader: impl AsyncRead + Send + 'static) -> Self {
        Self {
            inner: Body::Reader(Box::pin(reader)),
        }
    }

    /// Consume the body as a reader for incremental processing. The caller
    /// controls its own byte budget; endpoints use [`Self::collect`] instead.
    pub fn into_reader(self) -> Pin<Box<dyn AsyncRead + Send>> {
        match self.inner {
            Body::Bytes(bytes) => Box::pin(Cursor::new(bytes)),
            Body::Reader(reader) => reader,
        }
    }

    /// Buffered bytes, when this body was constructed from a `Vec`.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.inner {
            Body::Bytes(bytes) => Some(bytes),
            Body::Reader(_) => None,
        }
    }

    /// Collect at most `limit` bytes. Reads at most `limit + 1` bytes, stops on
    /// overflow, propagates I/O errors, and drops the reader on every exit path.
    /// The bound applies to actual bytes, independent of `Content-Length`.
    pub async fn collect(self, limit: usize) -> Result<Vec<u8>> {
        let mut reader = match self.inner {
            Body::Bytes(bytes) => {
                if bytes.len() > limit {
                    return Err(over_budget(limit));
                }
                return Ok(bytes);
            }
            Body::Reader(reader) => reader,
        };
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            let remaining = limit - bytes.len();
            let read_len = buffer.len().min(remaining.saturating_add(1));
            let count = reader.read(&mut buffer[..read_len]).await.map_err(|err| {
                crate::status::transport_error(
                    &err.to_string(),
                    "response body",
                    "reading HTTP response body",
                )
            })?;
            if count == 0 {
                return Ok(bytes);
            }
            if count > remaining {
                return Err(over_budget(limit));
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
    }
}

fn over_budget(limit: usize) -> Error {
    Error::OverBudget {
        detail: format!("HTTP response body exceeds {limit} bytes"),
    }
}

impl From<Vec<u8>> for HttpBody {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            inner: Body::Bytes(bytes),
        }
    }
}

impl Default for HttpBody {
    fn default() -> Self {
        Vec::new().into()
    }
}
