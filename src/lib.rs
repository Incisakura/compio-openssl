//! A compio asynchronous stream of OpenSSL stream.
//!
//! You can use [`SslStream::new`] to build a stream just like [`openssl:ssl::SslStream`](ssl::SslStream::new)
//! or setup a stream manually and convert it to [`SslStream`] using [`SslStream::from`].

use std::io::{self, ErrorKind, Write};
use std::result::Result;

use compio::BufResult;
use compio::buf::{IoBuf, IoBufMut};
use compio::io::compat::SyncStream;
use compio::io::{AsyncRead, AsyncWrite};
use openssl::error::ErrorStack;
use openssl::ssl::{self, ErrorCode, ShutdownResult, ShutdownState, Ssl, SslRef};

#[cfg(test)]
mod test;

/// Compio asynchronous version of [`openssl:ssl::SslStream`](ssl::SslStream).
#[derive(Debug)]
pub struct SslStream<S> {
    stream: ssl::SslStream<SyncStream<S>>,
}

impl<S: AsyncRead + AsyncWrite> SslStream<S> {
    /// Create a new `SslStream`.
    ///
    /// Reference: [`SslStream::new`](ssl::SslStream::new)
    pub fn new(ssl: Ssl, stream: S) -> Result<SslStream<S>, ErrorStack> {
        let stream = ssl::SslStream::new(ssl, SyncStream::new(stream))?;
        Ok(SslStream { stream })
    }

    /// Get a mutable reference to the underlying stream.
    ///
    /// # Warning
    ///
    /// Any read/write operation to the stream would most likely corrupt the SSL session.
    #[inline(always)]
    pub fn get_mut(&mut self) -> &mut S {
        self.stream.get_mut().get_mut()
    }

    /// Returns a shared reference to the underlying stream.
    #[inline(always)]
    pub fn get_ref(&self) -> &S {
        self.stream.get_ref().get_ref()
    }

    /// Returns a shared reference to the [`Ssl`] object associated with this stream.
    #[inline(always)]
    pub fn ssl(&self) -> &SslRef {
        self.stream.ssl()
    }

    /// Initiates a server-side TLS handshake.
    ///
    /// Reference: [`SslStream::accept`](ssl::SslStream::accept)
    pub async fn accept(&mut self) -> io::Result<()> {
        self.ssl_async_do(|s| s.accept()).await
    }

    /// Initiates a server-side TLS handshake.
    ///
    /// Reference: [`SslStream::connect`](ssl::SslStream::connect)
    pub async fn connect(&mut self) -> io::Result<()> {
        self.ssl_async_do(|s| s.connect()).await
    }

    /// Read application data transmitted by a client before handshake completion.
    ///
    /// Useful for reducing latency, but vulnerable to replay attacks.
    ///
    /// Returns Ok(0) if all early data has been read.
    ///
    /// Reference: [`SslStream::read_early_data`](ssl::SslStream::read_early_data)
    #[cfg(any(ossl111, libressl340))]
    pub async fn read_realy_data(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.ssl_async_do(|s| s.read_early_data(buf)).await
    }

    /// Send data to the server without blocking on handshake completion.
    ///
    /// Useful for reducing latency, but vulnerable to replay attacks.
    ///
    /// Reference: [`SslStream::write_early_data`](ssl::SslStream::write_early_data)
    #[cfg(any(ossl111, libressl340))]
    pub async fn write_realy_data(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ssl_async_do(|s| s.write_early_data(buf)).await
    }

    /// Reads data from the stream, without removing it from the queue.
    ///
    /// Reference: [`SslStream::ssl_peek`](ssl::SslStream::ssl_peek)
    pub async fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.ssl_async_do(|s| s.ssl_peek(buf)).await
    }

    /// Returns the session's shutdown state.
    #[inline(always)]
    pub fn get_shutdown(&mut self) -> ShutdownState {
        self.stream.get_shutdown()
    }

    /// Sets the session's shutdown state.
    ///
    /// This can be used to tell OpenSSL that the session should be cached even if a full two-way shutdown was not completed.
    #[inline(always)]
    pub fn set_shutdown(&mut self, state: ShutdownState) {
        self.stream.set_shutdown(state)
    }

    /// Perform a stateless server-side handshake.
    ///
    /// Requires that cookie generation and verification callbacks were
    /// set on the SSL context.
    ///
    /// Returns `Ok(true)` if a complete ClientHello containing a valid cookie
    /// was read, in which case the handshake should be continued via
    /// `accept`. If a HelloRetryRequest containing a fresh cookie was
    /// transmitted, `Ok(false)` is returned instead. If the handshake cannot
    /// proceed at all, `Err` is returned.
    #[inline(always)]
    #[cfg(ossl111)]
    pub async fn stateless(&mut self) -> Result<bool, ErrorStack> {
        self.stream.stateless()
    }

    async fn ssl_async_do<R, F>(&mut self, mut f: F) -> io::Result<R>
    where
        F: FnMut(&mut ssl::SslStream<SyncStream<S>>) -> Result<R, ssl::Error>,
    {
        loop {
            match f(&mut self.stream) {
                Ok(n) => return Ok(n),
                Err(e) => match e.code() {
                    ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => {
                        if self.stream.get_mut().flush_write_buf().await? == 0 {
                            self.stream.get_mut().fill_read_buf().await?;
                        }
                    }
                    _ => return Err(ssl_err_into_io(e)),
                },
            }
        }
    }
}

impl<S> From<ssl::SslStream<SyncStream<S>>> for SslStream<S> {
    fn from(value: ssl::SslStream<SyncStream<S>>) -> Self {
        SslStream { stream: value }
    }
}

#[inline]
fn ssl_err_into_io(err: openssl::ssl::Error) -> io::Error {
    err.into_io_error().unwrap_or_else(|e| io::Error::new(io::ErrorKind::Other, e))
}

impl<S: AsyncRead> AsyncRead for SslStream<S> {
    async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        let read_buf = buf.as_mut_slice();
        loop {
            let ret = self.stream.ssl_read_uninit(read_buf);
            match ret {
                Ok(n) => {
                    // SAFETY: the length we just read
                    unsafe { buf.set_buf_init(n) };
                    return BufResult(Ok(n), buf);
                }
                Err(e) if e.code() == ErrorCode::ZERO_RETURN => {
                    return BufResult(Ok(0), buf);
                }
                Err(e) if e.code() == ErrorCode::WANT_READ => {
                    match self.stream.get_mut().fill_read_buf().await {
                        Ok(_) => continue,
                        Err(e) => return BufResult(Err(e), buf),
                    }
                }
                Err(e) if e.code() == ErrorCode::SYSCALL && e.io_error().is_none() => {}
                Err(e) => return BufResult(Err(ssl_err_into_io(e)), buf),
            }
        }
    }

    // OpenSSL does not support vectored reads
}

/// `AsyncRead` is needed for shutting down stream.
impl<S: AsyncWrite + AsyncRead> AsyncWrite for SslStream<S> {
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        let slice = buf.as_slice();
        loop {
            let ret = self.stream.ssl_write(slice);
            match ret {
                Ok(n) => {
                    let ret = self.stream.get_mut().flush_write_buf().await;
                    return BufResult(ret.map(|_| n), buf);
                }
                Err(e) if e.code() == ErrorCode::WANT_WRITE => {
                    match self.stream.get_mut().flush_write_buf().await {
                        Ok(_) => continue,
                        Err(e) => return BufResult(Err(e), buf),
                    }
                }
                Err(e) => return BufResult(Err(ssl_err_into_io(e)), buf),
            }
        }
    }

    // OpenSSL does not support vectored writes

    async fn flush(&mut self) -> io::Result<()> {
        loop {
            match self.stream.flush() {
                Ok(_) => {
                    self.stream.get_mut().flush_write_buf().await?;
                    return Ok(());
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    self.stream.get_mut().flush_write_buf().await?;
                }
                e => return e,
            }
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        loop {
            let ret = self.stream.shutdown();
            match ret {
                Ok(ShutdownResult::Sent) => {
                    self.stream.get_mut().flush_write_buf().await?;
                }
                Ok(ShutdownResult::Received) => {
                    break;
                }
                Err(e) if e.code() == ErrorCode::WANT_WRITE => {
                    self.stream.get_mut().flush_write_buf().await?;
                }
                Err(e) if e.code() == ErrorCode::WANT_READ => {
                    self.stream.get_mut().fill_read_buf().await?;
                }
                Err(e) if e.code() == ErrorCode::SYSCALL && e.io_error().is_none() => {
                    break;
                }
                Err(e) => return Err(ssl_err_into_io(e)),
            }
        }
        self.stream.get_mut().get_mut().shutdown().await
    }
}
