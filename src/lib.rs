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

pub struct SslStream<S> {
    stream: ssl::SslStream<SyncStream<S>>,
}

impl<S: AsyncRead + AsyncWrite> SslStream<S> {
    pub fn new(ssl: Ssl, stream: S) -> Result<SslStream<S>, ErrorStack> {
        let stream = ssl::SslStream::new(ssl, SyncStream::new(stream))?;
        Ok(SslStream { stream })
    }

    #[inline(always)]
    pub fn get_mut(&mut self) -> &mut S {
        self.stream.get_mut().get_mut()
    }

    #[inline(always)]
    pub fn get_ref(&self) -> &S {
        self.stream.get_ref().get_ref()
    }

    #[inline(always)]
    pub fn ssl(&self) -> &SslRef {
        self.stream.ssl()
    }

    pub async fn accept(&mut self) -> io::Result<()> {
        self.ssl_async_do(|s| s.accept()).await
    }

    pub async fn connect(&mut self) -> io::Result<()> {
        self.ssl_async_do(|s| s.connect()).await
    }

    pub async fn read_realy_data(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.ssl_async_do(|s| s.read_early_data(buf)).await
    }

    pub async fn write_realy_data(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ssl_async_do(|s| s.write_early_data(buf)).await
    }

    pub async fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.ssl_async_do(|s| s.ssl_peek(buf)).await
    }

    #[inline(always)]
    pub fn get_shutdown(&mut self) -> ShutdownState {
        self.stream.get_shutdown()
    }

    #[inline(always)]
    pub fn set_shutdown(&mut self, state: ShutdownState) {
        self.stream.set_shutdown(state)
    }

    #[inline(always)]
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
                    ErrorCode::WANT_READ | ErrorCode::WANT_WRITE  => {
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
                },
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
                    return BufResult(ret.map(|_| n), buf)
                },
                Err(e) if e.code() == ErrorCode::WANT_WRITE => {
                    match self.stream.get_mut().flush_write_buf().await {
                        Ok(_) => continue,
                        Err(e) => return BufResult(Err(e), buf),
                    }
                },
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
