# compio-openssl

An asynchronous OpenSSL stream for [compio](https://github.com/compio-rs/compio/tree/master).

## Features

- **Asynchronous support**: Built on top of compio's asynchronous manner, async-based SSL/TLS communication.
- **Compatibility**: Maintain API compatibility with the original synchronous SslStream.
- **Wide OpenSSL version support**: Compatible with wide versions of OpenSSL just like the openssl crate dose.

*Note: to use TLS 1.3 early data, you need OpenSSL 1.1.1 at least.

## Example

``` rust
use compio::net::TcpStream;
use openssl::ssl::{SslConnector, SslMethod};

let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
let tls_connector = builder.build();

let stream = TcpStream::connect(("www.google.com", 443)).await.unwrap();
let tls_ctx = tls_connector.configure().unwrap().into_ssl("www.google.com").unwrap();
let mut stream = SslStream::new(tls_ctx, stream).unwrap();
stream.connect().await.unwrap();

// Now you get a full async TLS stream!
```

Fore more examples, see our [test](https://github.com/Incisakura/compio-openssl/blob/master/src/test.rs).

## Vendored

To make OpenSSL static links to your binary, please use openssl's `vendored` feature.

``` toml
[dependencies]
openssl = { version = "0.10", features = ["vendored"] }
```

## License

MIT License
