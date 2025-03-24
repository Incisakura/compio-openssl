use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::time::Duration;

use compio::io::{AsyncReadExt, AsyncWrite};
use compio::net::{TcpListener, TcpStream};
use openssl::ssl::{Ssl, SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode};

use super::SslStream;

const TEST_PAYLOAD: &[u8] = include_bytes!("../README.md");

#[compio::test]
async fn self_test() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 10443)).await.unwrap();
    let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server()).unwrap();
    builder.set_certificate_chain_file("./test/public.pem").unwrap();
    builder.set_private_key_file("./test/privkey.pem", SslFiletype::PEM).unwrap();
    let tls_acceptor = builder.build();

    let server_task = compio::runtime::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = SslStream::new(Ssl::new(tls_acceptor.context()).unwrap(), stream).unwrap();
        stream.accept().await.unwrap();
        let buf = Vec::with_capacity(TEST_PAYLOAD.len());
        let (_, buf) = stream.read_to_end(buf).await.unwrap();
        assert_eq!(buf, TEST_PAYLOAD);
    });

    // client
    let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);
    let tls_connector = builder.build();
    let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, 10443)).await.unwrap();
    let tls_ctx = tls_connector.configure().unwrap().into_ssl("localhost").unwrap();
    let mut stream = SslStream::new(tls_ctx, stream).unwrap();
    stream.connect().await.unwrap();
    stream.write(TEST_PAYLOAD).await.unwrap();
    stream.shutdown().await.unwrap();
    server_task.await.unwrap();
}

#[allow(clippy::zombie_processes)]
#[compio::test]
async fn client_test() {
    let mut child = Command::new("bash")
        .arg("-c")
        .arg("openssl s_server -cert test/public.pem -key test/privkey.pem -accept 127.0.0.1:10444 -WWW")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // wait openssl to setup
    std::thread::sleep(Duration::from_secs(1));

    let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);
    let tls_connector = builder.build();
    let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, 10444)).await.unwrap();
    let tls_ctx = tls_connector.configure().unwrap().into_ssl("localhost").unwrap();
    let mut stream = SslStream::new(tls_ctx, stream).unwrap();
    stream.connect().await.unwrap();

    // emit request
    let body = b"GET /README.md HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write(body).await.unwrap();

    // receive response
    let header = b"HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\n";
    let (_, body) = stream.read_to_end(Vec::with_capacity(header.len() + TEST_PAYLOAD.len())).await.unwrap();

    child.kill().unwrap();
    assert_eq!(&body[..header.len()], header);
    assert_eq!(&body[header.len()..], TEST_PAYLOAD);
}

#[allow(clippy::zombie_processes)]
#[compio::test]
async fn server_test() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 10445)).await.unwrap();
    let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server()).unwrap();
    builder.set_certificate_chain_file("./test/public.pem").unwrap();
    builder.set_private_key_file("./test/privkey.pem", SslFiletype::PEM).unwrap();
    let tls_acceptor = builder.build();

    let mut child = Command::new("bash")
        .arg("-c")
        .arg("openssl s_client -connect localhost:10445 -servername localhost < README.md")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let (stream, _) = listener.accept().await.unwrap();
    let mut stream = SslStream::new(Ssl::new(tls_acceptor.context()).unwrap(), stream).unwrap();
    stream.accept().await.unwrap();
    let (_, buf) = stream.read_to_end(Vec::new()).await.unwrap();

    child.kill().unwrap();
    assert_eq!(buf, TEST_PAYLOAD);
}
