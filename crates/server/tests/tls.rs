//! The real listener: HTTPS with the stored certificate, nothing in clear.

use std::sync::Arc;

use larder_server::{AppState, router, tls};
use larder_server_infrastructure::{Argon2Hasher, Db, TlsIdentity};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Starts the server on a free port and returns its address.
async fn start(identity: &TlsIdentity) -> std::net::SocketAddr {
    let state = AppState::new(
        Db::in_memory().await.unwrap(),
        Arc::new(Argon2Hasher::insecure_fast()),
        true,
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let identity = identity.clone();
    tokio::spawn(async move {
        tls::serve(listener, &identity, router(state), std::future::pending()).await
    });
    addr
}

/// A client that trusts exactly `trusted` as its root.
fn client(trusted: &TlsIdentity) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(trusted.cert_pem.as_bytes()).unwrap())
        .unwrap();
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

async fn get_health(
    addr: std::net::SocketAddr,
    connector: TlsConnector,
) -> std::io::Result<String> {
    let tcp = TcpStream::connect(addr).await?;
    let name = ServerName::try_from("localhost").unwrap();
    let mut stream = connector.connect(name, tcp).await?;
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
}

#[tokio::test]
async fn serves_https_with_its_certificate() {
    let identity = TlsIdentity::generate().unwrap();
    let addr = start(&identity).await;
    let response = get_health(addr, client(&identity)).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains(r#""status":"ok""#));
}

#[tokio::test]
async fn a_client_expecting_another_certificate_is_refused() {
    let identity = TlsIdentity::generate().unwrap();
    let addr = start(&identity).await;
    let other = TlsIdentity::generate().unwrap();
    assert!(get_health(addr, client(&other)).await.is_err());
}

#[tokio::test]
async fn plain_http_gets_no_answer() {
    let identity = TlsIdentity::generate().unwrap();
    let addr = start(&identity).await;
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = tcp.read_to_end(&mut response).await;
    assert!(!String::from_utf8_lossy(&response).contains("200"));
}
