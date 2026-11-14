//! HTTPS serving. The server always speaks TLS; there is no plain HTTP.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use larder_server_infrastructure::TlsIdentity;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// TLS 1.3 only, with ring's default cipher suites. Every client is the
/// Larder app, so there is no old client to stay compatible with.
pub fn server_config(identity: &TlsIdentity) -> Result<ServerConfig, String> {
    let cert = CertificateDer::from_pem_slice(identity.cert_pem.as_bytes())
        .map_err(|e| format!("stored TLS certificate is unreadable: {e}"))?;
    let key = PrivateKeyDer::from_pem_slice(identity.key_pem.as_bytes())
        .map_err(|e| format!("stored TLS key is unreadable: {e}"))?;
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| format!("TLS certificate and key do not match: {e}"))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// Serves `router` over HTTPS on `listener` until `shutdown` completes,
/// then lets open requests finish for up to 10 seconds.
pub async fn serve(
    listener: std::net::TcpListener,
    identity: &TlsIdentity,
    router: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    let config = RustlsConfig::from_config(Arc::new(server_config(identity)?));
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let handle = Handle::new();
    let stopper = handle.clone();
    tokio::spawn(async move {
        shutdown.await;
        stopper.graceful_shutdown(Some(Duration::from_secs(10)));
    });
    axum_server::from_tcp_rustls(listener, config)
        .map_err(|e| e.to_string())?
        .handle(handle)
        // Gives handlers the client's address, for limiting sign-in attempts.
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| format!("server stopped: {e}"))
}
