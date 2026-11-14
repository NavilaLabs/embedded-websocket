//! Runs the example code on the host: a TLS server serves the echo server, and the wss:// client
//! talks to it and only trusts the server key it pins.

#[path = "host/server_without_certificate.rs"]
mod server_without_certificate;

use std::{net::SocketAddr, sync::Arc};

use embassy_common::{serve_echo, wss_echo, Buffers, Error, WssTarget};
use embedded_io_adapters::tokio_1::FromTokio;
use rcgen::{CertificateParams, CertifiedIssuer, KeyPair, PublicKeyData};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
    TlsAcceptor,
};

struct TestPki {
    certificate_der: Vec<u8>,
    server_key_der: Vec<u8>,
    server_config: Arc<rustls::ServerConfig>,
}

fn test_pki(server_name: &str) -> TestPki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let server_key = KeyPair::generate().unwrap();
    let server_cert = CertificateParams::new(vec![server_name.to_owned()])
        .unwrap()
        .signed_by(&server_key, &ca)
        .unwrap();

    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![
            CertificateDer::from(server_cert.der().to_vec()),
            CertificateDer::from(ca.der().to_vec()),
        ],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
    )
    .unwrap();
    TestPki {
        certificate_der: server_cert.der().to_vec(),
        server_key_der: server_key.subject_public_key_info(),
        server_config: Arc::new(server_config),
    }
}

/// Accepts one TLS connection and serves the websocket echo server on it.
async fn tls_echo_server(server_config: Arc<rustls::ServerConfig>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let Ok(tls) = TlsAcceptor::from(server_config).accept(tcp).await else {
            return;
        };
        let mut buffers = Buffers::new();
        let _ = serve_echo(&mut FromTokio::new(tls), &mut buffers).await;
    });
    addr
}

async fn connect_and_echo(addr: SocketAddr, server_key_der: &[u8]) -> Result<String, Error> {
    let tcp = FromTokio::new(TcpStream::connect(addr).await.unwrap());
    let target = WssTarget {
        host: "localhost",
        path: "/echo",
        server_key_der,
    };
    let mut tls_read = vec![0; 16640];
    let mut tls_write = vec![0; 16640];
    let mut buffers = Buffers::new();
    let echo = wss_echo(
        tcp,
        &target,
        &mut tls_read,
        &mut tls_write,
        rand_core_06::OsRng,
        rand::rng(),
        &mut buffers,
        "hello over tls",
    )
    .await?;
    Ok(echo.to_owned())
}

#[tokio::test]
async fn client_gets_the_echo_from_the_pinned_server() {
    let pki = test_pki("localhost");
    let addr = tls_echo_server(pki.server_config.clone()).await;
    let echo = connect_and_echo(addr, &pki.server_key_der).await.unwrap();
    assert_eq!(echo, "hello over tls");
}

#[tokio::test]
async fn client_rejects_a_server_with_another_key() {
    let pki = test_pki("localhost");
    let other = test_pki("localhost");
    let addr = tls_echo_server(pki.server_config.clone()).await;
    assert!(matches!(
        connect_and_echo(addr, &other.server_key_der).await,
        Err(Error::Tls(_))
    ));
}

#[tokio::test]
async fn client_rejects_a_handshake_without_certificate_verify() {
    let pki = test_pki("localhost");
    for certificate in [None, Some(pki.certificate_der.clone())] {
        let addr = server_without_certificate::spawn(certificate).await;
        assert!(matches!(
            connect_and_echo(addr, &pki.server_key_der).await,
            Err(Error::ServerNotAuthenticated)
        ));
    }
}

#[tokio::test]
async fn client_refuses_a_pinned_key_that_is_not_a_p256_key() {
    let addr = server_without_certificate::spawn(None).await;
    assert!(matches!(
        connect_and_echo(addr, b"not a key").await,
        Err(Error::InvalidServerKey)
    ));
}
