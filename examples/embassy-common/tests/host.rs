//! Runs the example code on the host: a TLS server with a test certificate authority serves the
//! echo server, and the wss:// client talks to it with certificate verification.

use std::{net::SocketAddr, sync::Arc};

use embassy_common::{serve_echo, wss_echo, Buffers, Error, WssTarget};
use embedded_io_adapters::tokio_1::FromTokio;
use rcgen::{CertificateParams, CertifiedIssuer, KeyPair};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
    TlsAcceptor,
};

struct TestPki {
    ca_der: Vec<u8>,
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
        ca_der: ca.der().to_vec(),
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

async fn connect_and_echo(pki: &TestPki, ca_der: &[u8], host: &str) -> Result<String, Error> {
    let addr = tls_echo_server(pki.server_config.clone()).await;
    let tcp = FromTokio::new(TcpStream::connect(addr).await.unwrap());
    let target = WssTarget {
        host,
        path: "/echo",
        ca_der,
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
async fn client_gets_the_echo_from_a_verified_server() {
    let pki = test_pki("localhost");
    let echo = connect_and_echo(&pki, &pki.ca_der, "localhost")
        .await
        .unwrap();
    assert_eq!(echo, "hello over tls");
}

#[tokio::test]
async fn client_rejects_a_server_signed_by_another_authority() {
    let pki = test_pki("localhost");
    let other = test_pki("localhost");
    assert!(matches!(
        connect_and_echo(&pki, &other.ca_der, "localhost").await,
        Err(Error::Tls(_))
    ));
}

#[tokio::test]
async fn client_rejects_a_certificate_for_another_host() {
    let pki = test_pki("localhost");
    assert!(matches!(
        connect_and_echo(&pki, &pki.ca_der, "example.com").await,
        Err(Error::Tls(_))
    ));
}
