//! Runs the example code on the host: a TLS server serves the echo server, and the wss:// client
//! verifies its certificate chain against a root certificate authority.

#[path = "host/server_without_certificate.rs"]
mod server_without_certificate;

use std::{net::SocketAddr, sync::Arc, time::SystemTime};

use embassy_common::{serve_echo, wss_echo, Buffers, Error, WssTarget};
use embedded_io_adapters::tokio_1::FromTokio;
use embedded_tls::TlsClock;
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
    TlsAcceptor,
};
// links the operating system random number generator and the software crypto drivers
use {embassy_crypto_rand as _, embassy_crypto_rustcrypto as _};

struct HostClock;

impl TlsClock for HostClock {
    fn now() -> Option<u64> {
        Some(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
    }
}

struct NoTime;

impl TlsClock for NoTime {
    fn now() -> Option<u64> {
        None
    }
}

fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params
}

fn new_root() -> CertifiedIssuer<'static, KeyPair> {
    CertifiedIssuer::self_signed(ca_params(), KeyPair::generate().unwrap()).unwrap()
}

/// A server certificate for `host` under an intermediate of `root`, with its chain and key.
fn server_chain(root: &CertifiedIssuer<'_, KeyPair>, host: &str) -> (Vec<Vec<u8>>, KeyPair) {
    let intermediate_key = KeyPair::generate().unwrap();
    let intermediate_params = ca_params();
    let intermediate = intermediate_params
        .clone()
        .signed_by(&intermediate_key, root)
        .unwrap();
    let intermediate_issuer = Issuer::new(intermediate_params, intermediate_key);
    let server_key = KeyPair::generate().unwrap();
    let server = CertificateParams::new(vec![host.to_owned()])
        .unwrap()
        .signed_by(&server_key, &intermediate_issuer)
        .unwrap();
    (
        vec![server.der().to_vec(), intermediate.der().to_vec()],
        server_key,
    )
}

/// Serves one TLS connection with `chain` and runs the websocket echo server on it.
async fn tls_echo_server(chain: Vec<Vec<u8>>, key: &KeyPair) -> SocketAddr {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        chain.into_iter().map(CertificateDer::from).collect(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let Ok(tls) = TlsAcceptor::from(Arc::new(config)).accept(tcp).await else {
            return;
        };
        let mut buffers = Buffers::new();
        let _ = serve_echo(&mut FromTokio::new(tls), &mut buffers).await;
    });
    addr
}

async fn connect_and_echo<C: TlsClock>(
    addr: SocketAddr,
    ca_der: &[u8],
    host: &str,
) -> Result<String, Error> {
    let tcp = FromTokio::new(TcpStream::connect(addr).await.unwrap());
    let target = WssTarget {
        host,
        path: "/echo",
        ca_der,
    };
    let mut tls_read = vec![0; 16640];
    let mut tls_write = vec![0; 16640];
    let mut buffers = Buffers::new();
    let echo = wss_echo::<_, C>(
        tcp,
        &target,
        &mut tls_read,
        &mut tls_write,
        rand::rng(),
        &mut buffers,
        "hello over tls",
    )
    .await?;
    Ok(echo.to_owned())
}

#[tokio::test]
async fn client_gets_the_echo_from_a_server_under_the_root() {
    let root = new_root();
    let (chain, key) = server_chain(&root, "localhost");
    let addr = tls_echo_server(chain, &key).await;
    let echo = connect_and_echo::<HostClock>(addr, root.der(), "localhost").await;
    assert_eq!(echo.unwrap(), "hello over tls");
}

#[tokio::test]
async fn client_rejects_a_server_under_another_root() {
    let (chain, key) = server_chain(&new_root(), "localhost");
    let addr = tls_echo_server(chain, &key).await;
    assert!(matches!(
        connect_and_echo::<HostClock>(addr, new_root().der(), "localhost").await,
        Err(Error::Tls(_))
    ));
}

#[tokio::test]
async fn client_rejects_a_certificate_for_another_host() {
    let root = new_root();
    let (chain, key) = server_chain(&root, "localhost");
    let addr = tls_echo_server(chain, &key).await;
    assert!(matches!(
        connect_and_echo::<HostClock>(addr, root.der(), "example.com").await,
        Err(Error::Tls(_))
    ));
}

#[tokio::test]
async fn client_rejects_an_expired_certificate() {
    let root = new_root();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2021, 1, 1);
    let certificate = params.signed_by(&key, &root).unwrap();
    let addr = tls_echo_server(vec![certificate.der().to_vec()], &key).await;
    assert!(matches!(
        connect_and_echo::<HostClock>(addr, root.der(), "localhost").await,
        Err(Error::Tls(_))
    ));
}

#[tokio::test]
async fn client_rejects_a_chain_through_an_end_entity_certificate() {
    let root = new_root();
    let attacker_key = KeyPair::generate().unwrap();
    let mut attacker_params = CertificateParams::new(vec!["attacker.example".to_owned()]).unwrap();
    attacker_params.is_ca = IsCa::ExplicitNoCa;
    attacker_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let attacker = attacker_params
        .clone()
        .signed_by(&attacker_key, &root)
        .unwrap();
    let forged_key = KeyPair::generate().unwrap();
    let forged = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&forged_key, &Issuer::new(attacker_params, attacker_key))
        .unwrap();
    let chain = vec![forged.der().to_vec(), attacker.der().to_vec()];
    let addr = tls_echo_server(chain, &forged_key).await;
    assert!(matches!(
        connect_and_echo::<HostClock>(addr, root.der(), "localhost").await,
        Err(Error::Tls(_))
    ));
}

#[tokio::test]
async fn client_rejects_a_handshake_without_certificate_verify() {
    let root = new_root();
    let (chain, _) = server_chain(&root, "localhost");
    for certificate in [None, Some(chain[0].clone())] {
        let addr = server_without_certificate::spawn(certificate).await;
        assert!(matches!(
            connect_and_echo::<HostClock>(addr, root.der(), "localhost").await,
            Err(Error::Tls(_))
        ));
    }
}

#[tokio::test]
async fn client_does_not_connect_without_the_time() {
    let root = new_root();
    let (chain, key) = server_chain(&root, "localhost");
    let addr = tls_echo_server(chain, &key).await;
    assert!(matches!(
        connect_and_echo::<NoTime>(addr, root.der(), "localhost").await,
        Err(Error::ClockNotSet)
    ));
}
