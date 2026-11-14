//! A TLS 1.3 server that completes the handshake without CertificateVerify, so without proving
//! that it holds any key, as an attacker on the network path can: its Finished is valid because
//! it only depends on the ECDHE exchange (RFC 8446 section 4.4.4). It may send a Certificate, for
//! example the public certificate of the real server.

use std::{net::SocketAddr, time::Duration};

use aes_gcm::{aead::Aead, aead::Payload, Aes128Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const KEY_SHARE: u16 = 0x0033;
const SECP256R1: u16 = 0x0017;

/// Accepts one connection and answers its ClientHello with a handshake that proves nothing,
/// with `certificate` in a Certificate message if it is given.
pub async fn spawn(certificate: Option<Vec<u8>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let client_hello = read_record(&mut tcp).await;
        respond(&mut tcp, &client_hello, certificate.as_deref()).await;
        // the client either gives up or continues; give it a moment, then hang up
        let mut sink = [0; 1024];
        let _ = tokio::time::timeout(Duration::from_secs(1), tcp.read(&mut sink)).await;
    });
    addr
}

async fn read_record(tcp: &mut TcpStream) -> Vec<u8> {
    let mut header = [0; 5];
    tcp.read_exact(&mut header).await.unwrap();
    let mut body = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
    tcp.read_exact(&mut body).await.unwrap();
    body
}

async fn respond(tcp: &mut TcpStream, client_hello: &[u8], certificate: Option<&[u8]>) {
    let (session_id, client_key) = parse_client_hello(client_hello);
    let secret = EphemeralSecret::random(&mut rand_core_06::OsRng);
    let shared = secret.diffie_hellman(&PublicKey::from_sec1_bytes(&client_key).unwrap());

    let mut server_hello_body = vec![0x03, 0x03];
    server_hello_body.extend([7; 32]);
    server_hello_body.push(session_id.len() as u8);
    server_hello_body.extend(&session_id);
    server_hello_body.extend([0x13, 0x01, 0x00]);
    let point = EncodedPoint::from(secret.public_key());
    let mut extensions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
    extensions.extend(KEY_SHARE.to_be_bytes());
    extensions.extend(((point.len() + 4) as u16).to_be_bytes());
    extensions.extend(SECP256R1.to_be_bytes());
    extensions.extend((point.len() as u16).to_be_bytes());
    extensions.extend(point.as_bytes());
    server_hello_body.extend((extensions.len() as u16).to_be_bytes());
    server_hello_body.extend(extensions);
    let server_hello = handshake_message(2, &server_hello_body);

    let mut transcript = Sha256::new();
    transcript.update(client_hello);
    transcript.update(&server_hello);
    let server_secret =
        handshake_traffic_secret(shared.raw_secret_bytes(), &transcript.clone().finalize());

    let mut messages = handshake_message(8, &[0, 0]);
    if let Some(certificate) = certificate {
        let mut entry = (certificate.len() as u32).to_be_bytes()[1..].to_vec();
        entry.extend(certificate);
        entry.extend([0, 0]);
        let mut body = vec![0];
        body.extend(&(entry.len() as u32).to_be_bytes()[1..]);
        body.extend(entry);
        messages.extend(handshake_message(11, &body));
    }
    transcript.update(&messages);
    let finished_key = expand_label(&server_secret, "finished", &[], 32);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&finished_key).unwrap();
    mac.update(&transcript.finalize());
    let finished = handshake_message(20, &mac.finalize().into_bytes());

    let mut inner = messages;
    inner.extend(finished);
    inner.push(0x16);
    let key = expand_label(&server_secret, "key", &[], 16);
    let iv = expand_label(&server_secret, "iv", &[], 12);
    let mut header = vec![0x17, 0x03, 0x03];
    header.extend(((inner.len() + 16) as u16).to_be_bytes());
    let ciphertext = Aes128Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: &inner,
                aad: &header,
            },
        )
        .unwrap();

    let mut flight = record(0x16, &server_hello);
    flight.extend([0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    flight.extend(header);
    flight.extend(ciphertext);
    tcp.write_all(&flight).await.unwrap();
}

/// Returns the legacy session id and the P-256 key share of a ClientHello handshake message.
fn parse_client_hello(message: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let body = &message[4..];
    let mut at = 2 + 32;
    let session_id = body[at + 1..at + 1 + body[at] as usize].to_vec();
    at += 1 + body[at] as usize;
    at += 2 + u16::from_be_bytes([body[at], body[at + 1]]) as usize;
    at += 1 + body[at] as usize;
    let end = at + 2 + u16::from_be_bytes([body[at], body[at + 1]]) as usize;
    at += 2;
    while at < end {
        let kind = u16::from_be_bytes([body[at], body[at + 1]]);
        let len = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
        let data = &body[at + 4..at + 4 + len];
        if kind == KEY_SHARE {
            let mut share = 2;
            while share < data.len() {
                let group = u16::from_be_bytes([data[share], data[share + 1]]);
                let key_len = u16::from_be_bytes([data[share + 2], data[share + 3]]) as usize;
                if group == SECP256R1 {
                    return (session_id, data[share + 4..share + 4 + key_len].to_vec());
                }
                share += 4 + key_len;
            }
        }
        at += 4 + len;
    }
    panic!("the client offers no P-256 key share");
}

fn handshake_traffic_secret(shared: &[u8], hello_hash: &[u8]) -> Vec<u8> {
    let (early_secret, _) = Hkdf::<Sha256>::extract(Some(&[0; 32]), &[0; 32]);
    let derived = expand_label(&early_secret, "derived", &Sha256::digest([]), 32);
    let (handshake_secret, _) = Hkdf::<Sha256>::extract(Some(&derived), shared);
    expand_label(&handshake_secret, "s hs traffic", hello_hash, 32)
}

// RFC 8446 section 7.1
fn expand_label(secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let label = format!("tls13 {label}");
    let mut info = (len as u16).to_be_bytes().to_vec();
    info.push(label.len() as u8);
    info.extend(label.as_bytes());
    info.push(context.len() as u8);
    info.extend(context);
    let mut out = vec![0; len];
    Hkdf::<Sha256>::from_prk(secret)
        .unwrap()
        .expand(&info, &mut out)
        .unwrap();
    out
}

fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut message = vec![kind];
    message.extend(&(body.len() as u32).to_be_bytes()[1..]);
    message.extend(body);
    message
}

fn record(content_type: u8, fragment: &[u8]) -> Vec<u8> {
    let mut record = vec![content_type, 0x03, 0x03];
    record.extend((fragment.len() as u16).to_be_bytes());
    record.extend(fragment);
    record
}
