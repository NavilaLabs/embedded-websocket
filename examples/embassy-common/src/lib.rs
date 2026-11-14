//! Application code shared by the embassy examples. It works on any stream that implements the
//! `embedded-io-async` traits, for example the `TcpSocket` of `embassy-net`, so the board crates
//! only set up the hardware and the network.
#![no_std]

use embedded_io_async::{Read, Write};
use embedded_io_websocket::{
    asynch::Framer, Decision, FramerError, FramerState, ReadResult, WebSocketClient,
    WebSocketCloseStatusCode, WebSocketOptions, WebSocketSendMessageType, WebSocketServer,
    MIN_FRAME_BUF_LEN,
};
use embedded_tls::{
    Aes128GcmSha256, CertificateRef, CertificateVerifyRef, CryptoProvider, CryptoRngCore,
    SignatureScheme, TlsConfig, TlsConnection, TlsContext, TlsError, TlsVerifier,
};
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use rand_core::Rng;
use sha2::{Digest, Sha256};

/// The buffers of one websocket connection.
pub struct Buffers {
    read: [u8; 1024],
    write: [u8; 1024],
    frame: [u8; 1024],
}

impl Buffers {
    /// Creates zeroed buffers.
    pub const fn new() -> Self {
        Self {
            read: [0; 1024],
            write: [0; 1024],
            frame: [0; 1024],
        }
    }
}

impl Default for Buffers {
    fn default() -> Self {
        Self::new()
    }
}

/// The server a [`wss_echo`] client connects to.
pub struct WssTarget<'a> {
    /// The host name, sent in the TLS handshake and the `Host` header.
    pub host: &'a str,
    /// The path of the websocket, for example `/echo`.
    pub path: &'a str,
    /// The public key of the server as DER encoded SubjectPublicKeyInfo, which must be an ECDSA
    /// P-256 key. Only a server that proves it holds the matching private key is trusted; its
    /// certificate is not inspected. Keep the key when renewing the certificate, or the
    /// firmware must be rebuilt.
    pub server_key_der: &'a [u8],
}

/// An error of [`wss_echo`].
#[derive(Debug)]
pub enum Error {
    /// The TLS connection failed, for example because the server signed the handshake with
    /// another key than the pinned one.
    Tls(TlsError),
    /// The TLS handshake completed without the server proving that it holds the pinned key.
    ServerNotAuthenticated,
    /// [`WssTarget::server_key_der`] is not a DER encoded ECDSA P-256 public key.
    InvalidServerKey,
    /// The websocket failed.
    WebSocket(FramerError<TlsError>),
    /// The server answered with something other than a text message.
    UnexpectedReply,
}

impl From<FramerError<TlsError>> for Error {
    fn from(error: FramerError<TlsError>) -> Self {
        match error {
            FramerError::Io(error) => Error::Tls(error),
            error => Error::WebSocket(error),
        }
    }
}

// Trusts a server only after it signed the handshake transcript with the pinned key in its
// CertificateVerify message (RFC 8446 section 4.4.3). embedded-tls also completes a handshake in
// which the server sends no Certificate or CertificateVerify at all, so `is_authenticated` must
// be checked after the handshake.
struct PinnedKeyVerifier {
    key: VerifyingKey,
    certificate_transcript: Option<Sha256>,
    is_authenticated: bool,
}

impl TlsVerifier<Aes128GcmSha256> for PinnedKeyVerifier {
    fn set_hostname_verification(&mut self, _hostname: &str) -> Result<(), TlsError> {
        // the pinned key identifies the server, whatever names its certificate holds
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        transcript: &Sha256,
        _certificate: CertificateRef,
    ) -> Result<(), TlsError> {
        self.certificate_transcript = Some(transcript.clone());
        Ok(())
    }

    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), TlsError> {
        let transcript = self
            .certificate_transcript
            .take()
            .ok_or(TlsError::InvalidSignature)?;
        if verify.signature_scheme != SignatureScheme::EcdsaSecp256r1Sha256 {
            return Err(TlsError::InvalidSignature);
        }
        let signature =
            Signature::from_der(verify.signature).map_err(|_| TlsError::InvalidSignature)?;
        let mut message = [0x20; 64 + 34 + 32];
        message[64..98].copy_from_slice(b"TLS 1.3, server CertificateVerify\0");
        message[98..].copy_from_slice(&transcript.finalize());
        self.key
            .verify(&message, &signature)
            .map_err(|_| TlsError::InvalidSignature)?;
        self.is_authenticated = true;
        Ok(())
    }
}

struct PinnedKeyProvider<R> {
    rng: R,
    verifier: PinnedKeyVerifier,
}

impl<R: CryptoRngCore> CryptoProvider for PinnedKeyProvider<R> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = &'static [u8];

    fn rng(&mut self) -> impl CryptoRngCore {
        &mut self.rng
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, TlsError> {
        Ok(&mut self.verifier)
    }
}

/// Opens a `wss://` connection to the server with the pinned key over `stream`, sends `message`, returns the text the
/// server answers with and closes the connection.
///
/// `tls_read` must fit a whole TLS record, which is up to 16640 bytes. `tls_rng` must be a
/// cryptographically secure random number generator; `websocket_rng` only masks frames.
///
/// # Errors
///
/// * [`Error::InvalidServerKey`] if `target.server_key_der` is not an ECDSA P-256 public key.
/// * [`Error::Tls`] if the TLS handshake fails, including a server that signs it with another key.
/// * [`Error::ServerNotAuthenticated`] if the server completes the handshake without signing it.
/// * [`Error::WebSocket`] if the opening handshake or a frame fails.
/// * [`Error::UnexpectedReply`] if the server does not answer with a text message.
#[allow(clippy::too_many_arguments)]
pub async fn wss_echo<'b, S: Read + Write>(
    stream: S,
    target: &WssTarget<'_>,
    tls_read: &mut [u8],
    tls_write: &mut [u8],
    tls_rng: impl CryptoRngCore,
    websocket_rng: impl Rng,
    buffers: &'b mut Buffers,
    message: &str,
) -> Result<&'b str, Error> {
    let key = VerifyingKey::from_public_key_der(target.server_key_der)
        .map_err(|_| Error::InvalidServerKey)?;
    let config = TlsConfig::new().with_server_name(target.host);
    let mut provider = PinnedKeyProvider {
        rng: tls_rng,
        verifier: PinnedKeyVerifier {
            key,
            certificate_transcript: None,
            is_authenticated: false,
        },
    };
    let mut tls = TlsConnection::new(stream, tls_read, tls_write);
    tls.open(TlsContext::new(&config, &mut provider))
        .await
        .map_err(Error::Tls)?;
    if !provider.verifier.is_authenticated {
        return Err(Error::ServerNotAuthenticated);
    }

    let mut state = FramerState::new();
    let mut websocket = WebSocketClient::new_client(websocket_rng);
    let Buffers { read, write, frame } = buffers;
    let mut framer = Framer::new(read, &mut state, write, &mut websocket);
    let options = WebSocketOptions {
        path: target.path,
        host: target.host,
        origin: None,
        sub_protocols: None,
        additional_headers: None,
    };
    framer.connect(&mut tls, &options).await?;
    framer
        .write(
            &mut tls,
            WebSocketSendMessageType::Text,
            true,
            message.as_bytes(),
        )
        .await?;
    let echo_len = match framer.read(&mut tls, frame).await? {
        ReadResult::Text(echo) => echo.len(),
        _ => return Err(Error::UnexpectedReply),
    };

    framer
        .close(&mut tls, WebSocketCloseStatusCode::NormalClosure, None)
        .await?;
    // a separate buffer for the close handshake keeps the echo in `frame`
    let mut close_payload = [0; MIN_FRAME_BUF_LEN];
    while !matches!(
        framer.read(&mut tls, &mut close_payload).await?,
        ReadResult::Closed { .. } | ReadResult::Disconnected
    ) {}
    // the websocket is closed either way, so a failed TLS close changes nothing
    let _ = tls.close().await;

    core::str::from_utf8(&frame[..echo_len]).map_err(|_| Error::UnexpectedReply)
}

/// Accepts a websocket on `stream` and sends every text and binary message back until the
/// client closes it.
///
/// # Errors
///
/// Any error of the framer, see [`Framer::accept`] and [`Framer::read`].
pub async fn serve_echo<S: Read + Write>(
    stream: &mut S,
    buffers: &mut Buffers,
) -> Result<(), FramerError<S::Error>> {
    let mut state = FramerState::new();
    let mut websocket = WebSocketServer::new_server();
    let Buffers { read, write, frame } = buffers;
    let mut framer = Framer::new(read, &mut state, write, &mut websocket);
    if !framer
        .accept(stream, |_| Decision::Accept { sub_protocol: None })
        .await?
    {
        return Ok(());
    }
    loop {
        match framer.read(stream, frame).await? {
            ReadResult::Text(text) => {
                framer
                    .write(
                        stream,
                        WebSocketSendMessageType::Text,
                        true,
                        text.as_bytes(),
                    )
                    .await?
            }
            ReadResult::Binary(binary) => {
                framer
                    .write(stream, WebSocketSendMessageType::Binary, true, binary)
                    .await?
            }
            ReadResult::Pong(_) => {}
            ReadResult::Closed { .. } | ReadResult::Disconnected => return Ok(()),
        }
    }
}
