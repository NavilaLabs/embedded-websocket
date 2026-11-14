//! Application code shared by the embassy examples. It works on any stream that implements the
//! `embedded-io-async` traits, for example the `TcpSocket` of `embassy-net`, so the board crates
//! only set up the hardware and the network.
//!
//! TLS needs a random number generator registered with `embassy-crypto`, which each board crate
//! provides.
#![no_std]

pub mod sntp;

use embedded_io_async::{Read, Write};
use embedded_io_websocket::{
    asynch::Framer, Decision, FramerError, FramerState, ReadResult, WebSocketClient,
    WebSocketCloseStatusCode, WebSocketOptions, WebSocketSendMessageType, WebSocketServer,
    MIN_FRAME_BUF_LEN,
};
use embedded_tls::{
    webpki::CertVerifier, Aes128GcmSha256, Certificate, TlsClock, TlsConfig, TlsConnection,
    TlsContext, TlsError,
};
use rand_core::CryptoRng;
// a crate that is never named is not linked, and this one provides the software crypto drivers
use embassy_crypto_rustcrypto as _;

pub use sntp::NetworkClock;

/// The largest server certificate, without its chain, that [`wss_echo`] accepts.
pub const MAX_SERVER_CERTIFICATE_LEN: usize = 4096;

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
    /// The host name, which the server certificate must name.
    pub host: &'a str,
    /// The path of the websocket, for example `/echo`.
    pub path: &'a str,
    /// The DER encoded root certificate that the chain of the server must lead to, for example
    /// ISRG Root X2 for a Let's Encrypt ECDSA certificate. Only ECDSA P-256 and P-384 signatures
    /// are checked.
    pub ca_der: &'a [u8],
}

/// An error of [`wss_echo`].
#[derive(Debug)]
pub enum Error {
    /// The clock does not know the time yet, so certificate dates cannot be checked.
    ClockNotSet,
    /// The TLS connection failed, for example because the certificate of the server is not valid.
    Tls(TlsError),
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

/// Opens a `wss://` connection over `stream`, sends `message`, returns the text the server
/// answers with and closes the connection.
///
/// The certificate chain of the server must lead to `target.ca_der`, name `target.host` and be
/// valid at the time `Clock` gives, for example [`NetworkClock`]. `tls_read` must fit a whole
/// TLS record, which is up to 16640 bytes. `websocket_rng` only masks frames.
///
/// # Errors
///
/// * [`Error::ClockNotSet`] if `Clock` does not know the time.
/// * [`Error::Tls`] if the TLS handshake fails, including a certificate that is not valid for
///   `target`.
/// * [`Error::WebSocket`] if the opening handshake or a frame fails.
/// * [`Error::UnexpectedReply`] if the server does not answer with a text message.
pub async fn wss_echo<'b, S: Read + Write, Clock: TlsClock>(
    stream: S,
    target: &WssTarget<'_>,
    tls_read: &mut [u8],
    tls_write: &mut [u8],
    websocket_rng: impl CryptoRng,
    buffers: &'b mut Buffers,
    message: &str,
) -> Result<&'b str, Error> {
    // without the time the verifier would skip the dates and accept an expired certificate
    if Clock::now().is_none() {
        return Err(Error::ClockNotSet);
    }
    let config = TlsConfig::new().with_server_name(target.host);
    let verifier: CertVerifier<Aes128GcmSha256, Clock, MAX_SERVER_CERTIFICATE_LEN> =
        CertVerifier::new(Certificate::X509(target.ca_der));
    let mut tls = TlsConnection::new(stream, tls_read, tls_write);
    tls.open(TlsContext::new(&config, verifier))
        .await
        .map_err(Error::Tls)?;

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
