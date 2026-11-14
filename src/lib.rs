//! A `no_std` websocket library (RFC 6455) for clients and servers, with framers for streams that
//! implement the [`embedded_io`] or [`embedded_io_async`](https://docs.rs/embedded-io-async) traits.
//!
//! # Framers
//!
//! Start with [`blocking::Framer`], or [`asynch::Framer`] with the `asynch` feature. A framer
//! works on buffers you provide and reads and writes whole messages:
//!
//! * The client performs the opening handshake with `connect`, the server with `accept`, which
//!   lets you decide per request whether to open a websocket, for example by path.
//! * `read` returns whole text and binary messages, answers pings and completes a close
//!   handshake the other party starts. If the other party violates the protocol, the framer
//!   closes the connection with the matching status code.
//! * `read_chunk` returns messages larger than the frame buffer in chunks, see [`ReadChunk`].
//! * `write` splits messages that do not fit into the write buffer into several frames.
//!
//! A read or write that fails, or is cancelled in the async framer, can be called again with a
//! framer created from the same buffers and [`FramerState`]: it continues where it stopped.
//!
//! ```no_run
//! use embedded_io_websocket::{
//!     blocking::Framer, FramerError, FramerState, ReadResult, WebSocketClient, WebSocketOptions,
//!     WebSocketSendMessageType,
//! };
//!
//! fn echo_once<S: embedded_io::Read + embedded_io::Write>(
//!     stream: &mut S,
//! ) -> Result<(), FramerError<S::Error>> {
//!     let (mut read_buf, mut write_buf, mut frame_buf) = ([0; 1024], [0; 1024], [0; 1024]);
//!     let mut state = FramerState::new();
//!     let mut websocket = WebSocketClient::new_client(rand::rng());
//!     let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut websocket);
//!
//!     let options = WebSocketOptions {
//!         path: "/chat",
//!         host: "localhost",
//!         origin: Some("http://localhost"),
//!         sub_protocols: None,
//!         additional_headers: None,
//!     };
//!     framer.connect(stream, &options)?;
//!     framer.write(stream, WebSocketSendMessageType::Text, true, b"hello")?;
//!     if let ReadResult::Text(text) = framer.read(stream, &mut frame_buf)? {
//!         assert_eq!(text, "hello");
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Without a framer
//!
//! [`WebSocketClient`] and [`WebSocketServer`] encode and decode handshakes and frames on byte
//! slices, so they work with any transport.
//!
//! # Features
//!
//! * `asynch`: the [`asynch`] module with the async framer.
//! * `std`: implements `std::error::Error` for [`Error`].

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

use core::{cmp, result, str};
use heapless::{String, Vec};
use rand_core::Rng;
use sha1::{Digest, Sha1};

mod http;
mod random;
pub use self::random::EmptyRng;

#[cfg(feature = "asynch")]
#[cfg_attr(docsrs, doc(cfg(feature = "asynch")))]
pub mod asynch;
pub mod blocking;
mod framer_core;
mod head;
mod request;
mod url;
pub use self::framer_core::{
    FramerError, FramerState, ReadChunk, ReadResult, MIN_FRAME_BUF_LEN, MIN_READ_BUF_LEN,
    MIN_WRITE_BUF_LEN,
};
pub use self::request::{Decision, Request};
pub use self::url::WebSocketUrl;

/// Entry points for the fuzz targets in `fuzz/`; not part of the API.
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing {
    use crate::{request::Request, Result, WebSocketKey};

    /// See `head::head_len`.
    pub fn head_len(buf: &[u8], searched: &mut usize) -> Option<usize> {
        crate::head::head_len(buf, searched)
    }

    /// See `Request::parse`.
    pub fn parse_request(head: &[u8]) -> Result<Request<'_>> {
        Request::parse(head)
    }

    /// See `Request::upgrade_key`.
    pub fn upgrade_key(request: &Request<'_>) -> core::result::Result<WebSocketKey, &'static [u8]> {
        request.upgrade_key()
    }
}

const MASK_KEY_LEN: usize = 4;
const MAX_CONTROL_FRAME_PAYLOAD_LEN: usize = 125;

/// Result returning a websocket specific error if encountered
pub type Result<T> = result::Result<T, Error>;

/// A fixed length 24-character string used to hold a websocket key for the opening handshake
pub type WebSocketKey = String<24>;

/// Websocket send message type used when sending a websocket frame
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum WebSocketSendMessageType {
    /// A UTF8 encoded text string
    Text = 1,
    /// Binary data
    Binary = 2,
    /// An unsolicited ping message
    Ping = 9,
    /// A pong message in response to a ping message
    Pong = 10,
    /// A close message in response to a close message from the other party. Used to complete a
    /// closing handshake. If initiate a close handshake use the `close` function
    CloseReply = 11,
}

impl WebSocketSendMessageType {
    fn to_op_code(self) -> WebSocketOpCode {
        match self {
            WebSocketSendMessageType::Text => WebSocketOpCode::TextFrame,
            WebSocketSendMessageType::Binary => WebSocketOpCode::BinaryFrame,
            WebSocketSendMessageType::Ping => WebSocketOpCode::Ping,
            WebSocketSendMessageType::Pong => WebSocketOpCode::Pong,
            WebSocketSendMessageType::CloseReply => WebSocketOpCode::ConnectionClose,
        }
    }
}

/// Websocket receive message type use when reading a websocket frame
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum WebSocketReceiveMessageType {
    /// A UTF8 encoded text string
    Text = 1,
    /// Binary data
    Binary = 2,
    /// Signals that the close handshake is complete
    CloseCompleted = 7,
    /// Signals that the other party has initiated the close handshake. If you receive this message
    /// you should respond with a `WebSocketSendMessageType::CloseReply` with the same payload as
    /// close message
    CloseMustReply = 8,
    /// A ping message that you should respond to with a `WebSocketSendMessageType::Pong` message
    /// including the same payload as the ping
    Ping = 9,
    /// A pong message in response to a ping message
    Pong = 10,
}

/// Websocket close status code as per the rfc6455 websocket spec
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum WebSocketCloseStatusCode {
    /// Normal closure (1000), meaning that the purpose for which the connection was established
    /// has been fulfilled
    NormalClosure,
    /// Endpoint unavailable (1001) indicates that an endpoint is "going away", such as a server
    /// going down or a browser having navigated away from a page
    EndpointUnavailable,
    /// Protocol error (1002) indicates that an endpoint is terminating the connection due
    /// to a protocol error.
    ProtocolError,
    /// Invalid message type (1003) indicates that an endpoint is terminating the connection
    /// because it has received a type of data it cannot accept (e.g., an endpoint that
    /// understands only text data MAY send this if it receives a binary message)
    InvalidMessageType,
    /// Reserved (1004) for future use
    Reserved,
    /// Empty (1005) indicates that no status code was present
    Empty,
    /// Invalid payload data (1007) indicates that an endpoint is terminating the connection
    /// because it has received data within a message that was not consistent with the type of
    /// the message (e.g., non-UTF-8 data within a text message)
    InvalidPayloadData,
    /// Policy violation (1008) indicates that an endpoint is terminating the connection because
    /// it has received a message that violates its policy. This is a generic status code that
    /// can be returned when there is no other more suitable status code
    PolicyViolation,
    /// Message too big (1009) indicates that an endpoint is terminating the connection because
    /// it has received a message that is too big for it to process
    MessageTooBig,
    /// Mandatory extension (1010) indicates that an endpoint (client) is terminating the
    /// connection because it has expected the server to negotiate one or more extension, but
    /// the server didn't return them in the response message of the WebSocket handshake
    MandatoryExtension,
    /// Internal server error (1011) indicates that a server is terminating the connection because
    /// it encountered an unexpected condition that prevented it from fulfilling the request
    InternalServerError,
    /// TLS handshake (1015) connection was closed due to a failure to perform a TLS handshake
    TlsHandshake,
    /// Custom close code
    Custom(u16),
}

impl WebSocketCloseStatusCode {
    fn from_u16(value: u16) -> WebSocketCloseStatusCode {
        match value {
            1000 => WebSocketCloseStatusCode::NormalClosure,
            1001 => WebSocketCloseStatusCode::EndpointUnavailable,
            1002 => WebSocketCloseStatusCode::ProtocolError,
            1003 => WebSocketCloseStatusCode::InvalidMessageType,
            1004 => WebSocketCloseStatusCode::Reserved,
            1005 => WebSocketCloseStatusCode::Empty,
            1007 => WebSocketCloseStatusCode::InvalidPayloadData,
            1008 => WebSocketCloseStatusCode::PolicyViolation,
            1009 => WebSocketCloseStatusCode::MessageTooBig,
            1010 => WebSocketCloseStatusCode::MandatoryExtension,
            1011 => WebSocketCloseStatusCode::InternalServerError,
            1015 => WebSocketCloseStatusCode::TlsHandshake,
            _ => WebSocketCloseStatusCode::Custom(value),
        }
    }

    fn to_u16(self) -> u16 {
        match self {
            WebSocketCloseStatusCode::NormalClosure => 1000,
            WebSocketCloseStatusCode::EndpointUnavailable => 1001,
            WebSocketCloseStatusCode::ProtocolError => 1002,
            WebSocketCloseStatusCode::InvalidMessageType => 1003,
            WebSocketCloseStatusCode::Reserved => 1004,
            WebSocketCloseStatusCode::Empty => 1005,
            WebSocketCloseStatusCode::InvalidPayloadData => 1007,
            WebSocketCloseStatusCode::PolicyViolation => 1008,
            WebSocketCloseStatusCode::MessageTooBig => 1009,
            WebSocketCloseStatusCode::MandatoryExtension => 1010,
            WebSocketCloseStatusCode::InternalServerError => 1011,
            WebSocketCloseStatusCode::TlsHandshake => 1015,
            WebSocketCloseStatusCode::Custom(value) => value,
        }
    }
}

/// The state of the websocket
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum WebSocketState {
    /// The websocket has been created with `new_client()` or `new_server()`
    None = 0,
    /// The client has created an opening handshake
    Connecting = 1,
    /// The server has completed the opening handshake via server_accept() or, likewise, the
    /// client has completed the opening handshake via client_accept(). The user is free to call
    /// `write()`, `read()` or `close()` on the websocket
    Open = 2,
    /// The `close()` function has been called
    CloseSent = 3,
    /// A Close websocket frame has been received
    CloseReceived = 4,
    /// The close handshake has been completed
    Closed = 5,
    /// The server or client opening handshake failed
    Aborted = 6,
}

/// Websocket specific errors
#[derive(PartialEq, Eq, Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Error {
    /// Websocket frame has an invalid opcode
    InvalidOpCode,
    /// A frame length cannot be decoded, a control frame is longer than 125 bytes, or a close
    /// frame has a one byte payload
    InvalidFrameLength,
    /// A close frame holds a status code that must not be sent (RFC 6455 section 7.4)
    InvalidCloseStatusCode,
    /// The operation needs an open websocket
    WebSocketNotOpen,
    /// The opening handshake is performed on a websocket that is already open
    WebsocketAlreadyOpen,
    /// Text that must be UTF-8 is not, for example the reason of a close frame
    Utf8Error,
    /// An error that cannot be described more precisely
    Unknown,
    /// The HTTP header of the opening handshake is not valid HTTP/1.1
    HttpHeaderInvalid,
    /// The HTTP header of the opening handshake is not complete yet
    HttpHeaderIncomplete,
    /// The output buffer is too small for the frame or HTTP header
    WriteToBufferTooSmall,
    /// The input does not contain a whole frame header yet
    ReadFrameIncomplete,
    /// The server answered the opening handshake with a status code other than 101
    HttpResponseCodeInvalid(Option<u16>),
    /// The `Sec-WebSocket-Accept` header of the server is missing or does not match the key
    AcceptStringInvalid,
    /// The sub protocol of the opening handshake is not one the client offered
    SubProtocolNotOffered,
    /// The sub protocols a client offers are not unique and non-empty HTTP tokens
    /// (RFC 6455 section 4.1)
    InvalidSubProtocol,
    /// A conversion that cannot fail failed
    ConvertInfallible,
    /// A continuation frame arrives without a fragmented message to continue
    UnexpectedContinuationFrame,
    /// A frame sets reserved bits although no extension was negotiated
    ReservedBitsSet,
    /// A control frame is fragmented
    FragmentedControlFrame,
    /// A text or binary frame starts while a fragmented message is still incomplete
    UnexpectedDataFrame,
    /// A message is written while the message of a failed write is not finished yet
    UnfinishedWrite,
    /// A URL is not a valid `ws://` or `wss://` URL, see [`WebSocketUrl::parse`]
    InvalidUrl,
    /// The request is not a websocket upgrade. The first bytes of the output, as many as this
    /// holds, are the `400 Bad Request` or `426 Upgrade Required` response to send before closing
    /// the connection
    NotAnUpgrade(usize),
    /// A whole message is read while a message read in chunks is not finished yet
    UnfinishedRead,
    /// A server receives a frame that the client did not mask (RFC 6455 section 5.1)
    UnmaskedClientFrame,
    /// A client receives a frame that the server masked (RFC 6455 section 5.1)
    MaskedServerFrame,
}

impl From<str::Utf8Error> for Error {
    fn from(_: str::Utf8Error) -> Error {
        Error::Utf8Error
    }
}

impl From<core::convert::Infallible> for Error {
    fn from(_: core::convert::Infallible) -> Error {
        Error::ConvertInfallible
    }
}

impl From<heapless::CapacityError> for Error {
    fn from(_: heapless::CapacityError) -> Error {
        Error::WriteToBufferTooSmall
    }
}

impl From<()> for Error {
    fn from(_: ()) -> Error {
        Error::Unknown
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::HttpResponseCodeInvalid(Some(code)) => write!(f, "bad http response ({code})"),
            _ => write!(f, "{:?}", self),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum WebSocketOpCode {
    ContinuationFrame = 0,
    TextFrame = 1,
    BinaryFrame = 2,
    ConnectionClose = 8,
    Ping = 9,
    Pong = 10,
}

impl WebSocketOpCode {
    fn to_message_type(self) -> Result<WebSocketReceiveMessageType> {
        match self {
            WebSocketOpCode::TextFrame => Ok(WebSocketReceiveMessageType::Text),
            WebSocketOpCode::BinaryFrame => Ok(WebSocketReceiveMessageType::Binary),
            _ => Err(Error::InvalidOpCode),
        }
    }
}

/// The metadata result of a `read` function call of a websocket
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct WebSocketReadResult {
    /// Number of bytes read from the `from` buffer
    pub len_from: usize,
    /// Number of bytes written to the `to` buffer
    pub len_to: usize,
    /// End of message flag is `true` if the `to` buffer contains an entire websocket frame
    /// payload otherwise `false` if the user must continue calling the read function to get the
    /// rest of the payload
    pub end_of_message: bool,
    /// Close status code (as per the websocket spec) if the message type is `CloseMustReply` or
    /// `CloseCompleted`. If a close status is specified then a UTF8 encoded string could also
    /// appear in the frame payload giving more detailed information about why the websocket was
    /// closed.
    pub close_status: Option<WebSocketCloseStatusCode>,
    /// The websocket frame type
    pub message_type: WebSocketReceiveMessageType,
}

/// Websocket options used by a websocket client to initiate an opening handshake with a
/// websocket server
pub struct WebSocketOptions<'a> {
    /// The request uri (e.g. `/chat?id=123`) of the GET method used to identify the endpoint of the
    /// websocket connection. A path that does not start with `/` is sent with a `/` in front.
    pub path: &'a str,
    /// The value of the `Host` header: the host name (e.g. `server.example.com`), followed by
    /// `:` and the port unless it is the default port of the scheme
    pub host: &'a str,
    /// The origin (e.g. `http://example.com`) is used to protect against unauthorized
    /// cross-origin use of a WebSocket server by scripts using the WebSocket API in a web
    /// browser. Clients other than browsers may leave it out (`None`), but some servers require
    /// it.
    pub origin: Option<&'a str>,
    /// A list of requested sub protocols in order of preference. The server should return the
    /// first sub protocol it supports or none at all. Each sub protocol is an HTTP token, for
    /// example `chat` or `v2.json`, and appears once. An empty list sends no sub protocols
    pub sub_protocols: Option<&'a [&'a str]>,
    /// Any additional headers the server may require that are not part of the websocket
    /// spec. These should be fully formed http headers without the `\r\n` (e.g. `MyHeader: foo`)
    pub additional_headers: Option<&'a [&'a str]>,
}

/// Used to return a sized type from `WebSocket::new_server()`
pub type WebSocketServer = WebSocket<EmptyRng, Server>;

/// Used to return a sized type from `WebSocketClient::new_client()`
pub type WebSocketClient<T> = WebSocket<T, Client>;

/// Marks a [`WebSocket`] as the server side of a connection.
pub enum Server {}
/// Marks a [`WebSocket`] as the client side of a connection.
pub enum Client {}

/// The side of a connection a [`WebSocket`] is on: [`Server`] or [`Client`].
pub trait WebSocketType {}
impl WebSocketType for Server {}
impl WebSocketType for Client {}

/// Websocket client and server implementation
pub struct WebSocket<T, S: WebSocketType>
where
    T: Rng,
{
    is_client: bool,
    rng: T,
    continuation_frame_op_code: Option<WebSocketOpCode>,
    is_write_continuation: bool,
    /// The state of the connection. The opening and closing handshakes update it.
    pub state: WebSocketState,
    continuation_read: Option<ContinuationRead>,
    marker: core::marker::PhantomData<S>,
}

impl<T, Type> WebSocket<T, Type>
where
    T: Rng,
    Type: WebSocketType,
{
    /// Creates a new websocket client by passing in a required random number generator
    ///
    /// # Examples
    /// ```
    /// use embedded_io_websocket as ws;
    /// use rand;
    /// let mut ws_client = ws::WebSocketClient::new_client(rand::rng());
    ///
    /// assert_eq!(ws::WebSocketState::None, ws_client.state);
    /// ```
    pub fn new_client(rng: T) -> WebSocketClient<T> {
        WebSocket {
            is_client: true,
            rng,
            continuation_frame_op_code: None,
            is_write_continuation: false,
            state: WebSocketState::None,
            continuation_read: None,
            marker: core::marker::PhantomData::<Client>,
        }
    }

    /// Creates a new websocket server. Note that you must use the `WebSocketServer` type and
    /// not the generic `WebSocket` type for this call or you will get a `'type annotations needed'`
    /// compilation error.
    ///
    /// # Examples
    /// ```
    /// use embedded_io_websocket as ws;
    /// let mut ws_server = ws::WebSocketServer::new_server();
    ///
    /// assert_eq!(ws::WebSocketState::None, ws_server.state);
    /// ```
    pub fn new_server() -> WebSocketServer {
        let rng = EmptyRng::new();
        WebSocket {
            is_client: false,
            rng,
            continuation_frame_op_code: None,
            is_write_continuation: false,
            state: WebSocketState::None,
            continuation_read: None,
            marker: core::marker::PhantomData::<Server>,
        }
    }
}

impl<T> WebSocket<T, Server>
where
    T: Rng,
{
    /// Answers the HTTP `request` that opens a connection and opens the websocket.
    ///
    /// Read the request with [`Request::read`]. Writes the `101 Switching Protocols` response
    /// into `to` and returns its length. `sub_protocol` must be one the client offered; the
    /// response is 129 bytes without it and 26 bytes plus its length more with it.
    ///
    /// # Examples
    ///
    /// ```
    /// use embedded_io_websocket as ws;
    /// let request = b"GET /chat HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
    ///     Connection: Upgrade\r\nSec-WebSocket-Key: Z7OY1UwHOx/nkSz38kfPwg==\r\n\
    ///     Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Version: 13\r\n\r\n";
    /// let (request, _) = ws::Request::read(request).unwrap();
    /// let mut buffer = [0; 1000];
    /// let mut ws_server = ws::WebSocketServer::new_server();
    /// let len = ws_server
    ///     .server_accept(&request, Some("chat"), &mut buffer)
    ///     .unwrap();
    /// let response = std::str::from_utf8(&buffer[..len]).unwrap();
    ///
    /// assert_eq!("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Protocol: chat\r\nSec-WebSocket-Accept: ptPnPeDOTo6khJlzmLhOZSh2tAY=\r\n\r\n", response);
    /// ```
    ///
    /// # Errors
    ///
    /// * [`Error::NotAnUpgrade`] if the request is not a valid websocket upgrade (RFC 6455
    ///   section 4.2.1). `to` then holds the response that rejects it.
    /// * [`Error::SubProtocolNotOffered`] if the client did not offer `sub_protocol`.
    /// * [`Error::WriteToBufferTooSmall`] if the response does not fit into `to`.
    /// * [`Error::WebsocketAlreadyOpen`] if the websocket is already open.
    pub fn server_accept(
        &mut self,
        request: &Request<'_>,
        sub_protocol: Option<&str>,
        to: &mut [u8],
    ) -> Result<usize> {
        if self.state == WebSocketState::Open {
            return Err(Error::WebsocketAlreadyOpen);
        }
        let sec_websocket_key = match request.upgrade_key() {
            Ok(key) => key,
            Err(response) => {
                to.get_mut(..response.len())
                    .ok_or(Error::WriteToBufferTooSmall)?
                    .copy_from_slice(response);
                return Err(Error::NotAnUpgrade(response.len()));
            }
        };
        if sub_protocol.is_some_and(|protocol| !request.offers(protocol)) {
            return Err(Error::SubProtocolNotOffered);
        }

        match http::build_connect_handshake_response(&sec_websocket_key, sub_protocol, to) {
            Ok(http_response_len) => {
                self.state = WebSocketState::Open;
                Ok(http_response_len)
            }
            Err(e) => {
                self.state = WebSocketState::Aborted;
                Err(e)
            }
        }
    }
}

impl<T> WebSocket<T, Client>
where
    T: Rng,
{
    /// Used by the client to initiate a websocket opening handshake
    ///
    /// # Examples
    /// ```
    /// use embedded_io_websocket as ws;
    /// let mut buffer: [u8; 2000] = [0; 2000];
    /// let mut ws_client = ws::WebSocketClient::new_client(rand::rng());
    /// let sub_protocols = ["chat", "superchat"];
    /// let websocket_options = ws::WebSocketOptions {
    ///     path: "/chat",
    ///     host: "localhost",
    ///     origin: Some("http://localhost"),
    ///     sub_protocols: Some(&sub_protocols),
    ///     additional_headers: None,
    /// };
    ///
    /// let (len, web_socket_key) = ws_client.client_connect(&websocket_options, &mut buffer).unwrap();
    ///
    /// let actual_http = std::str::from_utf8(&buffer[..len]).unwrap();
    /// let mut expected_http = String::new();
    /// expected_http.push_str("GET /chat HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
    /// expected_http.push_str(web_socket_key.as_str());
    /// expected_http.push_str("\r\nOrigin: http://localhost\r\nSec-WebSocket-Protocol: chat, superchat\r\nSec-WebSocket-Version: 13\r\n\r\n");
    /// assert_eq!(expected_http.as_str(), actual_http);
    /// ```
    ///
    /// # Errors
    /// * Returns `WriteToBufferTooSmall` if the request does not fit into `to`
    /// * Returns `WebsocketAlreadyOpen` if called on a websocket that is already open
    /// * Returns `InvalidSubProtocol` if the sub protocols of `websocket_options` are not
    ///   unique HTTP tokens
    pub fn client_connect(
        &mut self,
        websocket_options: &WebSocketOptions,
        to: &mut [u8],
    ) -> Result<(usize, WebSocketKey)> {
        if self.state == WebSocketState::Open {
            return Err(Error::WebsocketAlreadyOpen);
        }

        match http::build_connect_handshake_request(websocket_options, &mut self.rng, to) {
            Ok((request_len, sec_websocket_key)) => {
                self.state = WebSocketState::Connecting;
                Ok((request_len, sec_websocket_key))
            }
            Err(e) => Err(e),
        }
    }

    /// Used by a websocket client for checking the server response to an opening handshake
    /// (sent using the client_connect function). Pass the sub protocols the client requested in
    /// `sub_protocols`. The server chooses one of them (or none) and you get that entry of
    /// `sub_protocols` in the result
    /// # Examples
    /// ```
    /// use embedded_io_websocket as ws;
    /// let mut ws_client = ws::WebSocketClient::new_client(rand::rng());
    /// let ws_key = ws::WebSocketKey::try_from("Z7OY1UwHOx/nkSz38kfPwg==").unwrap();
    /// let server_response_html = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Protocol: chat\r\nSec-WebSocket-Accept: ptPnPeDOTo6khJlzmLhOZSh2tAY=\r\n\r\n";    ///
    /// let (len, sub_protocol) = ws_client
    ///     .client_accept(&ws_key, Some(&["chat"]), server_response_html.as_bytes())
    ///     .unwrap();
    ///
    /// assert_eq!(159, len);
    /// assert_eq!("chat", sub_protocol.unwrap());
    /// ```
    /// # Errors
    /// * Returns `HttpResponseCodeInvalid` if the HTTP response code is not `101 Switching Protocols`
    /// * Returns `AcceptStringInvalid` if the web server failed to return a valid accept string
    /// * Returns `SubProtocolNotOffered` if the server chose a sub protocol that is not in
    ///   `sub_protocols`
    /// * Returns `HttpHeader(Version)` or some other varient if the HTTP response is not well formed
    /// * Returns `WebsocketAlreadyOpen` if called on a websocket that is already open
    pub fn client_accept<'o>(
        &mut self,
        sec_websocket_key: &WebSocketKey,
        sub_protocols: Option<&[&'o str]>,
        from: &[u8],
    ) -> Result<(usize, Option<&'o str>)> {
        if self.state == WebSocketState::Open {
            return Err(Error::WebsocketAlreadyOpen);
        }

        match http::read_server_connect_handshake_response(sec_websocket_key, sub_protocols, from) {
            Ok((len, sec_websocket_protocol)) => {
                self.state = WebSocketState::Open;
                Ok((len, sec_websocket_protocol))
            }
            Err(Error::HttpHeaderIncomplete) => Err(Error::HttpHeaderIncomplete),
            Err(e) => {
                self.state = WebSocketState::Aborted;
                Err(e)
            }
        }
    }
}

impl<T, Type> WebSocket<T, Type>
where
    T: Rng,
    Type: WebSocketType,
{
    /// Reads the payload from a websocket frame in buffer `from` into a buffer `to` and returns
    /// metadata about the frame. Since this function is designed to be called in a memory
    /// constrained system we may not read the entire payload in one go. In each of the scenarios
    /// below the `read_result.end_of_message` flag would be `false`:
    /// * The payload is fragmented into multiple websocket frames (as per the websocket spec)
    /// * The `from` buffer does not hold the entire websocket frame. For example if only part of
    ///   the frame was read or if the `from` buffer is too small to hold an entire websocket frame
    /// * The `to` buffer is too small to hold the entire websocket frame payload
    ///
    /// If the function returns `read_result.end_of_message` `false` then the next
    /// call to the function should not include data that has already been passed into the function.
    /// The websocket *remembers* the websocket frame header and is able to process the rest of the
    /// payload correctly. If the `from` buffer contains multiple websocket frames then only one of
    /// them will be returned at a time and the user must make multiple calls to the function by
    /// taking note of `read_result.len_from` which tells you how many bytes were read from the
    /// `from` buffer
    ///
    /// # Examples
    ///
    /// ```
    /// use embedded_io_websocket as ws;
    /// //                    h   e   l   l   o
    /// let buffer1 = [129,5,104,101,108,108,111];
    /// let mut buffer2: [u8; 128] = [0; 128];
    /// let mut ws_client = ws::WebSocketClient::new_client(rand::rng());
    /// ws_client.state = ws::WebSocketState::Open; // skip the opening handshake
    /// let ws_result = ws_client.read(&buffer1, &mut buffer2).unwrap();
    ///
    /// assert_eq!("hello".as_bytes(), &buffer2[..ws_result.len_to]);
    /// ```
    /// # Errors
    /// * Returns `WebSocketNotOpen` when the websocket is not open when this function is called
    /// * Returns `InvalidOpCode` if the websocket frame contains an invalid opcode
    /// * Returns `UnexpectedContinuationFrame` if we receive a continuation frame without first
    ///   receiving a non-continuation frame with an opcode describing the payload
    /// * Returns `ReadFrameIncomplete` if the `from` buffer does not contain a full websocket
    ///   header (typically 2-14 bytes depending on the payload)
    /// * Returns `InvalidFrameLength` if the frame length cannot be decoded
    ///
    pub fn read(&mut self, from: &[u8], to: &mut [u8]) -> Result<WebSocketReadResult> {
        if self.state == WebSocketState::Open || self.state == WebSocketState::CloseSent {
            let frame = self.read_frame(from, to)?;

            match frame.op_code {
                WebSocketOpCode::Ping => Ok(frame.to_readresult(WebSocketReceiveMessageType::Ping)),
                WebSocketOpCode::Pong => Ok(frame.to_readresult(WebSocketReceiveMessageType::Pong)),
                WebSocketOpCode::TextFrame => {
                    Ok(frame.to_readresult(WebSocketReceiveMessageType::Text))
                }
                WebSocketOpCode::BinaryFrame => {
                    Ok(frame.to_readresult(WebSocketReceiveMessageType::Binary))
                }
                WebSocketOpCode::ConnectionClose => match self.state {
                    WebSocketState::CloseSent => {
                        self.state = WebSocketState::Closed;
                        Ok(frame.to_readresult(WebSocketReceiveMessageType::CloseCompleted))
                    }
                    _ => {
                        self.state = WebSocketState::CloseReceived;
                        Ok(frame.to_readresult(WebSocketReceiveMessageType::CloseMustReply))
                    }
                },
                WebSocketOpCode::ContinuationFrame => match self.continuation_frame_op_code {
                    Some(cf_op_code) => Ok(frame.to_readresult(cf_op_code.to_message_type()?)),
                    None => Err(Error::UnexpectedContinuationFrame),
                },
            }
        } else {
            Err(Error::WebSocketNotOpen)
        }
    }

    /// Writes the payload in `from` to a websocket frame in `to`
    /// * message_type - The type of message to send: Text, Binary, Ping, Pong or CloseReply
    /// * end_of_message - False to fragment a frame into multiple smaller frames. The last frame
    ///   should set this to true. Ignored for Ping, Pong and CloseReply: control frames are
    ///   never fragmented and may be sent between the frames of a fragmented message
    /// * from - The buffer containing the payload to encode
    /// * to - The the buffer to save the websocket encoded payload to.
    ///   Returns the number of bytes written to the `to` buffer
    /// # Examples
    ///
    /// ```
    /// use embedded_io_websocket as ws;
    /// let mut buffer: [u8; 1000] = [0; 1000];
    /// let mut ws_server = ws::WebSocketServer::new_server();
    /// ws_server.state = ws::WebSocketState::Open; // skip the opening handshake
    /// let len = ws_server.write(ws::WebSocketSendMessageType::Text, true, "hello".as_bytes(),
    ///     &mut buffer).unwrap();
    ///
    /// //                     h   e   l   l   o
    /// let expected = [129,5,104,101,108,108,111];
    /// assert_eq!(&expected, &buffer[..len]);
    /// ```
    /// # Errors
    /// * Returns `WebSocketNotOpen` when the websocket is not open when this function is called.
    ///   After [`close`](Self::close) only a Pong may still be sent, to answer a ping that
    ///   arrives before the close reply
    /// * Returns `WriteToBufferTooSmall` when the `to` buffer is too small to fit the websocket
    ///   frame header (2-14 bytes) plus the payload. Consider fragmenting the messages by making
    ///   multiple write calls with `end_of_message` set to `false` and the final call set to `true`
    /// * Returns `InvalidFrameLength` when the payload of a Ping, Pong or CloseReply is longer
    ///   than 125 bytes
    pub fn write(
        &mut self,
        message_type: WebSocketSendMessageType,
        end_of_message: bool,
        from: &[u8],
        to: &mut [u8],
    ) -> Result<usize> {
        let op_code = message_type.to_op_code();
        let may_send = match self.state {
            WebSocketState::Open | WebSocketState::CloseReceived => true,
            // RFC 6455 section 5.5.2: a ping must be answered until a close frame is received
            WebSocketState::CloseSent => op_code == WebSocketOpCode::Pong,
            _ => false,
        };
        if !may_send {
            return Err(Error::WebSocketNotOpen);
        }
        match op_code {
            WebSocketOpCode::TextFrame | WebSocketOpCode::BinaryFrame => {
                let op_code = if self.is_write_continuation {
                    WebSocketOpCode::ContinuationFrame
                } else {
                    op_code
                };
                let len = self.write_frame(from, to, op_code, end_of_message)?;
                self.is_write_continuation = !end_of_message;
                Ok(len)
            }
            _ => {
                if from.len() > MAX_CONTROL_FRAME_PAYLOAD_LEN {
                    return Err(Error::InvalidFrameLength);
                }
                // Control frames are never fragmented and may be sent between the frames of a
                // fragmented message (RFC 6455 section 5.5).
                let len = self.write_frame(from, to, op_code, true)?;
                if op_code == WebSocketOpCode::ConnectionClose {
                    self.state = WebSocketState::Closed
                }
                Ok(len)
            }
        }
    }

    /// Initiates a close handshake.
    /// Both the client and server may initiate a close handshake. If successful the function
    /// changes the websocket state from Open -> CloseSent
    ///
    /// A `status_description` longer than 123 bytes is cut at the last character that fits, so
    /// the close frame stays within the 125 bytes a control frame may carry.
    /// # Errors
    /// * Returns `WebSocketNotOpen` when the websocket is not open when this function is called
    /// * Returns `WriteToBufferTooSmall` when the `to` buffer is too small to fit the websocket
    ///   frame header (2-14 bytes) plus the payload. Consider sending a smaller status_description
    pub fn close(
        &mut self,
        close_status: WebSocketCloseStatusCode,
        status_description: Option<&str>,
        to: &mut [u8],
    ) -> Result<usize> {
        if self.state != WebSocketState::Open {
            return Err(Error::WebSocketNotOpen);
        }
        let mut payload: Vec<u8, MAX_CONTROL_FRAME_PAYLOAD_LEN> = Vec::new();
        payload.extend_from_slice(&close_status.to_u16().to_be_bytes())?;
        if let Some(status_description) = status_description {
            let mut len = status_description.len().min(payload.capacity() - 2);
            while !status_description.is_char_boundary(len) {
                len -= 1;
            }
            payload.extend_from_slice(&status_description.as_bytes()[..len])?;
        }
        let len = self.write_frame(&payload, to, WebSocketOpCode::ConnectionClose, true)?;
        self.state = WebSocketState::CloseSent;
        Ok(len)
    }

    fn next_control_frame_len(&self, from_buffer: &[u8]) -> Result<Option<FrameLen>> {
        if self.continuation_read.is_some() {
            return Ok(None);
        }

        if from_buffer.len() < 2 {
            return Err(Error::ReadFrameIncomplete);
        }

        match get_op_code(from_buffer[0] & 0x0F)? {
            WebSocketOpCode::ConnectionClose | WebSocketOpCode::Ping | WebSocketOpCode::Pong => {
                let (payload_len, len_bytes) = read_length(from_buffer[1], &from_buffer[2..])?;
                // RFC 6455 section 5.5, also keeps the sum below from overflowing
                if payload_len > MAX_CONTROL_FRAME_PAYLOAD_LEN {
                    return Err(Error::InvalidFrameLength);
                }
                let mask_len = if from_buffer[1] & 0x80 == 0x80 {
                    MASK_KEY_LEN
                } else {
                    0
                };
                Ok(Some(FrameLen {
                    payload: payload_len,
                    total: 2 + len_bytes + mask_len + payload_len,
                }))
            }
            _ => Ok(None),
        }
    }

    fn read_frame(&mut self, from_buffer: &[u8], to_buffer: &mut [u8]) -> Result<WebSocketFrame> {
        match &mut self.continuation_read {
            Some(continuation_read) => {
                let mut result = read_continuation(continuation_read, from_buffer, to_buffer);
                if result.op_code == WebSocketOpCode::ContinuationFrame {
                    if let Some(continuation_frame_op_code) = self.continuation_frame_op_code {
                        result.op_code = continuation_frame_op_code;
                    }
                }
                if continuation_read.count == 0 {
                    self.continuation_read = None;
                }
                if result.is_fin_bit_set {
                    self.continuation_frame_op_code = None;
                }
                Ok(result)
            }
            None => {
                let (mut result, continuation_read) =
                    read_frame(from_buffer, to_buffer, self.is_client)?;

                match result.op_code {
                    WebSocketOpCode::BinaryFrame | WebSocketOpCode::TextFrame => {
                        if self.continuation_frame_op_code.is_some() {
                            return Err(Error::UnexpectedDataFrame);
                        }
                        self.continuation_frame_op_code = if result.is_fin_bit_set {
                            None
                        } else {
                            Some(result.op_code)
                        };
                    }
                    WebSocketOpCode::ContinuationFrame => {
                        result.op_code = self
                            .continuation_frame_op_code
                            .ok_or(Error::UnexpectedContinuationFrame)?;
                        if result.is_fin_bit_set {
                            self.continuation_frame_op_code = None;
                        }
                    }
                    _ => {
                        // control frames should not affect the continuation frame mechanics
                    }
                }

                self.continuation_read = continuation_read;
                Ok(result)
            }
        }
    }

    fn write_frame(
        &mut self,
        from_buffer: &[u8],
        to_buffer: &mut [u8],
        op_code: WebSocketOpCode,
        end_of_message: bool,
    ) -> Result<usize> {
        let fin_bit_set_as_byte: u8 = if end_of_message { 0x80 } else { 0x00 };
        let byte1: u8 = fin_bit_set_as_byte | op_code as u8;
        let count = from_buffer.len();
        const BYTE_HEADER_SIZE: usize = 2;
        const SHORT_HEADER_SIZE: usize = 4;
        const LONG_HEADER_SIZE: usize = 10;
        const MASK_KEY_SIZE: usize = 4;
        let mask_bit_set_as_byte = if self.is_client { 0x80 } else { 0x00 };
        let payload_len = from_buffer.len() + if self.is_client { MASK_KEY_SIZE } else { 0 };

        let header_size = if count < 126 {
            if payload_len + BYTE_HEADER_SIZE > to_buffer.len() {
                return Err(Error::WriteToBufferTooSmall);
            }
            to_buffer[0] = byte1;
            to_buffer[1] = mask_bit_set_as_byte | count as u8;
            BYTE_HEADER_SIZE
        } else if count <= u16::MAX as usize {
            if payload_len + SHORT_HEADER_SIZE > to_buffer.len() {
                return Err(Error::WriteToBufferTooSmall);
            }
            to_buffer[0] = byte1;
            to_buffer[1] = mask_bit_set_as_byte | 126;
            to_buffer[2..4].copy_from_slice(&(count as u16).to_be_bytes());
            SHORT_HEADER_SIZE
        } else {
            if payload_len + LONG_HEADER_SIZE > to_buffer.len() {
                return Err(Error::WriteToBufferTooSmall);
            }
            to_buffer[0] = byte1;
            to_buffer[1] = mask_bit_set_as_byte | 127;
            to_buffer[2..10].copy_from_slice(&(count as u64).to_be_bytes());
            LONG_HEADER_SIZE
        };

        // RFC 6455 section 10.3: clients mask frames so proxies cannot be made to cache them
        if self.is_client {
            let mut mask_key = [0; MASK_KEY_SIZE];
            self.rng.fill_bytes(&mut mask_key); // clients always have an rng instance
            to_buffer[header_size..header_size + MASK_KEY_SIZE].copy_from_slice(&mask_key);
            let to_buffer_start = header_size + MASK_KEY_SIZE;

            for (i, (from, to)) in from_buffer[..count]
                .iter()
                .zip(&mut to_buffer[to_buffer_start..to_buffer_start + count])
                .enumerate()
            {
                *to = *from ^ mask_key[i % MASK_KEY_SIZE];
            }

            Ok(to_buffer_start + count)
        } else {
            to_buffer[header_size..header_size + count].copy_from_slice(&from_buffer[..count]);
            Ok(header_size + count)
        }
    }
}

// Continuation read is used when we cannot fit the entire websocket frame into the supplied buffer
struct ContinuationRead {
    op_code: WebSocketOpCode,
    count: usize,
    is_fin_bit_set: bool,
    mask_key: Option<[u8; 4]>,
}

struct FrameLen {
    payload: usize,
    total: usize,
}

struct WebSocketFrame {
    is_fin_bit_set: bool,
    op_code: WebSocketOpCode,
    num_bytes_to: usize,
    num_bytes_from: usize,
    close_status: Option<WebSocketCloseStatusCode>,
}

impl WebSocketFrame {
    fn to_readresult(&self, message_type: WebSocketReceiveMessageType) -> WebSocketReadResult {
        WebSocketReadResult {
            len_from: self.num_bytes_from,
            len_to: self.num_bytes_to,
            end_of_message: self.is_fin_bit_set,
            close_status: self.close_status,
            message_type,
        }
    }
}

fn min(num1: usize, num2: usize, num3: usize) -> usize {
    cmp::min(cmp::min(num1, num2), num3)
}

fn read_into_buffer(
    mask_key: &mut Option<[u8; 4]>,
    from_buffer: &[u8],
    to_buffer: &mut [u8],
    len: usize,
) -> usize {
    let len_to_read = min(len, to_buffer.len(), from_buffer.len());

    match mask_key {
        Some(mask_key) => {
            for (i, (from, to)) in from_buffer[..len_to_read].iter().zip(to_buffer).enumerate() {
                *to = *from ^ mask_key[i % MASK_KEY_LEN];
            }
            mask_key.rotate_left(len_to_read % MASK_KEY_LEN);
        }
        None => {
            to_buffer[..len_to_read].copy_from_slice(&from_buffer[..len_to_read]);
        }
    }

    len_to_read
}

fn read_continuation(
    continuation_read: &mut ContinuationRead,
    from_buffer: &[u8],
    to_buffer: &mut [u8],
) -> WebSocketFrame {
    let len_read = read_into_buffer(
        &mut continuation_read.mask_key,
        from_buffer,
        to_buffer,
        continuation_read.count,
    );

    let is_complete = len_read == continuation_read.count;

    let frame = match continuation_read.op_code {
        WebSocketOpCode::ConnectionClose => decode_close_frame(to_buffer, len_read, len_read),
        _ => WebSocketFrame {
            num_bytes_from: len_read,
            num_bytes_to: len_read,
            op_code: continuation_read.op_code,
            close_status: None,
            is_fin_bit_set: if is_complete {
                continuation_read.is_fin_bit_set
            } else {
                false
            },
        },
    };

    continuation_read.count -= len_read;
    frame
}

fn read_frame(
    from_buffer: &[u8],
    to_buffer: &mut [u8],
    is_client: bool,
) -> Result<(WebSocketFrame, Option<ContinuationRead>)> {
    if from_buffer.len() < 2 {
        return Err(Error::ReadFrameIncomplete);
    }

    let byte1 = from_buffer[0];
    let byte2 = from_buffer[1];

    const FIN_BIT_FLAG: u8 = 0x80;
    const OP_CODE_FLAG: u8 = 0x0F;
    const RESERVED_BITS_FLAG: u8 = 0x70;
    let is_fin_bit_set = (byte1 & FIN_BIT_FLAG) == FIN_BIT_FLAG;
    if byte1 & RESERVED_BITS_FLAG != 0 {
        return Err(Error::ReservedBitsSet);
    }
    let op_code = get_op_code(byte1 & OP_CODE_FLAG)?;
    let is_control_frame = matches!(
        op_code,
        WebSocketOpCode::ConnectionClose | WebSocketOpCode::Ping | WebSocketOpCode::Pong
    );
    if is_control_frame && !is_fin_bit_set {
        return Err(Error::FragmentedControlFrame);
    }

    const MASK_FLAG: u8 = 0x80;
    let is_mask_bit_set = (byte2 & MASK_FLAG) == MASK_FLAG;
    match (is_client, is_mask_bit_set) {
        (true, true) => return Err(Error::MaskedServerFrame),
        (false, false) => return Err(Error::UnmaskedClientFrame),
        _ => {}
    }
    let (len, mut num_bytes_read) = read_length(byte2, &from_buffer[2..])?;

    num_bytes_read += 2;
    let from_buffer = &from_buffer[num_bytes_read..];

    let mut mask_key = if is_mask_bit_set {
        if from_buffer.len() < MASK_KEY_LEN {
            return Err(Error::ReadFrameIncomplete);
        }
        let mut mask_key: [u8; MASK_KEY_LEN] = [0; MASK_KEY_LEN];
        mask_key.copy_from_slice(&from_buffer[..MASK_KEY_LEN]);
        num_bytes_read += MASK_KEY_LEN;
        Some(mask_key)
    } else {
        None
    };

    // a control frame is decoded whole: its payload is answered or validated as one piece
    if is_control_frame {
        // RFC 6455 section 5.5
        if len > MAX_CONTROL_FRAME_PAYLOAD_LEN {
            return Err(Error::InvalidFrameLength);
        }
        let mask_len = if is_mask_bit_set { MASK_KEY_LEN } else { 0 };
        if from_buffer.len() - mask_len < len {
            return Err(Error::ReadFrameIncomplete);
        }
        if to_buffer.len() < len {
            return Err(Error::WriteToBufferTooSmall);
        }
    }

    let len_read = if is_mask_bit_set {
        let from_buffer = &from_buffer[MASK_KEY_LEN..];
        read_into_buffer(&mut mask_key, from_buffer, to_buffer, len)
    } else {
        read_into_buffer(&mut mask_key, from_buffer, to_buffer, len)
    };

    let has_continuation = len_read < len;
    num_bytes_read += len_read;
    if op_code == WebSocketOpCode::ConnectionClose && !has_continuation {
        validate_close_payload(&to_buffer[..len_read])?;
    }

    let frame = match op_code {
        WebSocketOpCode::ConnectionClose => decode_close_frame(to_buffer, num_bytes_read, len_read),
        _ => WebSocketFrame {
            num_bytes_from: num_bytes_read,
            num_bytes_to: len_read,
            op_code,
            close_status: None,
            is_fin_bit_set: if has_continuation {
                false
            } else {
                is_fin_bit_set
            },
        },
    };

    if has_continuation {
        let continuation_read = Some(ContinuationRead {
            op_code,
            count: len - len_read,
            is_fin_bit_set,
            mask_key,
        });
        Ok((frame, continuation_read))
    } else {
        Ok((frame, None))
    }
}

// RFC 6455 section 7.4: codes a peer may send, including those registered with IANA later
fn is_valid_close_status_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

fn validate_close_payload(payload: &[u8]) -> Result<()> {
    match payload {
        [] => Ok(()),
        [_] => Err(Error::InvalidFrameLength),
        [high, low, reason @ ..] => {
            if !is_valid_close_status_code(u16::from_be_bytes([*high, *low])) {
                return Err(Error::InvalidCloseStatusCode);
            }
            str::from_utf8(reason)?;
            Ok(())
        }
    }
}

fn get_op_code(val: u8) -> Result<WebSocketOpCode> {
    match val {
        0 => Ok(WebSocketOpCode::ContinuationFrame),
        1 => Ok(WebSocketOpCode::TextFrame),
        2 => Ok(WebSocketOpCode::BinaryFrame),
        8 => Ok(WebSocketOpCode::ConnectionClose),
        9 => Ok(WebSocketOpCode::Ping),
        10 => Ok(WebSocketOpCode::Pong),
        _ => Err(Error::InvalidOpCode),
    }
}

// returns (len, how_many_bytes_were_read)
fn read_length(byte2: u8, from_buffer: &[u8]) -> Result<(usize, usize)> {
    let len = byte2 & 0x7F;

    if len < 126 {
        return Ok((len as usize, 0));
    } else if len == 126 {
        if from_buffer.len() < 2 {
            return Err(Error::ReadFrameIncomplete);
        }
        let mut buf: [u8; 2] = [0; 2];
        buf.copy_from_slice(&from_buffer[..2]);
        let len = u16::from_be_bytes(buf);
        // RFC 6455 section 5.2: the length uses the fewest bytes possible
        if len < 126 {
            return Err(Error::InvalidFrameLength);
        }
        return Ok((len as usize, 2));
    } else if len == 127 {
        if from_buffer.len() < 8 {
            return Err(Error::ReadFrameIncomplete);
        }
        let mut buf: [u8; 8] = [0; 8];
        buf.copy_from_slice(&from_buffer[..8]);
        let len = u64::from_be_bytes(buf);
        // RFC 6455 section 5.2: the fewest bytes possible, and the most significant bit is 0
        if len <= u64::from(u16::MAX) || len >> 63 != 0 {
            return Err(Error::InvalidFrameLength);
        }
        // a length the target cannot address must not wrap around
        let len = usize::try_from(len).map_err(|_| Error::InvalidFrameLength)?;
        return Ok((len, 8));
    }

    Err(Error::InvalidFrameLength)
}

fn decode_close_frame(buffer: &[u8], num_bytes_read: usize, len: usize) -> WebSocketFrame {
    let close_status = match buffer[..len] {
        [high, low, ..] => WebSocketCloseStatusCode::from_u16(u16::from_be_bytes([high, low])),
        // RFC 6455 section 7.1.5
        _ => WebSocketCloseStatusCode::Empty,
    };
    WebSocketFrame {
        num_bytes_from: num_bytes_read,
        num_bytes_to: len,
        op_code: WebSocketOpCode::ConnectionClose,
        close_status: Some(close_status),
        is_fin_bit_set: true,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn read_frames(frames: &[u8], reads: usize) -> Result<WebSocketReadResult> {
        let mut ws_client = WebSocketClient::new_client(rand::rng());
        ws_client.state = WebSocketState::Open;
        let mut to = [0; 64];
        let mut from = frames;
        for _ in 1..reads {
            let result = ws_client.read(from, &mut to)?;
            from = &from[result.len_from..];
        }
        ws_client.read(from, &mut to)
    }

    #[test]
    fn frame_with_reserved_bits_is_rejected() {
        assert_eq!(
            read_frames(&[0xC1, 0x01, b'a'], 1).err(),
            Some(Error::ReservedBitsSet)
        );
    }

    #[test]
    fn client_rejects_a_masked_frame() {
        assert_eq!(
            read_frames(&[0x81, 0x81, 1, 2, 3, 4, b'a' ^ 1], 1).err(),
            Some(Error::MaskedServerFrame)
        );
    }

    #[test]
    fn server_rejects_an_unmasked_frame() {
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let mut to = [0; 64];
        assert_eq!(
            ws_server.read(&[0x81, 0x01, b'a'], &mut to).err(),
            Some(Error::UnmaskedClientFrame)
        );
    }

    #[test]
    fn server_accepts_a_masked_frame() {
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let mut to = [0; 64];
        let result = ws_server
            .read(&[0x81, 0x81, 1, 2, 3, 4, b'a' ^ 1], &mut to)
            .unwrap();
        assert_eq!(&to[..result.len_to], b"a");
    }

    #[test]
    fn control_frame_waits_for_its_whole_payload() {
        for frame in [&[0x88, 0x09, b'A', 0, 0][..], &[0x89, 0x05, b'p', b'i']] {
            assert_eq!(
                read_frames(frame, 1).err(),
                Some(Error::ReadFrameIncomplete),
                "{frame:x?}"
            );
        }
    }

    #[test]
    fn control_frame_longer_than_125_bytes_is_rejected() {
        let frame = [&[0x89, 126, 0, 126][..], &[0; 126]].concat();
        assert_eq!(
            read_frames(&frame, 1).err(),
            Some(Error::InvalidFrameLength)
        );
    }

    #[test]
    fn length_must_use_the_minimal_encoding() {
        for header in [
            &[0x82, 126, 0, 125][..],
            &[0x82, 127, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF],
            &[0x82, 127, 0x80, 0, 0, 0, 0, 1, 0, 0],
        ] {
            assert_eq!(
                read_frames(header, 1).err(),
                Some(Error::InvalidFrameLength),
                "{header:x?}"
            );
        }
        assert!(read_frames(&[0x82, 126, 0, 126], 1).is_ok());
    }

    #[test]
    fn control_frame_payload_must_fit_into_the_output() {
        let mut ws_client = WebSocketClient::new_client(rand::rng());
        ws_client.state = WebSocketState::Open;
        let mut to = [0; 2];
        assert_eq!(
            ws_client
                .read(&[0x89, 0x03, b'a', b'b', b'c'], &mut to)
                .err(),
            Some(Error::WriteToBufferTooSmall)
        );
    }

    #[test]
    fn fragmented_control_frame_is_rejected() {
        assert_eq!(
            read_frames(&[0x09, 0x00], 1).err(),
            Some(Error::FragmentedControlFrame)
        );
    }

    #[test]
    fn data_frame_inside_a_fragmented_message_is_rejected() {
        let frames = [0x01, 0x01, b'a', 0x01, 0x01, b'b'];
        assert_eq!(
            read_frames(&frames, 2).err(),
            Some(Error::UnexpectedDataFrame)
        );
    }

    #[test]
    fn continuation_frame_after_a_finished_message_is_rejected() {
        let frames = [0x01, 0x01, b'a', 0x80, 0x01, b'b', 0x00, 0x01, b'c'];
        assert!(read_frames(&frames, 2).unwrap().end_of_message);
        assert_eq!(
            read_frames(&frames, 3).err(),
            Some(Error::UnexpectedContinuationFrame)
        );
    }

    #[test]
    fn close_frame_payload_is_validated() {
        for (frame, expected) in [
            (&[0x88, 0x01, 0x03][..], Some(Error::InvalidFrameLength)),
            (
                &[0x88, 0x02, 0x00, 0x00],
                Some(Error::InvalidCloseStatusCode),
            ),
            (
                &[0x88, 0x02, 0x03, 0xEC],
                Some(Error::InvalidCloseStatusCode),
            ),
            (
                &[0x88, 0x02, 0x03, 0xED],
                Some(Error::InvalidCloseStatusCode),
            ),
            (
                &[0x88, 0x04, 0x03, 0xE8, 0xFF, 0xFF],
                Some(Error::Utf8Error),
            ),
            (&[0x88, 0x00], None),
            (&[0x88, 0x02, 0x03, 0xE8], None),
            (&[0x88, 0x02, 0x0B, 0xB8], None),
            (&[0x88, 0x04, 0x03, 0xE8, b'o', b'k'], None),
        ] {
            assert_eq!(read_frames(frame, 1).err(), expected, "{frame:x?}");
        }
    }

    fn open_server() -> WebSocketServer {
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        ws_server
    }

    #[test]
    fn write_that_does_not_fit_can_be_retried_in_fragments() {
        let mut ws_server = open_server();
        let mut to = [0; 8];
        let mut first_byte_of = |end_of_message: bool, payload: &[u8]| {
            ws_server
                .write(
                    WebSocketSendMessageType::Text,
                    end_of_message,
                    payload,
                    &mut to,
                )
                .map(|_| to[0])
        };
        assert_eq!(
            first_byte_of(false, b"too long"),
            Err(Error::WriteToBufferTooSmall)
        );
        assert_eq!(first_byte_of(true, b"short"), Ok(0x81));

        assert_eq!(first_byte_of(false, b"too"), Ok(0x01));
        assert_eq!(
            first_byte_of(true, b" long!!"),
            Err(Error::WriteToBufferTooSmall)
        );
        assert_eq!(first_byte_of(true, b" lo"), Ok(0x80));
    }

    #[test]
    fn close_that_does_not_fit_can_be_retried() {
        let mut ws_server = open_server();
        let mut to = [0; 8];
        assert_eq!(
            ws_server.close(
                WebSocketCloseStatusCode::NormalClosure,
                Some("bye now"),
                &mut to
            ),
            Err(Error::WriteToBufferTooSmall)
        );
        assert_eq!(ws_server.state, WebSocketState::Open);
        let len = ws_server
            .close(
                WebSocketCloseStatusCode::NormalClosure,
                Some("bye"),
                &mut to,
            )
            .unwrap();
        assert_eq!(&to[..len], &[0x88, 0x05, 0x03, 0xE8, b'b', b'y', b'e']);
        assert_eq!(ws_server.state, WebSocketState::CloseSent);
    }

    #[test]
    fn close_reply_that_does_not_fit_can_be_retried() {
        let mut ws_server = open_server();
        ws_server.state = WebSocketState::CloseReceived;
        let mut to = [0; 3];
        assert_eq!(
            ws_server.write(
                WebSocketSendMessageType::CloseReply,
                true,
                &[0x03, 0xE8],
                &mut to
            ),
            Err(Error::WriteToBufferTooSmall)
        );
        assert_eq!(ws_server.state, WebSocketState::CloseReceived);
        let mut to = [0; 4];
        ws_server
            .write(
                WebSocketSendMessageType::CloseReply,
                true,
                &[0x03, 0xE8],
                &mut to,
            )
            .unwrap();
        assert_eq!(ws_server.state, WebSocketState::Closed);
    }

    #[test]
    fn close_frame_without_status_code_reports_no_status() {
        let close = read_frames(&[0x88, 0x00], 1).unwrap();
        assert_eq!(close.close_status, Some(WebSocketCloseStatusCode::Empty));
        assert_eq!(close.len_to, 0);
    }

    #[test]
    fn close_cuts_a_long_description_at_a_character_boundary() {
        let mut ws_client = WebSocketClient::new_client(rand::rng());
        ws_client.state = WebSocketState::Open;
        let description = "é".repeat(100);
        let mut to = [0; 256];
        let len = ws_client
            .close(
                WebSocketCloseStatusCode::NormalClosure,
                Some(&description),
                &mut to,
            )
            .unwrap();

        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let mut payload = [0; 256];
        let result = ws_server.read(&to[..len], &mut payload).unwrap();
        assert_eq!(
            result.message_type,
            WebSocketReceiveMessageType::CloseMustReply
        );
        assert_eq!(result.len_to, 2 + 122);
        assert!(str::from_utf8(&payload[2..result.len_to]).is_ok());
    }

    #[test]
    fn payload_of_65535_bytes_uses_a_16_bit_length() {
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let payload = std::vec![0; 65535];
        let mut to = std::vec![0; 65535 + 14];
        let len = ws_server
            .write(WebSocketSendMessageType::Binary, true, &payload, &mut to)
            .unwrap();
        assert_eq!(len, 65535 + 4);
        assert_eq!(&to[1..4], &[126, 0xFF, 0xFF]);
    }

    #[test]
    fn oversized_control_frame_is_rejected() {
        let ws_client = WebSocketClient::new_client(rand::rng());
        // ping with a 64 bit payload length of u64::MAX
        let frame = [0x89, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(matches!(
            ws_client.next_control_frame_len(&frame),
            Err(Error::InvalidFrameLength)
        ));
    }

    #[test]
    fn read_fragmented_message_one_byte_at_a_time() {
        let mut ws_server = WebSocketServer::new_server();
        let mut frames = std::vec::Vec::new();
        let mut scratch = [0u8; 64];
        for (payload, op_code, fin) in [
            ("hello", WebSocketOpCode::TextFrame, false),
            (" world", WebSocketOpCode::ContinuationFrame, true),
        ] {
            let len = ws_server
                .write_frame(payload.as_bytes(), &mut scratch, op_code, fin)
                .unwrap();
            frames.extend_from_slice(&scratch[..len]);
        }

        let mut ws_client = WebSocketClient::new_client(rand::rng());
        ws_client.state = WebSocketState::Open;
        let mut message = [0u8; 64];
        let mut message_len = 0;
        let mut from_start = 0;
        for from_end in 1..=frames.len() {
            match ws_client.read(&frames[from_start..from_end], &mut message[message_len..]) {
                Ok(ws_result) => {
                    assert_eq!(ws_result.message_type, WebSocketReceiveMessageType::Text);
                    from_start += ws_result.len_from;
                    message_len += ws_result.len_to;
                    assert_eq!(ws_result.end_of_message, from_end == frames.len());
                }
                Err(Error::ReadFrameIncomplete) => {}
                Err(e) => panic!("unexpected error {e:?}"),
            }
        }

        assert_eq!(from_start, frames.len());
        assert_eq!(&message[..message_len], b"hello world");
    }

    #[test]
    fn opening_handshake() {
        let client_request = "GET /chat HTTP/1.1\r\n\
         Host: localhost:5000\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0\r\n\
         Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
         Accept-Language: en-US,en;q=0.5\r\n\
         Accept-Encoding: gzip, deflate\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Origin: http://localhost:5000\r\n\
         Sec-WebSocket-Extensions: permessage-deflate\r\n\
         Sec-WebSocket-Key: Z7OY1UwHOx/nkSz38kfPwg==\r\n\
         Sec-WebSocket-Protocol: chat\r\n\
         DNT: 1\r\n\
         Connection: keep-alive, Upgrade\r\n\
         Pragma: no-cache\r\n\
         Cache-Control: no-cache\r\n\
         Upgrade: websocket\r\n\
         \r\n\
         ";

        let (request, len) = Request::read(client_request.as_bytes()).unwrap();
        assert_eq!(len, client_request.len());
        assert!(request.offers("chat"));
        let mut web_socket = WebSocketServer::new_server();

        let mut ws_buffer: [u8; 3000] = [0; 3000];
        let size = web_socket
            .server_accept(&request, None, &mut ws_buffer)
            .unwrap();
        let response = std::str::from_utf8(&ws_buffer[..size]).unwrap();
        let client_response_expected = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: ptPnPeDOTo6khJlzmLhOZSh2tAY=\r\n\r\n";
        assert_eq!(client_response_expected, response);
    }

    #[test]
    fn server_write_frame() {
        let mut buffer: [u8; 1000] = [0; 1000];
        let mut ws_server = WebSocketServer::new_server();
        let len = ws_server
            .write_frame(
                "hello".as_bytes(),
                &mut buffer,
                WebSocketOpCode::TextFrame,
                true,
            )
            .unwrap();
        let expected = [129, 5, 104, 101, 108, 108, 111];
        assert_eq!(&expected, &buffer[..len]);
    }

    #[test]
    fn closing_handshake() {
        let mut buffer1: [u8; 500] = [0; 500];
        let mut buffer2: [u8; 500] = [0; 500];

        let mut rng = rand::rng();

        let mut ws_client = WebSocketClient::new_client(&mut rng);
        ws_client.state = WebSocketState::Open;

        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;

        // client sends a close (initiates the close handshake)
        ws_client
            .close(WebSocketCloseStatusCode::NormalClosure, None, &mut buffer1)
            .unwrap();

        // check that the client receives the close message
        let ws_result = ws_server.read(&buffer1, &mut buffer2).unwrap();
        assert_eq!(
            WebSocketReceiveMessageType::CloseMustReply,
            ws_result.message_type
        );

        // server MUST respond to complete the handshake
        ws_server
            .write(
                WebSocketSendMessageType::CloseReply,
                true,
                &buffer2[..ws_result.len_to],
                &mut buffer1,
            )
            .unwrap();
        assert_eq!(WebSocketState::Closed, ws_server.state);

        // check that the client receives the close message from the server
        let ws_result = ws_client.read(&buffer1, &mut buffer2).unwrap();
        assert_eq!(WebSocketState::Closed, ws_client.state);

        assert_eq!(
            WebSocketReceiveMessageType::CloseCompleted,
            ws_result.message_type
        );
    }

    #[test]
    fn send_message_from_client_to_server() {
        let mut buffer1: [u8; 1000] = [0; 1000];
        let mut buffer2: [u8; 1000] = [0; 1000];

        // how to create a client
        let mut ws_client = WebSocketClient::new_client(rand::rng());

        ws_client.state = WebSocketState::Open;
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;

        // client sends a Text message
        let hello = "hello";
        let num_bytes = ws_client
            .write(
                WebSocketSendMessageType::Text,
                true,
                hello.as_bytes(),
                &mut buffer1,
            )
            .unwrap();

        // check that the Server receives the Text message
        let ws_result = ws_server.read(&buffer1[..num_bytes], &mut buffer2).unwrap();
        assert_eq!(WebSocketReceiveMessageType::Text, ws_result.message_type);
        let received = std::str::from_utf8(&buffer2[..ws_result.len_to]).unwrap();
        assert_eq!(hello, received);
    }

    #[test]
    fn send_message_from_server_to_client() {
        let mut buffer1: [u8; 1000] = [0; 1000];
        let mut buffer2: [u8; 1000] = [0; 1000];

        let mut ws_client = WebSocketClient::new_client(rand::rng());
        ws_client.state = WebSocketState::Open;
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;

        // server sends a Text message
        let hello = "hello";
        let num_bytes = ws_server
            .write(
                WebSocketSendMessageType::Text,
                true,
                hello.as_bytes(),
                &mut buffer1,
            )
            .unwrap();

        // check that the client receives the Text message
        let ws_result = ws_client.read(&buffer1[..num_bytes], &mut buffer2).unwrap();
        assert_eq!(WebSocketReceiveMessageType::Text, ws_result.message_type);
        let received = std::str::from_utf8(&buffer2[..ws_result.len_to]).unwrap();
        assert_eq!(hello, received);
    }

    #[test]
    fn receive_buffer_too_small() {
        let mut buffer1: [u8; 1000] = [0; 1000];
        let mut buffer2: [u8; 1000] = [0; 1000];

        let mut ws_client = WebSocketClient::new_client(rand::rng());
        ws_client.state = WebSocketState::Open;
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;

        let hello = "hello";
        ws_server
            .write(
                WebSocketSendMessageType::Text,
                true,
                hello.as_bytes(),
                &mut buffer1,
            )
            .unwrap();

        match ws_client.read(&buffer1[..1], &mut buffer2) {
            Err(Error::ReadFrameIncomplete) => {
                // test passes
            }
            _ => {
                assert_eq!(true, false);
            }
        }
    }

    #[test]
    fn receive_large_frame_with_small_receive_buffer() {
        let mut buffer1: [u8; 1000] = [0; 1000];
        let mut buffer2: [u8; 1000] = [0; 1000];

        let mut ws_client = WebSocketClient::new_client(rand::rng());
        ws_client.state = WebSocketState::Open;
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;

        let hello = "hello";
        ws_server
            .write(
                WebSocketSendMessageType::Text,
                true,
                hello.as_bytes(),
                &mut buffer1,
            )
            .unwrap();

        let ws_result = ws_client.read(&buffer1[..2], &mut buffer2).unwrap();
        assert_eq!(0, ws_result.len_to);
        assert!(!ws_result.end_of_message);
        let ws_result = ws_client.read(&buffer1[2..3], &mut buffer2).unwrap();
        assert_eq!(1, ws_result.len_to);
        assert_eq!(
            "h",
            std::str::from_utf8(&buffer2[..ws_result.len_to]).unwrap()
        );
        assert!(!ws_result.end_of_message);
        let ws_result = ws_client.read(&buffer1[3..], &mut buffer2).unwrap();
        assert_eq!(4, ws_result.len_to);
        assert_eq!(
            "ello",
            std::str::from_utf8(&buffer2[..ws_result.len_to]).unwrap()
        );
        assert!(ws_result.end_of_message);
    }

    #[test]
    fn send_large_frame() {
        let buffer1 = [0u8; 15944];
        let mut buffer2 = [0u8; 64000];
        let mut buffer3 = [0u8; 64000];

        let mut ws_client = WebSocketClient::new_client(rand::rng());
        ws_client.state = WebSocketState::Open;

        ws_client
            .write(
                WebSocketSendMessageType::Binary,
                true,
                &buffer1,
                &mut buffer2,
            )
            .unwrap();

        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let ws_result = ws_server.read(&buffer2, &mut buffer3).unwrap();
        assert!(ws_result.end_of_message);
        assert_eq!(buffer1.len(), ws_result.len_to);
    }

    #[test]
    fn receive_large_frame_multi_read() {
        let mut buffer1 = [0_u8; 1000];
        let mut buffer2 = [0_u8; 1000];

        let mut ws_client = WebSocketClient::new_client(rand::rng());
        ws_client.state = WebSocketState::Open;
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;

        let message = "Hello, world. This is a long message that takes multiple reads";
        ws_server
            .write(
                WebSocketSendMessageType::Text,
                true,
                message.as_bytes(),
                &mut buffer1,
            )
            .unwrap();

        let mut buffer2_cursor = 0;
        let ws_result = ws_client.read(&buffer1[..40], &mut buffer2).unwrap();
        assert!(!ws_result.end_of_message);
        buffer2_cursor += ws_result.len_to;
        let ws_result = ws_client
            .read(
                &buffer1[ws_result.len_from..],
                &mut buffer2[buffer2_cursor..],
            )
            .unwrap();
        assert!(ws_result.end_of_message);
        buffer2_cursor += ws_result.len_to;

        assert_eq!(
            message,
            std::str::from_utf8(&buffer2[..buffer2_cursor]).unwrap()
        );
    }

    #[test]
    fn multiple_messages_in_receive_buffer() {
        let mut buffer1 = [0_u8; 1000];
        let mut buffer2 = [0_u8; 1000];

        let mut ws_client = WebSocketClient::new_client(rand::rng());
        ws_client.state = WebSocketState::Open;
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;

        let message1 = "Hello, world.";
        let len = ws_client
            .write(
                WebSocketSendMessageType::Text,
                true,
                message1.as_bytes(),
                &mut buffer1,
            )
            .unwrap();
        let message2 = "This is another message.";
        ws_client
            .write(
                WebSocketSendMessageType::Text,
                true,
                message2.as_bytes(),
                &mut buffer1[len..],
            )
            .unwrap();

        let mut buffer1_cursor = 0;
        let mut buffer2_cursor = 0;
        let ws_result = ws_server
            .read(&buffer1[buffer1_cursor..], &mut buffer2)
            .unwrap();
        assert!(ws_result.end_of_message);
        buffer1_cursor += ws_result.len_from;
        buffer2_cursor += ws_result.len_to;
        let ws_result = ws_server
            .read(&buffer1[buffer1_cursor..], &mut buffer2[buffer2_cursor..])
            .unwrap();
        assert!(ws_result.end_of_message);
        assert_eq!(
            message1,
            std::str::from_utf8(&buffer2[..buffer2_cursor]).unwrap()
        );

        assert_eq!(
            message2,
            std::str::from_utf8(&buffer2[buffer2_cursor..buffer2_cursor + ws_result.len_to])
                .unwrap()
        );
    }

    #[test]
    fn receive_large_frame_with_small_send_buffer() {
        let mut buffer1: [u8; 1000] = [0; 1000];
        let mut buffer2: [u8; 1000] = [0; 1000];

        let mut ws_client = WebSocketClient::new_client(rand::rng());
        ws_client.state = WebSocketState::Open;
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;

        let hello = "hello";
        ws_server
            .write(
                WebSocketSendMessageType::Text,
                true,
                hello.as_bytes(),
                &mut buffer1,
            )
            .unwrap();

        let ws_result = ws_client.read(&buffer1, &mut buffer2[..1]).unwrap();
        assert_eq!(1, ws_result.len_to);
        assert_eq!(
            "h",
            std::str::from_utf8(&buffer2[..ws_result.len_to]).unwrap()
        );
        assert!(!ws_result.end_of_message);
        let ws_result = ws_client
            .read(&buffer1[ws_result.len_from..], &mut buffer2[..4])
            .unwrap();
        assert_eq!(4, ws_result.len_to);
        assert_eq!(
            "ello",
            std::str::from_utf8(&buffer2[..ws_result.len_to]).unwrap()
        );
        assert!(ws_result.end_of_message);
    }

    #[test]
    fn control_frames_inside_a_fragmented_message_keep_their_opcode() {
        // first header byte of an unmasked frame: FIN bit followed by the opcode
        let mut buffer = [0; 64];
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let mut first_header_byte = |message_type, end_of_message| {
            ws_server
                .write(message_type, end_of_message, b"x", &mut buffer)
                .unwrap();
            buffer[0]
        };

        assert_eq!(
            first_header_byte(WebSocketSendMessageType::Text, false),
            0x01
        );
        assert_eq!(
            first_header_byte(WebSocketSendMessageType::Ping, false),
            0x89
        );
        assert_eq!(
            first_header_byte(WebSocketSendMessageType::Pong, true),
            0x8A
        );
        assert_eq!(
            first_header_byte(WebSocketSendMessageType::Text, true),
            0x80
        );
    }

    #[test]
    fn send_two_frame_message() {
        let mut buffer1: [u8; 1000] = [0; 1000];
        let mut buffer2: [u8; 1000] = [0; 1000];

        let mut ws_client = WebSocketClient::new_client(rand::rng());
        ws_client.state = WebSocketState::Open;
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;

        // client sends a fragmented Text message
        let hello = "Hello, ";
        let num_bytes_hello = ws_server
            .write(
                WebSocketSendMessageType::Text,
                false,
                hello.as_bytes(),
                &mut buffer1,
            )
            .unwrap();

        // client sends the remaining Text message
        let world = "World!";
        let num_bytes_world = ws_server
            .write(
                WebSocketSendMessageType::Text,
                true,
                world.as_bytes(),
                &mut buffer1[num_bytes_hello..],
            )
            .unwrap();

        // check that the Server receives the entire Text message
        let ws_result1 = ws_client
            .read(&buffer1[..num_bytes_hello], &mut buffer2)
            .unwrap();
        assert_eq!(WebSocketReceiveMessageType::Text, ws_result1.message_type);
        assert!(!ws_result1.end_of_message);
        let ws_result2 = ws_client
            .read(
                &buffer1[num_bytes_hello..num_bytes_hello + num_bytes_world],
                &mut buffer2[ws_result1.len_to..],
            )
            .unwrap();
        assert_eq!(WebSocketReceiveMessageType::Text, ws_result2.message_type);
        assert!(ws_result2.end_of_message);

        let received =
            std::str::from_utf8(&buffer2[..ws_result1.len_to + ws_result2.len_to]).unwrap();
        assert_eq!("Hello, World!", received);
    }

    #[test]
    fn send_multi_frame_message() {
        let mut buffer1: [u8; 1000] = [0; 1000];
        let mut buffer2: [u8; 1000] = [0; 1000];

        let mut ws_client = WebSocketClient::new_client(rand::rng());
        ws_client.state = WebSocketState::Open;
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;

        // server sends the first fragmented Text frame
        let fragment1 = "fragment1";
        let fragment1_num_bytes = ws_server
            .write(
                WebSocketSendMessageType::Text,
                false,
                fragment1.as_bytes(),
                &mut buffer1,
            )
            .unwrap();

        // send fragment2 as a continuation frame
        let fragment2 = "fragment2";
        let fragment2_num_bytes = ws_server
            .write(
                WebSocketSendMessageType::Text,
                false,
                fragment2.as_bytes(),
                &mut buffer1[fragment1_num_bytes..],
            )
            .unwrap();

        // send fragment3 as a continuation frame and indicate that this is the last frame
        let fragment3 = "fragment3";
        let _fragment3_num_bytes = ws_server
            .write(
                WebSocketSendMessageType::Text,
                true,
                fragment3.as_bytes(),
                &mut buffer1[fragment1_num_bytes + fragment2_num_bytes..],
            )
            .unwrap();

        // check that the client receives the "fragment1" Text message
        let ws_result = ws_client.read(&buffer1, &mut buffer2).unwrap();
        assert_eq!(WebSocketReceiveMessageType::Text, ws_result.message_type);
        let received = std::str::from_utf8(&buffer2[..ws_result.len_to]).unwrap();
        assert_eq!(fragment1, received);
        assert!(!ws_result.end_of_message);
        let mut read_cursor = ws_result.len_from;

        // check that the client receives the "fragment2" Text message
        let ws_result = ws_client
            .read(&buffer1[read_cursor..], &mut buffer2)
            .unwrap();
        assert_eq!(WebSocketReceiveMessageType::Text, ws_result.message_type);
        let received = std::str::from_utf8(&buffer2[..ws_result.len_to]).unwrap();
        assert_eq!(fragment2, received);
        assert!(!ws_result.end_of_message);
        read_cursor += ws_result.len_from;

        // check that the client receives the "fragment3" Text message
        let ws_result = ws_client
            .read(&buffer1[read_cursor..], &mut buffer2)
            .unwrap();
        assert_eq!(WebSocketReceiveMessageType::Text, ws_result.message_type);
        let received = std::str::from_utf8(&buffer2[..ws_result.len_to]).unwrap();
        assert_eq!(fragment3, received);
        assert!(ws_result.end_of_message);

        // check the actual bytes in the write buffer for fragment1
        let (is_fin_bit_set, op_code) = read_first_byte(buffer1[0]);
        assert!(!is_fin_bit_set);
        assert_eq!(op_code, WebSocketOpCode::TextFrame);

        // check the actual bytes in the write buffer for fragment2
        let (is_fin_bit_set, op_code) = read_first_byte(buffer1[fragment1_num_bytes]);
        assert!(!is_fin_bit_set);
        assert_eq!(op_code, WebSocketOpCode::ContinuationFrame);

        // check the actual bytes in the write buffer for fragment3
        let (is_fin_bit_set, op_code) =
            read_first_byte(buffer1[fragment1_num_bytes + fragment2_num_bytes]);
        assert!(is_fin_bit_set);
        assert_eq!(op_code, WebSocketOpCode::ContinuationFrame);
    }

    fn read_first_byte(byte: u8) -> (bool, WebSocketOpCode) {
        const FIN_BIT_FLAG: u8 = 0x80;
        const OP_CODE_FLAG: u8 = 0x0F;
        let is_fin_bit_set = (byte & FIN_BIT_FLAG) == FIN_BIT_FLAG;
        let op_code = get_op_code(byte & OP_CODE_FLAG).unwrap();
        (is_fin_bit_set, op_code)
    }
}
