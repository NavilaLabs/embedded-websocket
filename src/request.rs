use core::str;

use crate::{
    head::{is_token_byte, Head},
    Error, Result, WebSocketKey, WebSocketSubProtocol,
};

pub(crate) const BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

const UPGRADE_REQUIRED: &[u8] = b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// The HTTP request that opens a connection, as seen by a server before it decides how to answer.
pub struct Request<'a> {
    method: &'a str,
    path: &'a str,
    head: Head<'a>,
}

impl<'a> Request<'a> {
    /// Parses a complete request head that ends with the empty line.
    pub(crate) fn parse(head: &'a [u8]) -> Result<Self> {
        let head = Head::parse(head)?;
        let (method, path, version) = head.start_line().ok_or(Error::HttpHeaderInvalid)?;
        if method.is_empty()
            || !method.bytes().all(is_token_byte)
            || path.is_empty()
            || version != "HTTP/1.1"
        {
            return Err(Error::HttpHeaderInvalid);
        }
        Ok(Self { method, path, head })
    }

    /// The request target, for example `/chat?id=1`.
    pub fn path(&self) -> &'a str {
        self.path
    }

    /// The value of the first header called `name`, compared case-insensitively, without the
    /// whitespace around it.
    pub fn header(&self, name: &str) -> Option<&'a [u8]> {
        self.head.field(name)
    }

    /// Whether the client offered the sub protocol `protocol` in `Sec-WebSocket-Protocol`.
    pub fn offers(&self, protocol: &str) -> bool {
        self.offered().any(|offered| offered == protocol)
    }

    pub(crate) fn offered(&self) -> impl Iterator<Item = &'a str> {
        self.head.tokens("sec-websocket-protocol")
    }

    /// Checks that this is a websocket upgrade request and returns its key, or the response that
    /// rejects it (RFC 6455 section 4.2.1).
    pub(crate) fn upgrade_key(&self) -> core::result::Result<WebSocketKey, &'static [u8]> {
        if self.method != "GET"
            || !self.head.has_token("upgrade", "websocket")
            || !self.head.has_token("connection", "upgrade")
        {
            return Err(BAD_REQUEST);
        }
        if self.header("sec-websocket-version") != Some(b"13") {
            return Err(UPGRADE_REQUIRED);
        }
        self.header("sec-websocket-key")
            .and_then(|key| str::from_utf8(key).ok())
            .filter(|key| key.len() == 24)
            .and_then(|key| WebSocketKey::try_from(key).ok())
            .ok_or(BAD_REQUEST)
    }

    pub(crate) fn sub_protocol(&self, protocol: &str) -> Result<WebSocketSubProtocol> {
        if !self.offers(protocol) {
            return Err(Error::SubProtocolNotOffered);
        }
        WebSocketSubProtocol::try_from(protocol).map_err(|_| Error::SubProtocolNotOffered)
    }
}

/// How a server answers the HTTP request that opens a connection.
pub enum Decision<'a> {
    /// Completes the opening handshake, optionally with a sub protocol the client offered.
    ///
    /// If the request is not a valid websocket upgrade, the framer answers with
    /// `400 Bad Request` or `426 Upgrade Required` instead.
    Accept {
        /// The sub protocol to use. It must be one the client offered.
        sub_protocol: Option<&'a str>,
    },
    /// Sends this complete HTTP response, for example a `404 Not Found` or a web page, and does
    /// not open a websocket.
    Respond(&'a [u8]),
}
