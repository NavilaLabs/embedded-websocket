use core::str;

use crate::{Error, WebSocketKey, WebSocketSubProtocol};

pub(crate) const MAX_HEADERS: usize = 32;

pub(crate) const BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

const UPGRADE_REQUIRED: &[u8] = b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// The HTTP request that opens a connection, as seen by a server before it decides how to answer.
pub struct Request<'a> {
    method: &'a str,
    path: &'a str,
    headers: &'a [httparse::Header<'a>],
}

impl<'a> Request<'a> {
    pub(crate) fn new(
        request: &httparse::Request<'_, 'a>,
        headers: &'a [httparse::Header<'a>],
    ) -> Self {
        Self {
            method: request.method.unwrap_or_default(),
            path: request.path.unwrap_or_default(),
            headers,
        }
    }

    /// The request target, for example `/chat?id=1`.
    pub fn path(&self) -> &'a str {
        self.path
    }

    /// The value of the first header called `name`, compared case-insensitively.
    pub fn header(&self, name: &str) -> Option<&'a [u8]> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value)
    }

    /// Whether the client offered the sub protocol `protocol` in `Sec-WebSocket-Protocol`.
    pub fn offers(&self, protocol: &str) -> bool {
        self.header_tokens("sec-websocket-protocol")
            .any(|offered| offered == protocol)
    }

    /// Checks that this is a websocket upgrade request and returns its key, or the response that
    /// rejects it (RFC 6455 section 4.2.1).
    pub(crate) fn upgrade_key(&self) -> Result<WebSocketKey, &'static [u8]> {
        let has_token = |name, token: &str| {
            self.header_tokens(name)
                .any(|value| value.eq_ignore_ascii_case(token))
        };
        if self.method != "GET"
            || !has_token("upgrade", "websocket")
            || !has_token("connection", "upgrade")
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

    pub(crate) fn sub_protocol(&self, protocol: &str) -> Result<WebSocketSubProtocol, Error> {
        if !self.offers(protocol) {
            return Err(Error::SubProtocolNotOffered);
        }
        WebSocketSubProtocol::try_from(protocol).map_err(|_| Error::SubProtocolNotOffered)
    }

    // Values of all headers called `name` as one comma-separated list (RFC 9110 section 5.3).
    fn header_tokens(&self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |header| header.name.eq_ignore_ascii_case(name))
            .filter_map(|header| str::from_utf8(header.value).ok())
            .flat_map(|value| value.split(','))
            .map(str::trim)
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
