use core::{net::Ipv6Addr, str};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use crate::{
    head::{self, is_token_byte, Head},
    url::is_percent_encoding_valid,
    Error, Result, WebSocketKey,
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
    /// Reads the request head at the start of `from`, which holds the bytes received so far.
    ///
    /// Returns the request and the length of its head, after which the first websocket frames
    /// start.
    ///
    /// # Errors
    ///
    /// * [`Error::HttpHeaderIncomplete`] if `from` does not hold the whole head yet.
    /// * [`Error::HttpHeaderInvalid`] if the head is not a valid HTTP/1.1 request, also if it
    ///   does not have exactly one valid `Host` header (RFC 9112 section 3.2). Answer it with
    ///   `400 Bad Request` and close the connection.
    pub fn read(from: &'a [u8]) -> Result<(Self, usize)> {
        let len = head::head_len(from, &mut 0).ok_or(Error::HttpHeaderIncomplete)?;
        Ok((Self::parse(&from[..len])?, len))
    }

    /// Parses a complete request head that ends with the empty line.
    pub(crate) fn parse(head: &'a [u8]) -> Result<Self> {
        let head = Head::parse(head)?;
        let (method, path, version) = head.start_line().ok_or(Error::HttpHeaderInvalid)?;
        if method.is_empty()
            || !method.bytes().all(is_token_byte)
            || path.is_empty()
            || version != "HTTP/1.1"
            || !has_one_valid_host(&head)
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
    ///
    /// Offers that are not HTTP tokens are ignored, because a server must answer with a token
    /// (RFC 6455 section 4.2.2).
    pub fn offers(&self, protocol: &str) -> bool {
        self.head
            .tokens("sec-websocket-protocol")
            .any(|offered| offered == protocol && offered.bytes().all(is_token_byte))
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
        let version = self
            .head
            .unique_field("sec-websocket-version")
            .map_err(|_| BAD_REQUEST)?;
        if version != Some(b"13") {
            return Err(UPGRADE_REQUIRED);
        }
        self.head
            .unique_field("sec-websocket-key")
            .map_err(|_| BAD_REQUEST)?
            .and_then(|key| str::from_utf8(key).ok())
            .filter(|key| is_sixteen_base64_encoded_bytes(key))
            .and_then(|key| WebSocketKey::try_from(key).ok())
            .ok_or(BAD_REQUEST)
    }
}

// RFC 9112 section 3.2: a server must reject a request without exactly one valid Host field
fn has_one_valid_host(head: &Head<'_>) -> bool {
    match head.unique_field("host") {
        Ok(Some(value)) => str::from_utf8(value).is_ok_and(is_valid_host),
        _ => false,
    }
}

// uri-host [ ":" port ] of RFC 3986 section 3.2.2 and 3.2.3
fn is_valid_host(host: &str) -> bool {
    let (is_valid_name, port) = match host.strip_prefix('[') {
        Some(rest) => match rest.split_once(']') {
            Some((address, port)) => (address.parse::<Ipv6Addr>().is_ok(), port),
            None => return false,
        },
        None => {
            let (name, port) = host.split_at(host.find(':').unwrap_or(host.len()));
            let is_valid_name =
                name.bytes().all(is_reg_name_byte) && is_percent_encoding_valid(name);
            (is_valid_name, port)
        }
    };
    let is_valid_port = port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_digit()));
    is_valid_name && is_valid_port
}

// unreserved, pct-encoded and sub-delims of RFC 3986 section 3.2.2
fn is_reg_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~%!$&'()*+,;=".contains(&byte)
}

fn is_sixteen_base64_encoded_bytes(key: &str) -> bool {
    // two bytes more than a valid key needs, so a longer key does not fit
    let mut decoded = [0; 18];
    key.len() == 24 && BASE64.decode_slice(key, &mut decoded) == Ok(16)
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

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::*;

    fn upgrade_key_of(key: &str) -> core::result::Result<WebSocketKey, &'static [u8]> {
        let head = format!(
            "GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n"
        );
        Request::parse(head.as_bytes()).unwrap().upgrade_key()
    }

    #[test]
    fn offered_sub_protocols_that_are_not_tokens_cannot_be_chosen() {
        let head = "GET / HTTP/1.1\r\nHost: a\r\nSec-WebSocket-Protocol: a b, chat, x\"y\r\n\
                    Sec-WebSocket-Protocol: v2;q, v2.json\r\n\r\n";
        let request = Request::parse(head.as_bytes()).unwrap();
        assert!(request.offers("chat") && request.offers("v2.json"));
        for protocol in ["a b", "x\"y", "v2;q", ""] {
            assert!(!request.offers(protocol), "{protocol}");
        }
    }

    fn request_with_hosts(hosts: &str) -> Result<Request<'static>> {
        let head = format!("GET / HTTP/1.1\r\n{hosts}\r\n");
        Request::parse(std::string::String::leak(head).as_bytes())
    }

    // RFC 9112 section 3.2
    #[test]
    fn request_with_one_valid_host_is_accepted() {
        for host in [
            "Host: example.com\r\n",
            "Host: example.com:8080\r\n",
            "Host: 192.168.1.10:80\r\n",
            "Host: [::1]:443\r\n",
            "Host: [::1]\r\n",
            "Host: my-host_1.%41~!$&'()*+,;=\r\n",
            "Host: example.com:\r\n",
            "Host:\r\n",
        ] {
            assert!(request_with_hosts(host).is_ok(), "{host}");
        }
    }

    #[test]
    fn request_without_exactly_one_valid_host_is_rejected() {
        for hosts in [
            "",
            "Host: a\r\nHost: a\r\n",
            "Host: a b\r\n",
            "Host: a/b\r\n",
            "Host: a@b\r\n",
            "Host: a:b\r\n",
            "Host: a:80:80\r\n",
            "Host: %4\r\n",
            "Host: [::1\r\n",
            "Host: [not-ipv6]\r\n",
            "Host: [::1]80\r\n",
            "Host: ä\r\n",
        ] {
            assert_eq!(
                request_with_hosts(hosts).err(),
                Some(Error::HttpHeaderInvalid),
                "{hosts:?}"
            );
        }
    }

    // RFC 6455 section 11.3.1 and 11.3.5: neither field may appear more than once
    #[test]
    fn repeated_key_or_version_is_rejected() {
        let key = "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n";
        let version = "Sec-WebSocket-Version: 13\r\n";
        for fields in [
            format!("{key}{key}{version}"),
            format!("{key}{version}{version}"),
        ] {
            let head = format!(
                "GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                 {fields}\r\n"
            );
            let request = Request::parse(head.as_bytes()).unwrap();
            assert_eq!(request.upgrade_key(), Err(BAD_REQUEST), "{fields}");
        }
    }

    #[test]
    fn key_of_16_base64_encoded_bytes_is_accepted() {
        assert_eq!(
            upgrade_key_of("dGhlIHNhbXBsZSBub25jZQ==").unwrap(),
            "dGhlIHNhbXBsZSBub25jZQ=="
        );
    }

    #[test]
    fn key_that_is_not_16_base64_encoded_bytes_is_rejected() {
        for key in [
            "dGhlIHNhbXBsZSBub25jZ=Q",
            "dGhlIHNhbXBsZSBub25jZQ!!",
            "AAAAAAAAAAAAAAAAAAAAAAA=",
            "dGhlIHNhbXBsZSBub25jZR==",
        ] {
            assert_eq!(upgrade_key_of(key), Err(BAD_REQUEST), "{key}");
        }
    }
}
