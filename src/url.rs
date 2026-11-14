use core::net::{Ipv4Addr, Ipv6Addr};

use crate::{Error, Result, WebSocketOptions};

/// A `ws://` or `wss://` URL split into the parts a client needs (RFC 6455 section 3).
///
/// All parts borrow from the parsed string.
///
/// # Examples
///
/// ```
/// use embedded_io_websocket::WebSocketUrl;
///
/// let url = WebSocketUrl::parse("wss://example.com:8443/chat?room=1").unwrap();
/// assert!(url.is_secure());
/// assert_eq!(url.host(), "example.com");
/// assert_eq!(url.port(), 8443);
///
/// let options = url.options();
/// assert_eq!(options.path, "/chat?room=1");
/// assert_eq!(options.host, "example.com:8443");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebSocketUrl<'a> {
    is_secure: bool,
    host: &'a str,
    port: u16,
    authority: &'a str,
    resource: &'a str,
}

impl<'a> WebSocketUrl<'a> {
    /// Parses `url`, for example `ws://192.168.1.10:8080/chat` or `wss://[::1]/`.
    ///
    /// The scheme is `ws` or `wss` in any case. The host is a name of letters, digits, `-`, `.`,
    /// `_` and `~`, an IPv4 address or an IPv6 address in brackets. Without a port, the default
    /// port of the scheme is used. The path and query may contain the characters RFC 3986 allows
    /// there, including percent encoded ones, which are kept as they are.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] if `url` is not such a URL, also if it contains a fragment (`#`),
    /// which RFC 6455 forbids, user information (`user@`), which would be sent in plain text, an
    /// empty port or port 0.
    pub fn parse(url: &'a str) -> Result<Self> {
        let (scheme, rest) = url.split_once("://").ok_or(Error::InvalidUrl)?;
        let (is_secure, default_port) = if scheme.eq_ignore_ascii_case("ws") {
            (false, 80)
        } else if scheme.eq_ignore_ascii_case("wss") {
            (true, 443)
        } else {
            return Err(Error::InvalidUrl);
        };
        let authority_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, resource) = rest.split_at(authority_len);
        if !resource.bytes().all(is_resource_byte) || !is_percent_encoding_valid(resource) {
            return Err(Error::InvalidUrl);
        }
        let (host, port) = split_host_and_port(authority)?;
        Ok(Self {
            is_secure,
            host,
            port: port.unwrap_or(default_port),
            authority,
            resource,
        })
    }

    /// Returns `true` for `wss://`: the connection must be wrapped in TLS before the opening
    /// handshake.
    pub fn is_secure(&self) -> bool {
        self.is_secure
    }

    /// The host to resolve and connect to, and to verify the TLS certificate against. An IPv6
    /// address is returned without brackets.
    pub fn host(&self) -> &'a str {
        self.host
    }

    /// The port to connect to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the options of the opening handshake for this URL: its path and query, and its
    /// host and port as written for the `Host` header. Origin, sub protocols and additional
    /// headers are not set; set them on the result if the server needs them.
    pub fn options(&self) -> WebSocketOptions<'a> {
        WebSocketOptions {
            path: self.resource,
            host: self.authority,
            origin: None,
            sub_protocols: None,
            additional_headers: None,
        }
    }
}

fn split_host_and_port(authority: &str) -> Result<(&str, Option<u16>)> {
    let (host, port) = match authority.strip_prefix('[') {
        Some(rest) => {
            let (address, after) = rest.split_once(']').ok_or(Error::InvalidUrl)?;
            address.parse::<Ipv6Addr>().map_err(|_| Error::InvalidUrl)?;
            let port = match after {
                "" => None,
                after => Some(after.strip_prefix(':').ok_or(Error::InvalidUrl)?),
            };
            (address, port)
        }
        None => {
            let (host, port) = match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            };
            if host.is_empty() || !host.bytes().all(is_host_byte) {
                return Err(Error::InvalidUrl);
            }
            // URL parsers that follow the WHATWG URL standard, like browsers, read such a host as
            // an IPv4 address in one of several notations, so only the usual one is accepted
            if ends_in_a_number(host) && host.parse::<Ipv4Addr>().is_err() {
                return Err(Error::InvalidUrl);
            }
            (host, port)
        }
    };
    Ok((host, port.map(parse_port).transpose()?))
}

fn ends_in_a_number(host: &str) -> bool {
    let last_label = host
        .strip_suffix('.')
        .unwrap_or(host)
        .rsplit('.')
        .next()
        .unwrap_or_default();
    let hex_digits = last_label
        .strip_prefix("0x")
        .or_else(|| last_label.strip_prefix("0X"));
    match hex_digits {
        Some(digits) => digits.bytes().all(|byte| byte.is_ascii_hexdigit()),
        None => !last_label.is_empty() && last_label.bytes().all(|byte| byte.is_ascii_digit()),
    }
}

fn parse_port(port: &str) -> Result<u16> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::InvalidUrl);
    }
    match port.parse() {
        Ok(0) | Err(_) => Err(Error::InvalidUrl),
        Ok(port) => Ok(port),
    }
}

fn is_host_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

// RFC 3986 section 3.3 and 3.4: unreserved, percent encoded, sub-delims, ":", "@", "/" and "?"
pub(crate) fn is_resource_byte(byte: u8) -> bool {
    is_host_byte(byte)
        || matches!(
            byte,
            b'%' | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'/'
                | b'?'
        )
}

pub(crate) fn is_percent_encoding_valid(resource: &str) -> bool {
    let bytes = resource.as_bytes();
    bytes.iter().enumerate().all(|(index, &byte)| {
        byte != b'%'
            || bytes
                .get(index + 1..index + 3)
                .is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit))
    })
}
