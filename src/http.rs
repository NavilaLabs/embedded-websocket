use super::*;
use crate::{head, request::Request};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use heapless::{String, Vec};

/// Websocket details extracted from the http header
pub struct WebSocketContext {
    /// The list of sub protocols is restricted to a maximum of 3
    pub sec_websocket_protocol_list: Vec<WebSocketSubProtocol, 3>,
    /// The websocket key user to build the accept string to complete the opening handshake
    pub sec_websocket_key: WebSocketKey,
}

/// Reads the HTTP request that opens a connection.
///
/// `from` holds the bytes received so far. Returns the length of the request head, after which
/// the first websocket frames start, and the websocket details if the request is a valid
/// websocket upgrade (RFC 6455 section 4.2.1).
///
/// # Examples
/// ```
/// use embedded_io_websocket as ws;
/// let client_request = "GET /chat HTTP/1.1\r\n\
///     Host: myserver.example.com\r\n\
///     Upgrade: websocket\r\n\
///     Connection: Upgrade\r\n\
///     Sec-WebSocket-Key: Z7OY1UwHOx/nkSz38kfPwg==\r\n\
///     Origin: http://example.com\r\n\
///     Sec-WebSocket-Protocol: chat, advancedchat\r\n\
///     Sec-WebSocket-Version: 13\r\n\
///     \r\n";
///
/// let (len, ws_context) = ws::read_http_header(client_request.as_bytes()).unwrap();
/// let ws_context = ws_context.unwrap();
/// assert_eq!(client_request.len(), len);
/// assert_eq!("Z7OY1UwHOx/nkSz38kfPwg==", ws_context.sec_websocket_key);
/// assert_eq!("chat", ws_context.sec_websocket_protocol_list[0]);
/// assert_eq!("advancedchat", ws_context.sec_websocket_protocol_list[1]);
/// ```
///
/// # Errors
/// * Returns `HttpHeaderIncomplete` if `from` does not contain the whole request head yet
/// * Returns `HttpHeaderInvalid` if the request head is not valid HTTP/1.1
pub fn read_http_header(from: &[u8]) -> Result<(usize, Option<WebSocketContext>)> {
    let len = head::head_len(from, &mut 0).ok_or(Error::HttpHeaderIncomplete)?;
    let request = Request::parse(&from[..len])?;
    let Ok(sec_websocket_key) = request.upgrade_key() else {
        return Ok((len, None));
    };
    let mut sec_websocket_protocol_list = Vec::new();
    // sub protocols that do not fit are skipped, so the server never selects them
    for offered in request.offered() {
        if let Ok(offered) = String::try_from(offered) {
            let _ = sec_websocket_protocol_list.push(offered);
        }
    }
    Ok((
        len,
        Some(WebSocketContext {
            sec_websocket_protocol_list,
            sec_websocket_key,
        }),
    ))
}

pub fn read_server_connect_handshake_response(
    sec_websocket_key: &WebSocketKey,
    offered_sub_protocols: Option<&[&str]>,
    from: &[u8],
) -> Result<(usize, Option<WebSocketSubProtocol>)> {
    let len = head::head_len(from, &mut 0).ok_or(Error::HttpHeaderIncomplete)?;
    let response = head::Head::parse(&from[..len])?;
    let (version, code, _) = response.start_line().ok_or(Error::HttpHeaderInvalid)?;
    if version != "HTTP/1.1" || code.len() != 3 {
        return Err(Error::HttpHeaderInvalid);
    }
    let code: u16 = code.parse().map_err(|_| Error::HttpHeaderInvalid)?;
    if code != 101 {
        return Err(Error::HttpResponseCodeInvalid(Some(code)));
    }
    // RFC 6455 section 4.1: the client must fail the connection without these
    if !response.has_token("upgrade", "websocket") || !response.has_token("connection", "upgrade") {
        return Err(Error::HttpHeaderInvalid);
    }

    let mut expected_accept_string = [0; 28];
    build_accept_string(sec_websocket_key, &mut expected_accept_string)?;
    if response.field("sec-websocket-accept") != Some(&expected_accept_string[..]) {
        return Err(Error::AcceptStringInvalid);
    }

    let sub_protocol = match response.field("sec-websocket-protocol") {
        Some(sub_protocol) => {
            let sub_protocol = str::from_utf8(sub_protocol)?;
            if !offered_sub_protocols
                .unwrap_or_default()
                .contains(&sub_protocol)
            {
                return Err(Error::SubProtocolNotOffered);
            }
            Some(String::try_from(sub_protocol)?)
        }
        None => None,
    };
    Ok((len, sub_protocol))
}

pub fn build_connect_handshake_request(
    websocket_options: &WebSocketOptions,
    rng: &mut impl Rng,
    to: &mut [u8],
) -> Result<(usize, WebSocketKey)> {
    let mut http_request: String<1024> = String::new();
    let mut key_as_base64: [u8; 24] = [0; 24];

    let mut key: [u8; 16] = [0; 16];
    rng.fill_bytes(&mut key);
    BASE64
        .encode_slice(key, &mut key_as_base64)
        .expect("24 bytes fit the base64 encoding of 16 bytes");
    let sec_websocket_key: String<24> = String::try_from(str::from_utf8(&key_as_base64)?)?;

    http_request.push_str("GET ")?;
    http_request.push_str(websocket_options.path)?;
    http_request.push_str(" HTTP/1.1\r\nHost: ")?;
    http_request.push_str(websocket_options.host)?;
    http_request
        .push_str("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ")?;
    http_request.push_str(sec_websocket_key.as_str())?;
    http_request.push_str("\r\nOrigin: ")?;
    http_request.push_str(websocket_options.origin)?;

    // turn sub protocol list into a CSV list
    if let Some(sub_protocols) = websocket_options.sub_protocols {
        http_request.push_str("\r\nSec-WebSocket-Protocol: ")?;
        for (i, sub_protocol) in sub_protocols.iter().enumerate() {
            http_request.push_str(sub_protocol)?;
            if i < (sub_protocols.len() - 1) {
                http_request.push_str(", ")?;
            }
        }
    }
    http_request.push_str("\r\n")?;

    if let Some(additional_headers) = websocket_options.additional_headers {
        for additional_header in additional_headers.iter() {
            http_request.push_str(additional_header)?;
            http_request.push_str("\r\n")?;
        }
    }

    http_request.push_str("Sec-WebSocket-Version: 13\r\n\r\n")?;
    to[..http_request.len()].copy_from_slice(http_request.as_bytes());
    Ok((http_request.len(), sec_websocket_key))
}

pub fn build_connect_handshake_response(
    sec_websocket_key: &WebSocketKey,
    sec_websocket_protocol: Option<&WebSocketSubProtocol>,
    to: &mut [u8],
) -> Result<usize> {
    let mut http_response: String<1024> = String::new();
    http_response.push_str(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Connection: Upgrade\r\nUpgrade: websocket\r\n",
    )?;

    // if the user has specified a sub protocol
    if let Some(sec_websocket_protocol) = sec_websocket_protocol {
        http_response.push_str("Sec-WebSocket-Protocol: ")?;
        http_response.push_str(sec_websocket_protocol)?;
        http_response.push_str("\r\n")?;
    }

    let mut output = [0; 28];
    http::build_accept_string(sec_websocket_key, &mut output)?;
    let accept_string = str::from_utf8(&output)?;
    http_response.push_str("Sec-WebSocket-Accept: ")?;
    http_response.push_str(accept_string)?;
    http_response.push_str("\r\n\r\n")?;

    // save the response to the buffer
    to[..http_response.len()].copy_from_slice(http_response.as_bytes());
    Ok(http_response.len())
}

pub fn build_accept_string(sec_websocket_key: &WebSocketKey, output: &mut [u8; 28]) -> Result<()> {
    // concatenate the key with a known websocket GUID (as per the spec)
    let mut accept_string: String<64> = String::new();
    accept_string.push_str(sec_websocket_key)?;
    accept_string.push_str("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")?;

    // calculate the base64 encoded sha1 hash of the accept string above
    let mut sha1 = Sha1::new();
    sha1.update(&accept_string);
    let input = sha1.finalize();
    BASE64
        .encode_slice(input, output)
        .expect("28 bytes fit the base64 encoding of a 20 byte SHA-1 hash");
    Ok(())
}

#[cfg(test)]
mod capacity_tests {
    extern crate std;

    use super::*;

    const UPGRADE: &str = "GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n";

    #[test]
    fn values_that_do_not_fit_are_refused_or_skipped_instead_of_panicking() {
        let long = "x".repeat(100);
        let request = std::format!("{UPGRADE}Sec-WebSocket-Key: {long}\r\n\r\n");
        assert!(matches!(
            read_http_header(request.as_bytes()),
            Ok((_, None))
        ));

        let request = std::format!(
            "{UPGRADE}Sec-WebSocket-Protocol: chat, {long}\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        );
        let (_, context) = read_http_header(request.as_bytes()).unwrap();
        let context = context.unwrap();
        assert_eq!(context.sec_websocket_protocol_list.len(), 1);
        assert_eq!(context.sec_websocket_protocol_list[0], "chat");
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn accept_string_matches_the_rfc_6455_example() {
        let key = WebSocketKey::try_from("dGhlIHNhbXBsZSBub25jZQ==").unwrap();
        let mut output = [0; 28];
        build_accept_string(&key, &mut output).unwrap();
        assert_eq!(&output, b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    fn key() -> WebSocketKey {
        WebSocketKey::try_from("Z7OY1UwHOx/nkSz38kfPwg==").unwrap()
    }

    #[test]
    fn response_without_accept_string_is_rejected() {
        let response = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        assert_eq!(
            read_server_connect_handshake_response(&key(), None, response),
            Err(Error::AcceptStringInvalid)
        );
    }

    #[test]
    fn response_without_upgrade_headers_is_rejected() {
        let accept = "Sec-WebSocket-Accept: ptPnPeDOTo6khJlzmLhOZSh2tAY=\r\n";
        for headers in ["Connection: Upgrade\r\n", "Upgrade: websocket\r\n"] {
            let response =
                std::format!("HTTP/1.1 101 Switching Protocols\r\n{headers}{accept}\r\n");
            assert_eq!(
                read_server_connect_handshake_response(&key(), None, response.as_bytes()),
                Err(Error::HttpHeaderInvalid)
            );
        }
    }

    #[test]
    fn sub_protocol_the_client_did_not_offer_is_rejected() {
        let response = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Protocol: chat\r\nSec-WebSocket-Accept: ptPnPeDOTo6khJlzmLhOZSh2tAY=\r\n\r\n";
        for offered in [None, Some(&["superchat"][..])] {
            assert_eq!(
                read_server_connect_handshake_response(&key(), offered, response),
                Err(Error::SubProtocolNotOffered)
            );
        }
        let (_, sub_protocol) =
            read_server_connect_handshake_response(&key(), Some(&["superchat", "chat"]), response)
                .unwrap();
        assert_eq!(sub_protocol.unwrap(), "chat");
    }
}
