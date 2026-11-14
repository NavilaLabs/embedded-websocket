use super::*;
use crate::{head, url};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use heapless::String;

// Writes text into the start of a buffer.
struct Output<'a> {
    to: &'a mut [u8],
    len: usize,
}

impl<'a> Output<'a> {
    fn new(to: &'a mut [u8]) -> Self {
        Self { to, len: 0 }
    }

    fn push(&mut self, text: &str) -> Result<()> {
        let end = self.len + text.len();
        self.to
            .get_mut(self.len..end)
            .ok_or(Error::WriteToBufferTooSmall)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

pub(crate) fn read_server_connect_handshake_response<'o>(
    sec_websocket_key: &WebSocketKey,
    offered_sub_protocols: Option<&[&'o str]>,
    from: &[u8],
) -> Result<(usize, Option<&'o str>)> {
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
    if response.tokens("sec-websocket-extensions").next().is_some() {
        return Err(Error::ExtensionNotOffered);
    }

    let sub_protocol = match response.field("sec-websocket-protocol") {
        Some(sub_protocol) => {
            let sub_protocol = str::from_utf8(sub_protocol)?;
            let offered = offered_sub_protocols
                .unwrap_or_default()
                .iter()
                .find(|offered| **offered == sub_protocol)
                .ok_or(Error::SubProtocolNotOffered)?;
            Some(*offered)
        }
        None => None,
    };
    Ok((len, sub_protocol))
}

pub(crate) fn build_connect_handshake_request(
    websocket_options: &WebSocketOptions,
    rng: &mut impl Rng,
    to: &mut [u8],
) -> Result<(usize, WebSocketKey)> {
    if !can_be_sent(websocket_options) {
        return Err(Error::HttpHeaderInvalid);
    }
    let mut http_request = Output::new(to);
    let mut key_as_base64: [u8; 24] = [0; 24];

    let mut key: [u8; 16] = [0; 16];
    rng.fill_bytes(&mut key);
    BASE64
        .encode_slice(key, &mut key_as_base64)
        .expect("24 bytes fit the base64 encoding of 16 bytes");
    let sec_websocket_key: String<24> = String::try_from(str::from_utf8(&key_as_base64)?)?;

    http_request.push("GET ")?;
    // RFC 6455 section 3: an empty path is sent as "/", also before a query
    if !websocket_options.path.starts_with('/') {
        http_request.push("/")?;
    }
    http_request.push(websocket_options.path)?;
    http_request.push(" HTTP/1.1\r\nHost: ")?;
    http_request.push(websocket_options.host)?;
    http_request.push("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ")?;
    http_request.push(sec_websocket_key.as_str())?;
    if let Some(origin) = websocket_options.origin {
        http_request.push("\r\nOrigin: ")?;
        http_request.push(origin)?;
    }

    if let Some(sub_protocols) = websocket_options
        .sub_protocols
        .filter(|sub_protocols| !sub_protocols.is_empty())
    {
        if !are_unique_tokens(sub_protocols) {
            return Err(Error::InvalidSubProtocol);
        }
        http_request.push("\r\nSec-WebSocket-Protocol: ")?;
        for (index, sub_protocol) in sub_protocols.iter().enumerate() {
            if index > 0 {
                http_request.push(", ")?;
            }
            http_request.push(sub_protocol)?;
        }
    }
    http_request.push("\r\n")?;

    if let Some(additional_headers) = websocket_options.additional_headers {
        for additional_header in additional_headers.iter() {
            http_request.push(additional_header)?;
            http_request.push("\r\n")?;
        }
    }

    http_request.push("Sec-WebSocket-Version: 13\r\n\r\n")?;
    Ok((http_request.len, sec_websocket_key))
}

// Each option must stay within its part of the request head, so none can end a line and add
// header fields of its own: the path is an origin-form request target (RFC 9112 section 3.2.1),
// which also leaves out the fragment that RFC 6455 section 3 forbids, and field values and lines
// follow RFC 9110 section 5.
fn can_be_sent(websocket_options: &WebSocketOptions) -> bool {
    let path = websocket_options.path;
    path.bytes().all(url::is_resource_byte)
        && url::is_percent_encoding_valid(path)
        && head::is_valid_field_value(websocket_options.host.as_bytes())
        && websocket_options
            .origin
            .is_none_or(|origin| head::is_valid_field_value(origin.as_bytes()))
        && websocket_options
            .additional_headers
            .unwrap_or_default()
            .iter()
            .all(|header| head::is_valid_field(header.as_bytes()))
}

// RFC 6455 section 4.1, item 10
fn are_unique_tokens(sub_protocols: &[&str]) -> bool {
    sub_protocols
        .iter()
        .enumerate()
        .all(|(index, sub_protocol)| {
            !sub_protocol.is_empty()
                && sub_protocol.bytes().all(head::is_token_byte)
                && !sub_protocols[..index].contains(sub_protocol)
        })
}

pub(crate) fn build_connect_handshake_response(
    sec_websocket_key: &WebSocketKey,
    sec_websocket_protocol: Option<&str>,
    to: &mut [u8],
) -> Result<usize> {
    let mut http_response = Output::new(to);
    http_response.push(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Connection: Upgrade\r\nUpgrade: websocket\r\n",
    )?;

    // if the user has specified a sub protocol
    if let Some(sec_websocket_protocol) = sec_websocket_protocol {
        http_response.push("Sec-WebSocket-Protocol: ")?;
        http_response.push(sec_websocket_protocol)?;
        http_response.push("\r\n")?;
    }

    let mut output = [0; 28];
    http::build_accept_string(sec_websocket_key, &mut output)?;
    let accept_string = str::from_utf8(&output)?;
    http_response.push("Sec-WebSocket-Accept: ")?;
    http_response.push(accept_string)?;
    http_response.push("\r\n\r\n")?;
    Ok(http_response.len)
}

pub(crate) fn build_accept_string(
    sec_websocket_key: &WebSocketKey,
    output: &mut [u8; 28],
) -> Result<()> {
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

    // RFC 6455 section 4.1: the client offers no extension, so the server must not use one
    #[test]
    fn response_with_an_extension_is_rejected() {
        let response =
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
            Sec-WebSocket-Extensions: permessage-deflate\r\n\
            Sec-WebSocket-Accept: ptPnPeDOTo6khJlzmLhOZSh2tAY=\r\n\r\n";
        assert_eq!(
            read_server_connect_handshake_response(&key(), None, response),
            Err(Error::ExtensionNotOffered)
        );
    }

    #[test]
    fn handshakes_that_do_not_fit_the_output_fail_instead_of_panicking() {
        let options = WebSocketOptions {
            path: "/chat",
            host: "localhost",
            origin: Some("http://localhost"),
            sub_protocols: None,
            additional_headers: None,
        };
        let mut to = [0; 1024];
        let (len, _) =
            build_connect_handshake_request(&options, &mut rand::rng(), &mut to).unwrap();
        assert_eq!(
            build_connect_handshake_request(&options, &mut rand::rng(), &mut to[..len - 1]).err(),
            Some(Error::WriteToBufferTooSmall)
        );

        let len = build_connect_handshake_response(&key(), None, &mut to).unwrap();
        assert_eq!(
            build_connect_handshake_response(&key(), None, &mut to[..len - 1]).err(),
            Some(Error::WriteToBufferTooSmall)
        );
    }

    fn request_with_sub_protocols(sub_protocols: &[&str]) -> Result<std::string::String> {
        let options = WebSocketOptions {
            path: "/",
            host: "localhost",
            origin: None,
            sub_protocols: Some(sub_protocols),
            additional_headers: None,
        };
        let mut to = [0; 1024];
        let (len, _) = build_connect_handshake_request(&options, &mut rand::rng(), &mut to)?;
        Ok(std::string::String::from_utf8(to[..len].to_vec()).unwrap())
    }

    fn request_with_path(path: &str) -> Result<usize> {
        let options = WebSocketOptions {
            path,
            host: "localhost",
            origin: None,
            sub_protocols: None,
            additional_headers: None,
        };
        let mut to = [0; 1024];
        build_connect_handshake_request(&options, &mut rand::rng(), &mut to).map(|(len, _)| len)
    }

    // RFC 9112 section 3.2.1 and RFC 6455 section 3, which forbids fragments
    #[test]
    fn path_must_be_an_origin_form_target() {
        for path in ["/", "", "?a=1", "/a/b%20c?x=/:@!$&'()*+,;=-._~"] {
            assert!(request_with_path(path).is_ok(), "{path}");
        }
        for path in [
            "/a#b", "/a#", "/a{b}", "/a|b", "/a\"b", "/%zz", "/%4", "/a\\b", "/ä",
        ] {
            assert_eq!(
                request_with_path(path),
                Err(Error::HttpHeaderInvalid),
                "{path}"
            );
        }
    }

    #[test]
    fn request_fields_that_would_break_the_head_are_rejected() {
        let valid = WebSocketOptions {
            path: "/chat?room=1",
            host: "localhost:8080",
            origin: Some("http://localhost"),
            sub_protocols: None,
            additional_headers: Some(&["Authorization: Bearer a.b", "X-Empty:"]),
        };
        let mut to = [0; 1024];
        assert!(build_connect_handshake_request(&valid, &mut rand::rng(), &mut to).is_ok());

        let injected = "a\r\nX-Injected: 1";
        let invalid = [
            WebSocketOptions {
                path: injected,
                ..valid
            },
            WebSocketOptions {
                path: "/a b",
                ..valid
            },
            WebSocketOptions {
                path: "/a\tb",
                ..valid
            },
            WebSocketOptions {
                host: injected,
                ..valid
            },
            WebSocketOptions {
                host: "a\nb",
                ..valid
            },
            WebSocketOptions {
                host: "a\0b",
                ..valid
            },
            WebSocketOptions {
                origin: Some(injected),
                ..valid
            },
            WebSocketOptions {
                additional_headers: Some(&[injected]),
                ..valid
            },
            WebSocketOptions {
                additional_headers: Some(&["no colon"]),
                ..valid
            },
            WebSocketOptions {
                additional_headers: Some(&["Bad Name: 1"]),
                ..valid
            },
            WebSocketOptions {
                additional_headers: Some(&[""]),
                ..valid
            },
        ];
        for options in invalid {
            assert_eq!(
                build_connect_handshake_request(&options, &mut rand::rng(), &mut to).err(),
                Some(Error::HttpHeaderInvalid),
                "{:?} {:?} {:?} {:?}",
                options.path,
                options.host,
                options.origin,
                options.additional_headers
            );
        }
    }

    #[test]
    fn empty_sub_protocol_list_sends_no_header() {
        let request = request_with_sub_protocols(&[]).unwrap();
        assert!(!request.contains("Sec-WebSocket-Protocol"), "{request}");
    }

    #[test]
    fn sub_protocols_that_are_not_unique_tokens_are_rejected() {
        for sub_protocols in [
            &[""][..],
            &["chat", ""],
            &["a b"],
            &["a,b"],
            &["chat\r\nX: y"],
            &["chät"],
            &["chat", "chat"],
        ] {
            assert_eq!(
                request_with_sub_protocols(sub_protocols),
                Err(Error::InvalidSubProtocol),
                "{sub_protocols:?}"
            );
        }
        assert!(request_with_sub_protocols(&["chat", "Chat", "v1.json~"])
            .unwrap()
            .contains("\r\nSec-WebSocket-Protocol: chat, Chat, v1.json~\r\n"));
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
