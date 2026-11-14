//! Opening handshakes configured from a `ws://`, `wss://`, `http://` or `https://` URL.

use embedded_io_websocket::{Error, WebSocketClient, WebSocketUrl};

#[test]
fn url_parts_are_split_and_default_ports_filled_in() {
    for (url, is_secure, host, port, path, host_header) in [
        (
            "ws://example.com",
            false,
            "example.com",
            80,
            "/",
            "example.com",
        ),
        (
            "wss://example.com/",
            true,
            "example.com",
            443,
            "/",
            "example.com",
        ),
        (
            "WSS://Example.COM:8443/chat?room=1",
            true,
            "Example.COM",
            8443,
            "/chat?room=1",
            "Example.COM:8443",
        ),
        (
            "ws://example.com?x=1",
            false,
            "example.com",
            80,
            "/?x=1",
            "example.com",
        ),
        (
            "ws://192.168.1.10:8080/a/b",
            false,
            "192.168.1.10",
            8080,
            "/a/b",
            "192.168.1.10:8080",
        ),
        ("ws://[::1]:9001/", false, "::1", 9001, "/", "[::1]:9001"),
        (
            "wss://[2001:db8::7]/x%20y",
            true,
            "2001:db8::7",
            443,
            "/x%20y",
            "[2001:db8::7]",
        ),
        (
            "ws://example.com:443/",
            false,
            "example.com",
            443,
            "/",
            "example.com:443",
        ),
        // the WHATWG WebSockets standard reads http as ws and https as wss
        (
            "http://example.com/chat",
            false,
            "example.com",
            80,
            "/chat",
            "example.com",
        ),
        (
            "HTTPS://example.com:8443",
            true,
            "example.com",
            8443,
            "/",
            "example.com:8443",
        ),
    ] {
        let parsed = WebSocketUrl::parse(url).unwrap_or_else(|error| panic!("{url}: {error:?}"));
        assert_eq!(parsed.is_secure(), is_secure, "{url}");
        assert_eq!(parsed.host(), host, "{url}");
        assert_eq!(parsed.port(), port, "{url}");

        let mut to = [0; 512];
        let (len, _) = WebSocketClient::new_client(rand::rng())
            .client_connect(&parsed.options(), &mut to)
            .unwrap();
        let request = std::str::from_utf8(&to[..len]).unwrap();
        assert!(
            request.starts_with(&format!("GET {path} HTTP/1.1\r\n")),
            "{request}"
        );
        assert!(
            request.contains(&format!("\r\nHost: {host_header}\r\n")),
            "{request}"
        );
        assert!(!request.contains("\r\nOrigin:"), "{request}");
    }
}

#[test]
fn urls_a_websocket_cannot_use_are_rejected() {
    for url in [
        "",
        "example.com",
        "ftp://example.com/",
        "https://example.com/#fragment",
        "ws:/example.com",
        "ws://",
        "ws:///path",
        "ws://example.com/#fragment",
        "ws://user:secret@example.com/",
        "ws://user@example.com/",
        "ws://example.com:/",
        "ws://example.com:0/",
        "ws://example.com:65536/",
        "ws://example.com:80a/",
        "ws://exa mple.com/",
        "ws://example.com/a b",
        "ws://example.com/\u{e4}",
        "ws://example.com/a\\b",
        "ws://example.com/%zz",
        "ws://example.com/<script>",
        "ws://[::1/",
        "ws://[not-an-address]/",
        "ws://[fe80::1%25eth0]/",
        "ws://::1/",
        "ws://example.com\r\nX-Injected: 1/",
        "ws://1.2.3/",
        "ws://0x7f.1/",
        "ws://127.000.0.1/",
        "ws://256.0.0.1/",
        "ws://example.123/",
        "ws://example.0x1/",
    ] {
        assert_eq!(
            WebSocketUrl::parse(url).err(),
            Some(Error::InvalidUrl),
            "{url:?}"
        );
    }
}

#[test]
fn origin_is_sent_only_when_set() {
    let url = WebSocketUrl::parse("ws://example.com/").unwrap();
    let mut options = url.options();
    options.origin = Some("https://app.example.com");
    let mut to = [0; 512];
    let (len, _) = WebSocketClient::new_client(rand::rng())
        .client_connect(&options, &mut to)
        .unwrap();
    let request = std::str::from_utf8(&to[..len]).unwrap();
    assert!(
        request.contains("\r\nOrigin: https://app.example.com\r\n"),
        "{request}"
    );
}
