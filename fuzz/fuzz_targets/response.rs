//! The client accepts only a response that ends within the input and picks an offered protocol.
#![no_main]

use embedded_io_websocket::{EmptyRng, WebSocketClient, WebSocketKey};
use libfuzzer_sys::fuzz_target;

const OFFERED: &[&str] = &["chat", "superchat"];

fuzz_target!(|response: &[u8]| {
    let key = WebSocketKey::try_from("dGhlIHNhbXBsZSBub25jZQ==").unwrap();
    let mut ws_client = WebSocketClient::new_client(EmptyRng::new());
    if let Ok((len, protocol)) = ws_client.client_accept(&key, Some(OFFERED), response) {
        assert!(len <= response.len());
        assert!(response[..len].ends_with(b"\r\n\r\n"));
        if let Some(protocol) = protocol {
            assert!(OFFERED.contains(&protocol.as_str()));
        }
    }
});
