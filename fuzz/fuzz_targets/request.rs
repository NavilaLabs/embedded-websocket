//! A request the server accepts as an upgrade carries a key that is 16 base64 encoded bytes.
#![no_main]

use base64::Engine;
use embedded_io_websocket::fuzzing::{parse_request, upgrade_key};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|head: &[u8]| {
    let Ok(request) = parse_request(head) else {
        return;
    };
    assert!(!request.path().is_empty());
    let _ = request.header("sec-websocket-protocol");
    let _ = request.offers("chat");
    if let Ok(key) = upgrade_key(&request) {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(key.as_bytes())
            .expect("the key is base64");
        assert_eq!(decoded.len(), 16);
    }
});
