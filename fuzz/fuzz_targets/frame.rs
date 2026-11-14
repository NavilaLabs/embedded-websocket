//! The frame decoder never panics, and a whole unmasked frame encodes back to the same bytes.
#![no_main]

use embedded_io_websocket::{
    WebSocketClient, WebSocketReceiveMessageType, WebSocketSendMessageType, WebSocketServer,
    WebSocketState,
};
use libfuzzer_sys::fuzz_target;
use zero_rng::ZeroRng;

mod zero_rng;

fn send_type(message_type: WebSocketReceiveMessageType) -> WebSocketSendMessageType {
    match message_type {
        WebSocketReceiveMessageType::Text => WebSocketSendMessageType::Text,
        WebSocketReceiveMessageType::Binary => WebSocketSendMessageType::Binary,
        WebSocketReceiveMessageType::CloseMustReply
        | WebSocketReceiveMessageType::CloseCompleted => WebSocketSendMessageType::CloseReply,
        WebSocketReceiveMessageType::Ping => WebSocketSendMessageType::Ping,
        WebSocketReceiveMessageType::Pong => WebSocketSendMessageType::Pong,
    }
}

fuzz_target!(|input: (u8, &[u8])| {
    let (to_len, frames) = input;
    let mut to = vec![0; to_len as usize];

    let mut ws_server = WebSocketServer::new_server();
    ws_server.state = WebSocketState::Open;
    let mut from = frames;
    while let Ok(result) = ws_server.read(from, &mut to) {
        if result.len_from == 0 {
            break;
        }
        from = &from[result.len_from..];
    }

    let mut ws_client = WebSocketClient::new_client(ZeroRng);
    ws_client.state = WebSocketState::Open;
    let mut payload = vec![0; frames.len()];
    if let Ok(result) = ws_client.read(frames, &mut payload) {
        let is_whole_frame = result.end_of_message && frames[0] & 0x0F != 0;
        if is_whole_frame && result.message_type != WebSocketReceiveMessageType::CloseCompleted {
            let mut encoded = vec![0; frames.len() + 14];
            let mut encoder = WebSocketServer::new_server();
            encoder.state = WebSocketState::Open;
            let len = encoder
                .write(
                    send_type(result.message_type),
                    true,
                    &payload[..result.len_to],
                    &mut encoded,
                )
                .unwrap();
            assert_eq!(&encoded[..len], &frames[..result.len_from]);
        }
    }
});
