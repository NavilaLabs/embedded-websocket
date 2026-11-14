//! The sans-IO codec: both opening handshakes and frames on byte slices.
#![no_std]
#![no_main]

use core::hint::black_box;

use embedded_io_websocket::{
    Request, WebSocketClient, WebSocketCloseStatusCode, WebSocketOptions, WebSocketSendMessageType,
    WebSocketServer,
};
use size_probes::Random;

#[cortex_m_rt::entry]
fn main() -> ! {
    let (mut from, mut to) = ([0u8; 512], [0u8; 512]);
    loop {
        black_box(&mut from);
        let mut client = WebSocketClient::new_client(Random);
        let options = WebSocketOptions {
            path: black_box("/"),
            host: black_box("host"),
            origin: Some(black_box("origin")),
            sub_protocols: black_box(Some(&["chat"])),
            additional_headers: None,
        };
        if let Ok((_, key)) = client.client_connect(&options, &mut to) {
            let _ = black_box(client.client_accept(&key, options.sub_protocols, &from));
        }
        let _ = black_box(client.write(WebSocketSendMessageType::Text, true, &from[..10], &mut to));
        let _ = black_box(client.read(&from, &mut to));
        let _ = black_box(client.close(WebSocketCloseStatusCode::NormalClosure, None, &mut to));

        let mut server = WebSocketServer::new_server();
        if let Ok((request, _)) = Request::read(&from) {
            let _ = black_box(server.server_accept(&request, black_box(Some("chat")), &mut to));
        }
        let _ = black_box(server.read(&from, &mut to));
        let _ =
            black_box(server.write(WebSocketSendMessageType::Binary, true, &from[..10], &mut to));
    }
}
