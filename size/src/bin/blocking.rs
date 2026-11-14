//! The blocking framer as client and server, with every read and write operation.
#![no_std]
#![no_main]

use core::hint::black_box;

use embedded_io_websocket::{
    blocking::Framer, Decision, EmptyRng, FramerState, WebSocketClient, WebSocketCloseStatusCode,
    WebSocketOptions, WebSocketSendMessageType, WebSocketServer,
};
use size_probes::Stream;

#[cortex_m_rt::entry]
fn main() -> ! {
    let (mut read_buf, mut write_buf, mut frame_buf) = ([0u8; 512], [0u8; 512], [0u8; 512]);
    let mut stream = Stream;
    loop {
        let mut state = FramerState::new();
        let mut client = WebSocketClient::new_client(EmptyRng::new());
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut client);
        let options = WebSocketOptions {
            path: black_box("/"),
            host: black_box("host"),
            origin: black_box("origin"),
            sub_protocols: None,
            additional_headers: None,
        };
        let _ = black_box(framer.connect(&mut stream, &options));
        let _ = black_box(framer.write(&mut stream, WebSocketSendMessageType::Text, true, b"hi"));
        let _ = black_box(framer.read(&mut stream, &mut frame_buf).is_ok());
        let _ = black_box(framer.read_chunk(&mut stream, &mut frame_buf).is_ok());
        let _ = black_box(framer.ping(&mut stream));
        let _ = black_box(framer.close(&mut stream, WebSocketCloseStatusCode::NormalClosure, None));

        let mut state = FramerState::new();
        let mut server = WebSocketServer::new_server();
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut server);
        let _ = black_box(framer.accept(&mut stream, |_| Decision::Accept { sub_protocol: None }));
        let _ = black_box(framer.read(&mut stream, &mut frame_buf).is_ok());
    }
}
