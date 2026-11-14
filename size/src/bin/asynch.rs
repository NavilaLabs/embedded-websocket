//! The async framer as client and server, and a server split into reader and writer.
#![no_std]
#![no_main]

use core::hint::black_box;

use embedded_io_websocket::{
    asynch::{Framer, LocalMutex, Reader, Shared, Writer},
    Decision, EmptyRng, FramerState, WebSocketClient, WebSocketCloseStatusCode, WebSocketOptions,
    WebSocketSendMessageType, WebSocketServer,
};
use size_probes::{poll_once, Stream};

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
        let _ = black_box(poll_once(framer.connect(&mut stream, &options)).is_ready());
        let write = framer.write(&mut stream, WebSocketSendMessageType::Text, true, b"hi");
        let _ = black_box(poll_once(write).is_ready());
        let _ = black_box(poll_once(framer.read(&mut stream, &mut frame_buf)).is_ready());
        let _ = black_box(poll_once(framer.read_chunk(&mut stream, &mut frame_buf)).is_ready());
        let _ = black_box(poll_once(framer.ping(&mut stream)).is_ready());
        let close = framer.close(&mut stream, WebSocketCloseStatusCode::NormalClosure, None);
        let _ = black_box(poll_once(close).is_ready());

        let mut state = FramerState::new();
        let mut server = WebSocketServer::new_server();
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut server);
        let accept = framer.accept(&mut stream, |_| Decision::Accept { sub_protocol: None });
        let _ = black_box(poll_once(accept).is_ready());

        let shared = LocalMutex::new(Shared::new(Stream, &mut state, &mut write_buf, &mut server));
        let mut reader = Reader::new(&mut read_buf, Stream, &shared);
        let mut writer = Writer::new(&shared);
        let _ = black_box(poll_once(reader.read(&mut frame_buf)).is_ready());
        let write = writer.write(WebSocketSendMessageType::Binary, true, b"hi");
        let _ = black_box(poll_once(write).is_ready());
    }
}
