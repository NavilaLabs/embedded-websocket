// Echo server for the fuzzingclient mode of the Autobahn testsuite.
// Run autobahn/run.sh instead of starting it by hand.

use std::net::{TcpListener, TcpStream};

use embedded_io_adapters::std::FromStd;
use embedded_io_websocket::{
    blocking::Framer, Decision, FramerError, FramerState, ReadResult, WebSocketSendMessageType,
    WebSocketServer,
};

// Autobahn sends messages of up to 16 MiB.
const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024 + 64;

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:9002")?;
    for stream in listener.incoming() {
        let stream = stream?;
        std::thread::spawn(move || {
            if let Err(error) = echo(stream) {
                eprintln!("connection failed: {error:?}");
            }
        });
    }
    Ok(())
}

fn echo(stream: TcpStream) -> Result<(), FramerError<std::io::Error>> {
    let mut stream = FromStd::new(stream);
    let mut read_buf = vec![0; 4096];
    // smaller than most echoed messages, so they are sent in several frames
    let mut write_buf = vec![0; 4096];
    let mut frame_buf = vec![0; MAX_MESSAGE_LEN];

    let mut state = FramerState::new();
    let mut websocket = WebSocketServer::new_server();
    let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut websocket);
    if !framer.accept(&mut stream, |_| Decision::Accept { sub_protocol: None })? {
        return Ok(());
    }

    loop {
        let (message_type, payload) = match framer.read(&mut stream, &mut frame_buf) {
            Ok(ReadResult::Text(text)) => (WebSocketSendMessageType::Text, text.as_bytes()),
            Ok(ReadResult::Binary(binary)) => (WebSocketSendMessageType::Binary, binary),
            Ok(ReadResult::Pong(_)) => continue,
            Ok(ReadResult::Closed { .. } | ReadResult::Disconnected) => return Ok(()),
            Err(error) => return Err(error),
        };
        framer.write(&mut stream, message_type, true, payload)?;
    }
}
