// Echo server for the fuzzingclient mode of the Autobahn testsuite.
// Run autobahn/run.sh instead of starting it by hand.

use std::net::{TcpListener, TcpStream};

use embedded_io::Read;
use embedded_io_adapters::std::FromStd;
use embedded_io_websocket::{
    blocking::Framer, FramerError, FramerState, ReadResult, WebSocketSendMessageType,
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
    let mut write_buf = vec![0; MAX_MESSAGE_LEN];
    let mut frame_buf = vec![0; MAX_MESSAGE_LEN];

    let mut read_len = 0;
    let (websocket_context, header_len) = loop {
        let received = stream
            .read(&mut read_buf[read_len..])
            .map_err(FramerError::Io)?;
        if received == 0 {
            return Ok(());
        }
        read_len += received;
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut request = httparse::Request::new(&mut headers);
        if let httparse::Status::Complete(len) = request
            .parse(&read_buf[..read_len])
            .map_err(|error| FramerError::WebSocket(error.into()))?
        {
            let headers = request
                .headers
                .iter()
                .map(|header| (header.name, header.value));
            match embedded_io_websocket::read_http_header(headers)
                .map_err(FramerError::WebSocket)?
            {
                Some(websocket_context) => break (websocket_context, len),
                None => return Ok(()),
            }
        }
    };
    read_buf.copy_within(header_len..read_len, 0);

    let mut state = FramerState::with_buffered(read_len - header_len);
    let mut websocket = WebSocketServer::new_server();
    let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut websocket);
    framer.accept(&mut stream, &websocket_context, None)?;

    loop {
        let (message_type, payload) = match framer.read(&mut stream, &mut frame_buf) {
            Ok(ReadResult::Text(text)) => (WebSocketSendMessageType::Text, text.as_bytes()),
            Ok(ReadResult::Binary(binary)) => (WebSocketSendMessageType::Binary, binary),
            Ok(ReadResult::Pong(_)) => continue,
            Ok(ReadResult::Closed) => return Ok(()),
            Err(error) => return Err(error),
        };
        framer.write(&mut stream, message_type, true, payload)?;
    }
}
