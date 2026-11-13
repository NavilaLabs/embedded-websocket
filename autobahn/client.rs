// Echo client for the fuzzingserver mode of the Autobahn testsuite.
// Run autobahn/run.sh instead of starting it by hand.

use std::net::TcpStream;

use embedded_io_adapters::std::FromStd;
use embedded_io_websocket::{
    blocking::Framer, FramerError, FramerState, ReadResult, WebSocketClient, WebSocketOptions,
    WebSocketSendMessageType,
};

const ADDRESS: &str = "127.0.0.1:9001";
const AGENT: &str = "embedded-io-websocket";
// Autobahn sends messages of up to 16 MiB.
const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024 + 64;

type Result<T> = std::result::Result<T, FramerError<std::io::Error>>;

fn main() -> Result<()> {
    let mut buffers = Buffers::new();
    let case_count: u32 = buffers
        .request_text("/getCaseCount")?
        .parse()
        .expect("case count is a number");
    for case in 1..=case_count {
        if let Err(error) = buffers.echo(&format!("/runCase?case={case}&agent={AGENT}")) {
            eprintln!("case {case} failed: {error:?}");
        }
    }
    buffers.request_text(&format!("/updateReports?agent={AGENT}"))?;
    Ok(())
}

struct Buffers {
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
    frame_buf: Vec<u8>,
}

impl Buffers {
    fn new() -> Self {
        Self {
            read_buf: vec![0; 4096],
            write_buf: vec![0; MAX_MESSAGE_LEN],
            frame_buf: vec![0; MAX_MESSAGE_LEN],
        }
    }

    fn request_text(&mut self, path: &str) -> Result<String> {
        let mut text = String::new();
        self.run(path, |message_type, payload| {
            if message_type == WebSocketSendMessageType::Text {
                text = String::from_utf8_lossy(payload).into_owned();
            }
            false
        })?;
        Ok(text)
    }

    fn echo(&mut self, path: &str) -> Result<()> {
        self.run(path, |_, _| true)
    }

    fn run(
        &mut self,
        path: &str,
        mut on_message: impl FnMut(WebSocketSendMessageType, &[u8]) -> bool,
    ) -> Result<()> {
        let mut stream = FromStd::new(TcpStream::connect(ADDRESS).map_err(FramerError::Io)?);
        let mut state = FramerState::new();
        let mut websocket = WebSocketClient::new_client(rand::rng());
        let mut framer = Framer::new(
            &mut self.read_buf,
            &mut state,
            &mut self.write_buf,
            &mut websocket,
        );
        let websocket_options = WebSocketOptions {
            path,
            host: ADDRESS,
            origin: "http://127.0.0.1",
            sub_protocols: None,
            additional_headers: None,
        };
        framer.connect(&mut stream, &websocket_options)?;

        loop {
            let (message_type, payload) = match framer.read(&mut stream, &mut self.frame_buf) {
                Ok(ReadResult::Text(text)) => (WebSocketSendMessageType::Text, text.as_bytes()),
                Ok(ReadResult::Binary(binary)) => (WebSocketSendMessageType::Binary, binary),
                Ok(ReadResult::Pong(_)) => continue,
                Ok(ReadResult::Closed) => return Ok(()),
                Err(error) => return Err(error),
            };
            if on_message(message_type, payload) {
                framer.write(&mut stream, message_type, true, payload)?;
            }
        }
    }
}
