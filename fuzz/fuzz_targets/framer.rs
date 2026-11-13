//! A server framer accepts and reads arbitrary bytes without panicking, and only answers an
//! upgrade it accepted with `101 Switching Protocols`.
#![no_main]

use embedded_io_websocket::{
    blocking::Framer, Decision, FramerState, ReadChunk, ReadResult, WebSocketServer,
};
use libfuzzer_sys::fuzz_target;

struct Stream<'a> {
    unread: &'a [u8],
    read_len: usize,
    written: Vec<u8>,
}

impl embedded_io::ErrorType for Stream<'_> {
    type Error = embedded_io::ErrorKind;
}

impl embedded_io::Read for Stream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let len = buf.len().min(self.unread.len()).min(self.read_len);
        buf[..len].copy_from_slice(&self.unread[..len]);
        self.unread = &self.unread[len..];
        Ok(len)
    }
}

impl embedded_io::Write for Stream<'_> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

fuzz_target!(|input: (u8, bool, &[u8])| {
    let (read_len, chunked, bytes) = input;
    let mut stream = Stream {
        unread: bytes,
        read_len: read_len as usize + 1,
        written: Vec::new(),
    };
    let (mut read_buf, mut write_buf, mut frame_buf) = ([0; 512], [0; 256], [0; 200]);
    let mut state = FramerState::new();
    let mut websocket = WebSocketServer::new_server();
    let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut websocket);

    let accepted = framer.accept(&mut stream, |request| Decision::Accept {
        sub_protocol: request.offers("chat").then_some("chat"),
    });
    let is_open = matches!(accepted, Ok(true));
    assert_eq!(
        is_open,
        stream.written.starts_with(b"HTTP/1.1 101 "),
        "{accepted:?}"
    );
    if !is_open {
        return;
    }
    loop {
        let done = if chunked {
            matches!(
                framer.read_chunk(&mut stream, &mut frame_buf),
                Err(_) | Ok(ReadChunk::Closed { .. } | ReadChunk::Disconnected)
            )
        } else {
            matches!(
                framer.read(&mut stream, &mut frame_buf),
                Err(_) | Ok(ReadResult::Closed { .. } | ReadResult::Disconnected)
            )
        };
        if done {
            break;
        }
    }
});
