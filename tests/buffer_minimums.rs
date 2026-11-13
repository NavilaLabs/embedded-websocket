//! Checks that the minimum buffer lengths are exact: the largest frames and handshake responses
//! the framer handles by itself fit buffers of the minimum length and fail with one byte less.

use std::collections::VecDeque;

use embedded_io_websocket::{
    blocking::Framer, Decision, FramerError, FramerState, ReadResult, WebSocketClient,
    WebSocketReceiveMessageType, WebSocketSendMessageType, WebSocketServer, WebSocketState,
    MIN_FRAME_BUF_LEN, MIN_READ_BUF_LEN, MIN_WRITE_BUF_LEN,
};

const MAX_CONTROL_PAYLOAD: [u8; 125] = [b'p'; 125];

struct MemoryStream {
    unread: VecDeque<u8>,
    written: Vec<u8>,
}

impl MemoryStream {
    fn new(unread: Vec<u8>) -> Self {
        Self {
            unread: unread.into(),
            written: Vec::new(),
        }
    }
}

impl embedded_io::ErrorType for MemoryStream {
    type Error = core::convert::Infallible;
}

impl embedded_io::Read for MemoryStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let len = buf.len().min(self.unread.len());
        for (to, from) in buf.iter_mut().zip(self.unread.drain(..len)) {
            *to = from;
        }
        Ok(len)
    }
}

impl embedded_io::Write for MemoryStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn client_frame(message_type: WebSocketSendMessageType, payload: &[u8]) -> Vec<u8> {
    let mut ws_client = WebSocketClient::new_client(rand::rng());
    ws_client.state = WebSocketState::Open;
    let mut frame = vec![0; 256];
    let len = ws_client
        .write(message_type, true, payload, &mut frame)
        .unwrap();
    frame.truncate(len);
    frame
}

/// A server reads the largest ping a client can send and then a text message.
fn server_reads_largest_ping(
    read_buf_len: usize,
    frame_buf_len: usize,
) -> Result<(String, Vec<u8>), FramerError<core::convert::Infallible>> {
    let mut received = client_frame(WebSocketSendMessageType::Ping, &MAX_CONTROL_PAYLOAD);
    received.extend(client_frame(WebSocketSendMessageType::Text, b"after"));
    let mut stream = MemoryStream::new(received);
    let mut read_buf = vec![0; read_buf_len];
    let mut write_buf = vec![0; MIN_WRITE_BUF_LEN];
    let mut frame_buf = vec![0; frame_buf_len];
    let mut state = FramerState::new();
    let mut ws_server = WebSocketServer::new_server();
    ws_server.state = WebSocketState::Open;
    let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
    let text = match framer.read(&mut stream, &mut frame_buf)? {
        ReadResult::Text(text) => text.to_owned(),
        _ => panic!("expected the text message"),
    };
    Ok((text, stream.written))
}

#[test]
fn the_largest_control_frame_has_the_minimum_read_buffer_length() {
    let ping = client_frame(WebSocketSendMessageType::Ping, &MAX_CONTROL_PAYLOAD);
    assert_eq!(ping.len(), MIN_READ_BUF_LEN);
}

#[test]
fn minimum_buffers_handle_the_largest_ping() {
    let (text, written) = server_reads_largest_ping(MIN_READ_BUF_LEN, MIN_FRAME_BUF_LEN).unwrap();
    assert_eq!(text, "after");

    let mut ws_client = WebSocketClient::new_client(rand::rng());
    ws_client.state = WebSocketState::Open;
    let mut pong = [0; 125];
    let result = ws_client.read(&written, &mut pong).unwrap();
    assert_eq!(result.message_type, WebSocketReceiveMessageType::Pong);
    assert_eq!(result.len_from, written.len());
    assert_eq!(pong, MAX_CONTROL_PAYLOAD);
}

#[test]
fn a_read_buffer_one_byte_short_fails_on_the_largest_ping() {
    assert!(matches!(
        server_reads_largest_ping(MIN_READ_BUF_LEN - 1, MIN_FRAME_BUF_LEN),
        Err(FramerError::FrameTooLarge(_))
    ));
}

#[test]
fn a_frame_buffer_one_byte_short_fails_on_the_largest_ping() {
    assert!(matches!(
        server_reads_largest_ping(MIN_READ_BUF_LEN, MIN_FRAME_BUF_LEN - 1),
        Err(FramerError::FrameTooLarge(_))
    ));
}

#[test]
fn minimum_buffers_answer_the_largest_ping_as_a_client() {
    let mut ws_server = WebSocketServer::new_server();
    ws_server.state = WebSocketState::Open;
    let mut ping = vec![0; 256];
    let len = ws_server
        .write(
            WebSocketSendMessageType::Ping,
            true,
            &MAX_CONTROL_PAYLOAD,
            &mut ping,
        )
        .unwrap();
    ping.truncate(len);

    let mut stream = MemoryStream::new(ping);
    let mut read_buf = vec![0; MIN_READ_BUF_LEN];
    let mut write_buf = vec![0; MIN_WRITE_BUF_LEN];
    let mut frame_buf = vec![0; MIN_FRAME_BUF_LEN];
    let mut state = FramerState::new();
    let mut ws_client = WebSocketClient::new_client(rand::rng());
    ws_client.state = WebSocketState::Open;
    let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_client);
    assert!(matches!(
        framer.read(&mut stream, &mut frame_buf).unwrap(),
        ReadResult::Disconnected
    ));
    // a masked pong with the largest payload
    assert_eq!(stream.written.len(), MIN_READ_BUF_LEN);
}

/// A server accepts a request that offers a sub protocol of the largest length and chooses it.
fn accept_largest_sub_protocol(
    write_buf_len: usize,
) -> Result<Vec<u8>, FramerError<core::convert::Infallible>> {
    let sub_protocol = "s".repeat(24);
    let request = format!(
        "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: {sub_protocol}\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    let mut stream = MemoryStream::new(request.into_bytes());
    let mut read_buf = vec![0; 1024];
    let mut write_buf = vec![0; write_buf_len];
    let mut state = FramerState::new();
    let mut ws_server = WebSocketServer::new_server();
    let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
    let is_open = framer.accept(&mut stream, |_| Decision::Accept {
        sub_protocol: Some(&sub_protocol),
    })?;
    assert!(is_open);
    Ok(stream.written)
}

#[test]
fn the_largest_handshake_response_has_the_minimum_write_buffer_length() {
    let response = accept_largest_sub_protocol(MIN_WRITE_BUF_LEN).unwrap();
    assert_eq!(response.len(), MIN_WRITE_BUF_LEN);
    assert!(response.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));
}

#[test]
fn a_write_buffer_one_byte_short_fails_on_the_largest_handshake_response() {
    assert!(matches!(
        accept_largest_sub_protocol(MIN_WRITE_BUF_LEN - 1),
        Err(FramerError::WebSocket(
            embedded_io_websocket::Error::WriteToBufferTooSmall
        ))
    ));
}

#[test]
fn the_minimum_write_buffer_fits_the_largest_control_frame() {
    assert!(MIN_READ_BUF_LEN <= MIN_WRITE_BUF_LEN);
}
