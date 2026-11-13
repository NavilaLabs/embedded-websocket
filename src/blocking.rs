//! A websocket framer for blocking streams that implement the [`embedded_io`] traits.
//!
//! The [`Framer`] reads and writes whole websocket messages and has the same API as the
//! async [`crate::asynch::Framer`]. It handles stream reads that return a partial frame, a
//! partial frame header or multiple frames at once.
//!
//! Any stream that implements [`embedded_io::Read`] and [`embedded_io::Write`] works.

use embedded_io::{Read, Write};
use rand_core::Rng;

use crate::{
    framer_core::{Decoded, FramerCore},
    FramerError, FramerState, ReadResult, WebSocket, WebSocketCloseStatusCode, WebSocketContext,
    WebSocketOptions, WebSocketSendMessageType, WebSocketState, WebSocketSubProtocol,
    WebSocketType,
};

/// Reads and writes whole websocket messages over a blocking stream.
///
/// # Resuming after errors
///
/// When a call fails with an error the stream can recover from, for example a timeout or
/// `WouldBlock` on a non-blocking stream, the next call on a framer created from the same
/// buffers and [`FramerState`] continues where it stopped: a partially received message is
/// kept and a partially written frame is completed before anything else is written.
///
/// # Examples
///
/// ```no_run
/// use embedded_io_websocket::{
///     blocking::Framer,
///     FramerError, FramerState, ReadResult,
///     WebSocketClient, WebSocketOptions, WebSocketSendMessageType,
/// };
///
/// fn hello<S: embedded_io::Read + embedded_io::Write>(
///     stream: &mut S,
/// ) -> Result<(), FramerError<S::Error>> {
///     let mut read_buf = [0; 1024];
///     let mut state = FramerState::new();
///     let mut write_buf = [0; 1024];
///     let mut frame_buf = [0; 1024];
///     let mut websocket = WebSocketClient::new_client(rand::rng());
///     let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut websocket);
///
///     let websocket_options = WebSocketOptions {
///         path: "/chat",
///         host: "localhost",
///         origin: "http://localhost",
///         sub_protocols: None,
///         additional_headers: None,
///     };
///     framer.connect(stream, &websocket_options)?;
///     framer.write(stream, WebSocketSendMessageType::Text, true, b"hello")?;
///     if let ReadResult::Text(text) = framer.read(stream, &mut frame_buf)? {
///         assert_eq!("hello", text);
///     }
///     Ok(())
/// }
/// ```
pub struct Framer<'a, TRng, TWebSocketType>
where
    TRng: Rng,
    TWebSocketType: WebSocketType,
{
    core: FramerCore<'a, TRng, TWebSocketType>,
}

impl<'a, TRng> Framer<'a, TRng, crate::Client>
where
    TRng: Rng,
{
    /// Performs the client side of the opening handshake.
    ///
    /// Returns the sub protocol the server chose from
    /// [`WebSocketOptions::sub_protocols`], if any.
    ///
    /// # Errors
    ///
    /// * [`FramerError::Io`] if reading from or writing to the stream fails.
    /// * [`FramerError::WebSocket`] with [`Error::HttpHeaderIncomplete`] if the stream ends or
    ///   the read buffer is full before the HTTP response header is complete.
    /// * [`FramerError::WebSocket`] if the server rejects the opening handshake.
    ///
    /// [`Error::HttpHeaderIncomplete`]: crate::Error::HttpHeaderIncomplete
    pub fn connect<S>(
        &mut self,
        stream: &mut S,
        websocket_options: &WebSocketOptions<'_>,
    ) -> Result<Option<WebSocketSubProtocol>, FramerError<S::Error>>
    where
        S: Read + Write,
    {
        self.send_unsent(stream)?;
        let (len, web_socket_key) = self.core.encode_connect(websocket_options)?;
        self.send(stream, len)?;

        loop {
            let received_size = stream
                .read(self.core.connect_read_space()?)
                .map_err(FramerError::Io)?;
            if received_size == 0 {
                return Err(FramerError::WebSocket(crate::Error::HttpHeaderIncomplete));
            }
            self.core.commit_read(received_size);

            if let Some(sub_protocol) = self
                .core
                .decode_connect_response(&web_socket_key, websocket_options.sub_protocols)?
            {
                return Ok(sub_protocol);
            }
        }
    }
}

impl<'a, TRng> Framer<'a, TRng, crate::Server>
where
    TRng: Rng,
{
    /// Performs the server side of the opening handshake.
    ///
    /// Read the HTTP request header with [`crate::read_http_header`] first and pass the
    /// resulting context.
    ///
    /// `sub_protocol` is the sub protocol the server chose from
    /// [`WebSocketContext::sec_websocket_protocol_list`], or `None` to choose none.
    ///
    /// # Errors
    ///
    /// * [`FramerError::Io`] if writing to the stream fails.
    /// * [`FramerError::WebSocket`] with [`Error::SubProtocolNotOffered`] if the client did not
    ///   offer `sub_protocol`.
    /// * [`FramerError::WebSocket`] if the websocket is already open.
    ///
    /// [`Error::SubProtocolNotOffered`]: crate::Error::SubProtocolNotOffered
    pub fn accept<S>(
        &mut self,
        stream: &mut S,
        websocket_context: &WebSocketContext,
        sub_protocol: Option<&WebSocketSubProtocol>,
    ) -> Result<(), FramerError<S::Error>>
    where
        S: Write,
    {
        self.send_unsent(stream)?;
        let len = self.core.encode_accept(websocket_context, sub_protocol)?;
        self.send(stream, len)
    }
}

impl<'a, TRng, TWebSocketType> Framer<'a, TRng, TWebSocketType>
where
    TRng: Rng,
    TWebSocketType: WebSocketType,
{
    /// Creates a framer.
    ///
    /// `read_buf` holds bytes read from the stream. It must fit the HTTP response header of the
    /// opening handshake and any control frame (up to 131 bytes).
    ///
    /// `state` tracks progress across framers. A framer created with the same buffers and
    /// `state` continues where the previous one stopped.
    ///
    /// `write_buf` holds encoded frames. It must fit the largest payload you write plus the
    /// frame header (2 to 14 bytes).
    pub fn new(
        read_buf: &'a mut [u8],
        state: &'a mut FramerState,
        write_buf: &'a mut [u8],
        websocket: &'a mut WebSocket<TRng, TWebSocketType>,
    ) -> Self {
        Self {
            core: FramerCore::new(read_buf, state, write_buf, websocket),
        }
    }

    /// Returns the state of the websocket.
    pub fn state(&self) -> WebSocketState {
        self.core.websocket_state()
    }

    /// Initiates a close handshake.
    ///
    /// Has no effect if the other party already closed the websocket.
    ///
    /// # Errors
    ///
    /// * [`FramerError::Io`] if writing to the stream fails.
    /// * [`FramerError::WebSocket`] if the websocket is not open.
    pub fn close<S>(
        &mut self,
        stream: &mut S,
        close_status: WebSocketCloseStatusCode,
        status_description: Option<&str>,
    ) -> Result<(), FramerError<S::Error>>
    where
        S: Write,
    {
        self.send_unsent(stream)?;
        let len = self.core.encode_close(close_status, status_description)?;
        self.send(stream, len)
    }

    /// Writes `frame_buf` to the stream as one websocket frame.
    ///
    /// Set `end_of_message` to `false` to send a message in multiple frames and to `true` for
    /// the last frame.
    ///
    /// # Errors
    ///
    /// * [`FramerError::Io`] if writing to the stream fails.
    /// * [`FramerError::WebSocket`] if the websocket is not open or the frame does not fit into
    ///   the write buffer.
    pub fn write<S>(
        &mut self,
        stream: &mut S,
        message_type: WebSocketSendMessageType,
        end_of_message: bool,
        frame_buf: &[u8],
    ) -> Result<(), FramerError<S::Error>>
    where
        S: Write,
    {
        self.send_unsent(stream)?;
        let len = self
            .core
            .encode_write(message_type, end_of_message, frame_buf)?;
        self.send(stream, len)
    }

    /// Reads from the stream until a whole message arrived.
    ///
    /// Answers ping messages with a pong message and completes a close handshake the other party
    /// initiated. Returns [`ReadResult::Closed`] when the close handshake is complete or the
    /// stream ended.
    ///
    /// Pass the same `frame_buf` to every call: a call that fails may leave the first frames of
    /// a message in it.
    ///
    /// # Errors
    ///
    /// * [`FramerError::Io`] if reading from or writing to the stream fails.
    /// * [`FramerError::FrameTooLarge`] if the message does not fit into `frame_buf`, or a frame
    ///   header or control frame does not fit into the read buffer.
    /// * [`FramerError::Utf8`] if a text message is not valid UTF-8.
    /// * [`FramerError::WebSocket`] if the other party violates the websocket protocol.
    ///
    /// If the other party sent an invalid frame, an invalid text message or a message that does
    /// not fit, the framer starts a close handshake with the matching status code (1002, 1007 or
    /// 1009) before it returns the error. Drop the connection afterwards.
    pub fn read<'b, S>(
        &mut self,
        stream: &mut S,
        frame_buf: &'b mut [u8],
    ) -> Result<ReadResult<'b>, FramerError<S::Error>>
    where
        S: Read + Write,
    {
        self.send_unsent(stream)?;
        loop {
            match self.core.decode(frame_buf)? {
                Decoded::NeedMoreData => {
                    let len = stream
                        .read(self.core.read_space()?)
                        .map_err(FramerError::Io)?;
                    if len == 0 {
                        return Ok(ReadResult::Closed);
                    }
                    self.core.commit_read(len);
                }
                Decoded::SendThenContinue(len) => {
                    self.send(stream, len)?;
                }
                Decoded::SendThenClosed(len) => {
                    self.send(stream, len)?;
                    return Ok(ReadResult::Closed);
                }
                Decoded::SendThenFail(len, error) => {
                    self.send(stream, len)?;
                    return Err(error);
                }
                Decoded::Message(message) => return message.into_read_result(frame_buf),
            }
        }
    }

    fn send<S: Write>(&mut self, stream: &mut S, len: usize) -> Result<(), FramerError<S::Error>> {
        self.core.queue_unsent(len);
        self.send_unsent(stream)
    }

    fn send_unsent<S: Write>(&mut self, stream: &mut S) -> Result<(), FramerError<S::Error>> {
        if self.core.unsent().is_empty() {
            return Ok(());
        }
        while !self.core.unsent().is_empty() {
            match stream.write(self.core.unsent()).map_err(FramerError::Io)? {
                0 => panic!("write() returned Ok(0)"),
                written => self.core.mark_sent(written),
            }
        }
        stream.flush().map_err(FramerError::Io)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::{collections::VecDeque, vec, vec::Vec};

    use super::*;
    use crate::{WebSocketClient, WebSocketOpCode, WebSocketServer};

    struct BufferStream {
        read_buf: Vec<u8>,
        read_cursor: usize,
        max_read_len: usize,
        write_buf: Vec<u8>,
    }

    impl BufferStream {
        fn new(read_buf: Vec<u8>) -> Self {
            Self {
                read_buf,
                read_cursor: 0,
                max_read_len: usize::MAX,
                write_buf: Vec::new(),
            }
        }

        fn one_byte_per_read(read_buf: Vec<u8>) -> Self {
            Self {
                max_read_len: 1,
                ..Self::new(read_buf)
            }
        }
    }

    impl embedded_io::ErrorType for BufferStream {
        type Error = core::convert::Infallible;
    }

    impl Read for BufferStream {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let len = buf
                .len()
                .min(self.read_buf.len() - self.read_cursor)
                .min(self.max_read_len);
            buf[..len].copy_from_slice(&self.read_buf[self.read_cursor..self.read_cursor + len]);
            self.read_cursor += len;
            Ok(len)
        }
    }

    impl Write for BufferStream {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.write_buf.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn server_frames(frames: &[(&str, WebSocketOpCode, bool)]) -> Vec<u8> {
        let mut encoded = Vec::new();
        let mut scratch = vec![0u8; 1024];
        let mut ws_server = WebSocketServer::new_server();
        for (payload, op_code, fin) in frames {
            let len = ws_server
                .write_frame(payload.as_bytes(), &mut scratch, *op_code, *fin)
                .unwrap();
            encoded.extend_from_slice(&scratch[..len]);
        }
        encoded
    }

    fn fragmented_frames() -> Vec<u8> {
        server_frames(&[
            ("hello", WebSocketOpCode::TextFrame, false),
            (" world", WebSocketOpCode::ContinuationFrame, false),
            ("!", WebSocketOpCode::ContinuationFrame, true),
        ])
    }

    fn fragmented_frames_with_ping() -> Vec<u8> {
        server_frames(&[
            ("hello", WebSocketOpCode::TextFrame, false),
            ("", WebSocketOpCode::Ping, true),
            (" world!", WebSocketOpCode::ContinuationFrame, true),
        ])
    }

    fn read_texts(mut stream: BufferStream, messages: usize) -> BufferStream {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut frame_buf = vec![0; 1024];
        let mut state = FramerState::new();
        let mut ws_client = WebSocketClient::new_client(rand::rng());
        ws_client.state = WebSocketState::Open;
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_client);
        for _ in 0..messages {
            match framer.read(&mut stream, &mut frame_buf).unwrap() {
                ReadResult::Text(text) => assert_eq!(text, "hello world!"),
                _ => panic!("expected text frame"),
            }
        }
        assert!(matches!(
            framer.read(&mut stream, &mut frame_buf).unwrap(),
            ReadResult::Closed
        ));
        stream
    }

    #[test]
    fn fragmented_frames_are_joined() {
        read_texts(BufferStream::new(fragmented_frames()), 1);
    }

    #[test]
    fn fragmented_frames_with_control_frames() {
        let stream = read_texts(BufferStream::new(fragmented_frames_with_ping()), 1);
        // unmasked pong with an empty payload
        assert_eq!(&stream.write_buf[..2], &[0x8A, 0x80]);
    }

    #[test]
    fn fragmented_frames_with_control_frames_one_byte_per_read() {
        let stream = read_texts(
            BufferStream::one_byte_per_read(fragmented_frames_with_ping()),
            1,
        );
        // unmasked pong with an empty payload
        assert_eq!(&stream.write_buf[..2], &[0x8A, 0x80]);
    }

    #[test]
    fn multiple_messages_in_one_read() {
        let mut frames = fragmented_frames();
        frames.extend(fragmented_frames_with_ping());
        read_texts(BufferStream::new(frames), 2);
    }

    fn websocket_options() -> WebSocketOptions<'static> {
        WebSocketOptions {
            path: "/chat",
            host: "localhost",
            origin: "http://localhost",
            sub_protocols: None,
            additional_headers: None,
        }
    }

    #[test]
    fn frames_received_with_handshake_response() {
        use rand::{rngs::StdRng, SeedableRng};

        let mut scratch = vec![0; 1024];
        let (_, web_socket_key) = WebSocketClient::new_client(StdRng::seed_from_u64(1))
            .client_connect(&websocket_options(), &mut scratch)
            .unwrap();
        let mut ws_server = WebSocketServer::new_server();
        let len = ws_server
            .server_accept(&web_socket_key, None, &mut scratch)
            .unwrap();
        let mut received = scratch[..len].to_vec();
        received.extend(fragmented_frames());

        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut frame_buf = vec![0; 1024];
        let mut state = FramerState::new();
        let mut ws_client = WebSocketClient::new_client(StdRng::seed_from_u64(1));
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_client);
        let mut stream = BufferStream::new(received);
        framer.connect(&mut stream, &websocket_options()).unwrap();

        match framer.read(&mut stream, &mut frame_buf).unwrap() {
            ReadResult::Text(text) => assert_eq!(text, "hello world!"),
            _ => panic!("expected text frame"),
        }
    }

    #[test]
    fn connect_fails_when_stream_ends_during_handshake() {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut state = FramerState::new();
        let mut ws_client = WebSocketClient::new_client(rand::rng());
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_client);
        let mut stream = BufferStream::new(b"HTTP/1.1 101 Switching".to_vec());
        assert!(matches!(
            framer.connect(&mut stream, &websocket_options()),
            Err(FramerError::WebSocket(crate::Error::HttpHeaderIncomplete))
        ));
    }

    #[derive(Debug)]
    struct Interrupted;

    impl core::fmt::Display for Interrupted {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("interrupted")
        }
    }

    impl core::error::Error for Interrupted {}

    impl embedded_io::Error for Interrupted {
        fn kind(&self) -> embedded_io::ErrorKind {
            embedded_io::ErrorKind::TimedOut
        }
    }

    struct ScriptedStream {
        chunks: VecDeque<Vec<u8>>,
        write_budget: usize,
        written: Vec<u8>,
    }

    impl ScriptedStream {
        fn new() -> Self {
            Self {
                chunks: VecDeque::new(),
                write_budget: usize::MAX,
                written: Vec::new(),
            }
        }
    }

    impl embedded_io::ErrorType for ScriptedStream {
        type Error = Interrupted;
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let chunk = self.chunks.pop_front().ok_or(Interrupted)?;
            buf[..chunk.len()].copy_from_slice(&chunk);
            Ok(chunk.len())
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            if self.write_budget == 0 {
                return Err(Interrupted);
            }
            let len = buf.len().min(self.write_budget);
            self.write_budget -= len;
            self.written.extend_from_slice(&buf[..len]);
            Ok(len)
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn client_frame(payload: &[u8], op_code: WebSocketOpCode, fin: bool) -> Vec<u8> {
        let mut ws_client = WebSocketClient::new_client(rand::rng());
        let mut frame = vec![0; 256];
        let len = ws_client
            .write_frame(payload, &mut frame, op_code, fin)
            .unwrap();
        frame.truncate(len);
        frame
    }

    fn accept_with(sub_protocol: &str) -> Result<Vec<u8>, FramerError<core::convert::Infallible>> {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut state = FramerState::new();
        let mut ws_server = WebSocketServer::new_server();
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        let mut stream = BufferStream::new(Vec::new());
        let websocket_context = WebSocketContext {
            sec_websocket_protocol_list: heapless::Vec::from_slice(&[
                "chat".try_into().unwrap(),
                "superchat".try_into().unwrap(),
            ])
            .unwrap(),
            sec_websocket_key: "dGhlIHNhbXBsZSBub25jZQ==".try_into().unwrap(),
        };
        framer.accept(
            &mut stream,
            &websocket_context,
            Some(&sub_protocol.try_into().unwrap()),
        )?;
        Ok(stream.write_buf)
    }

    #[test]
    fn accept_sends_the_chosen_sub_protocol() {
        let response = accept_with("superchat").unwrap();
        let response = core::str::from_utf8(&response).unwrap();
        assert!(response.contains("\r\nSec-WebSocket-Protocol: superchat\r\n"));
    }

    #[test]
    fn accept_rejects_a_sub_protocol_the_client_did_not_offer() {
        assert!(matches!(
            accept_with("mqtt"),
            Err(FramerError::WebSocket(crate::Error::SubProtocolNotOffered))
        ));
    }

    fn server_reads(frame: Vec<u8>) -> (FramerError<Interrupted>, Vec<u8>) {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut frame_buf = vec![0; 1024];
        let mut state = FramerState::new();
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let mut stream = ScriptedStream::new();
        stream.chunks.push_back(frame);
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        let error = framer.read(&mut stream, &mut frame_buf).err().unwrap();
        (error, stream.written)
    }

    #[test]
    fn protocol_violation_closes_with_protocol_error() {
        let mut frame = client_frame(b"a", WebSocketOpCode::TextFrame, true);
        frame[0] |= 0x40;
        let (error, written) = server_reads(frame);
        assert!(matches!(
            error,
            FramerError::WebSocket(crate::Error::ReservedBitsSet)
        ));
        assert_eq!(written, [0x88, 0x02, 0x03, 0xEA]);
    }

    #[test]
    fn invalid_text_closes_with_invalid_payload_data() {
        let (error, written) =
            server_reads(client_frame(&[0xFF], WebSocketOpCode::TextFrame, true));
        assert!(matches!(error, FramerError::Utf8(_)));
        assert_eq!(written, [0x88, 0x02, 0x03, 0xEF]);
    }

    #[test]
    fn counts_pings_pongs_and_non_final_fragments() {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut frame_buf = vec![0; 1024];
        let mut state = FramerState::new();
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let mut stream = ScriptedStream::new();
        for chunk in [
            client_frame(b"a", WebSocketOpCode::Ping, true),
            client_frame(b"b", WebSocketOpCode::Pong, true),
            client_frame(b"x", WebSocketOpCode::TextFrame, false),
            client_frame(b"y", WebSocketOpCode::ContinuationFrame, true),
        ] {
            stream.chunks.push_back(chunk);
        }

        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        assert!(matches!(
            framer.read(&mut stream, &mut frame_buf).unwrap(),
            ReadResult::Pong(_)
        ));
        assert!(matches!(
            framer.read(&mut stream, &mut frame_buf).unwrap(),
            ReadResult::Text("xy")
        ));
        assert_eq!(state.control_frames(), 3);
    }

    #[test]
    fn failed_read_keeps_first_frames_of_message() {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut frame_buf = vec![0; 1024];
        let mut state = FramerState::new();
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let mut stream = ScriptedStream::new();

        stream
            .chunks
            .push_back(client_frame(b"hello", WebSocketOpCode::TextFrame, false));
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        assert!(matches!(
            framer.read(&mut stream, &mut frame_buf),
            Err(FramerError::Io(Interrupted))
        ));

        stream.chunks.push_back(client_frame(
            b" world!",
            WebSocketOpCode::ContinuationFrame,
            true,
        ));
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        match framer.read(&mut stream, &mut frame_buf).unwrap() {
            ReadResult::Text(text) => assert_eq!(text, "hello world!"),
            _ => panic!("expected text frame"),
        }
    }

    #[test]
    fn failed_pong_is_completed_before_next_write() {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut frame_buf = vec![0; 1024];
        let mut state = FramerState::new();
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let mut stream = ScriptedStream::new();
        stream
            .chunks
            .push_back(client_frame(b"ping", WebSocketOpCode::Ping, true));
        stream.write_budget = 1;

        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        assert!(matches!(
            framer.read(&mut stream, &mut frame_buf),
            Err(FramerError::Io(Interrupted))
        ));
        assert_eq!(stream.written.len(), 1);

        stream.write_budget = usize::MAX;
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        framer
            .write(&mut stream, WebSocketSendMessageType::Text, true, b"next")
            .unwrap();

        let mut expected_server = WebSocketServer::new_server();
        let mut expected = vec![0; 64];
        let pong_len = expected_server
            .write_frame(b"ping", &mut expected, WebSocketOpCode::Pong, true)
            .unwrap();
        let text_len = expected_server
            .write_frame(
                b"next",
                &mut expected[pong_len..],
                WebSocketOpCode::TextFrame,
                true,
            )
            .unwrap();
        assert_eq!(stream.written, &expected[..pong_len + text_len]);
    }
}
