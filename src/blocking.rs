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
    framer_core::{Answer, Decoded, FramerCore},
    request::BAD_REQUEST,
    Decision, FramerError, FramerState, ReadResult, Request, WebSocket, WebSocketCloseStatusCode,
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

        let mut searched = 0;
        loop {
            let received_size = stream
                .read(self.core.header_read_space()?)
                .map_err(FramerError::Io)?;
            if received_size == 0 {
                return Err(FramerError::WebSocket(crate::Error::HttpHeaderIncomplete));
            }
            self.core.commit_read(received_size);

            if let Some(sub_protocol) = self.core.decode_connect_response(
                &web_socket_key,
                websocket_options.sub_protocols,
                &mut searched,
            )? {
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
    /// Reads the HTTP request and passes it to `decide`, which accepts it or answers it with
    /// its own HTTP response. Bytes that arrive after the request are kept for the next
    /// [`read`](Self::read).
    ///
    /// Returns `true` if the websocket is open and `false` if the request was answered with an
    /// HTTP response instead: the one `decide` chose, or `400 Bad Request` or
    /// `426 Upgrade Required` for a request that `decide` accepted but that is not a valid
    /// websocket upgrade. Close the connection after `false`.
    ///
    /// Unlike [`read`](Self::read) and [`write`](Self::write), `accept` cannot be resumed: close
    /// the connection if it fails.
    ///
    /// # Errors
    ///
    /// * [`FramerError::Io`] if reading from or writing to the stream fails.
    /// * [`FramerError::WebSocket`] with [`Error::HttpHeaderInvalid`] if the request is not
    ///   valid HTTP/1.1. The framer answers it with `400 Bad Request` first.
    /// * [`FramerError::WebSocket`] with [`Error::HttpHeaderIncomplete`] if the stream ends or
    ///   the read buffer is full before the request header is complete.
    /// * [`FramerError::WebSocket`] with [`Error::SubProtocolNotOffered`] if `decide` accepts
    ///   with a sub protocol the client did not offer.
    /// * [`FramerError::WebSocket`] if the websocket is already open.
    ///
    /// [`Error::HttpHeaderInvalid`]: crate::Error::HttpHeaderInvalid
    /// [`Error::HttpHeaderIncomplete`]: crate::Error::HttpHeaderIncomplete
    /// [`Error::SubProtocolNotOffered`]: crate::Error::SubProtocolNotOffered
    pub fn accept<'d, S>(
        &mut self,
        stream: &mut S,
        decide: impl FnOnce(&Request<'_>) -> Decision<'d>,
    ) -> Result<bool, FramerError<S::Error>>
    where
        S: Read + Write,
    {
        self.send_unsent(stream)?;
        let mut searched = 0;
        let head_len = loop {
            if let Some(len) = self.core.head_len(&mut searched) {
                break len;
            }
            let received_size = stream
                .read(self.core.header_read_space()?)
                .map_err(FramerError::Io)?;
            if received_size == 0 {
                return Err(FramerError::WebSocket(crate::Error::HttpHeaderIncomplete));
            }
            self.core.commit_read(received_size);
        };

        let answer = match self.core.answer_request(head_len, decide) {
            Err(error @ FramerError::WebSocket(crate::Error::HttpHeaderInvalid)) => {
                stream.write_all(BAD_REQUEST).map_err(FramerError::Io)?;
                stream.flush().map_err(FramerError::Io)?;
                return Err(error);
            }
            answer => answer?,
        };
        match answer {
            Answer::Accept(len) => {
                self.send(stream, len)?;
                Ok(true)
            }
            Answer::Respond(response) => {
                stream.write_all(response).map_err(FramerError::Io)?;
                stream.flush().map_err(FramerError::Io)?;
                Ok(false)
            }
        }
    }
}

impl<'a, TRng, TWebSocketType> Framer<'a, TRng, TWebSocketType>
where
    TRng: Rng,
    TWebSocketType: WebSocketType,
{
    /// Creates a framer.
    ///
    /// `read_buf` holds bytes read from the stream. It must fit the HTTP header of the opening
    /// handshake and any control frame (up to 131 bytes).
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

    /// Writes `frame_buf` to the stream.
    ///
    /// A text or binary payload that does not fit into the write buffer is sent in several
    /// frames. Set `end_of_message` to `false` to continue the message with the next call and to
    /// `true` to end it. Ping, pong and close payloads are always sent in one frame.
    ///
    /// # Resuming after errors
    ///
    /// If a text or binary write fails, part of it may already be sent. Call `write` again with
    /// the same arguments before writing another text or binary message: it continues where the
    /// failed call stopped. Reads, pings, pongs and close in between are fine.
    ///
    /// # Errors
    ///
    /// * [`FramerError::Io`] if writing to the stream fails.
    /// * [`FramerError::WebSocket`] with [`Error::UnfinishedWrite`] if a previous write failed
    ///   and `frame_buf` has a different length than the payload of that write.
    /// * [`FramerError::WebSocket`] with [`Error::WriteToBufferTooSmall`] if not even one byte
    ///   of payload fits into the write buffer, or a ping, pong or close payload does not fit.
    /// * [`FramerError::WebSocket`] if the websocket is not open or a ping, pong or close
    ///   payload is longer than 125 bytes.
    ///
    /// [`Error::UnfinishedWrite`]: crate::Error::UnfinishedWrite
    /// [`Error::WriteToBufferTooSmall`]: crate::Error::WriteToBufferTooSmall
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
        if !matches!(
            message_type,
            WebSocketSendMessageType::Text | WebSocketSendMessageType::Binary
        ) {
            let len = self
                .core
                .encode_write(message_type, end_of_message, frame_buf)?;
            return self.send(stream, len);
        }
        while let Some(len) =
            self.core
                .encode_next_frame(message_type, end_of_message, frame_buf)?
        {
            self.send(stream, len)?;
        }
        Ok(())
    }

    /// Reads from the stream until a whole message arrived.
    ///
    /// Answers ping messages with a pong message and completes a close handshake the other party
    /// initiated. Returns [`ReadResult::Closed`] when the close handshake is complete and
    /// [`ReadResult::Disconnected`] when the stream ended before.
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
        if self.core.has_pending() {
            return self.core.finish(frame_buf);
        }
        loop {
            match self.core.decode(frame_buf)? {
                Decoded::NeedMoreData => {
                    let len = stream
                        .read(self.core.read_space()?)
                        .map_err(FramerError::Io)?;
                    if len == 0 {
                        return Ok(ReadResult::Disconnected);
                    }
                    self.core.commit_read(len);
                }
                Decoded::SendThenContinue(len) => {
                    self.send(stream, len)?;
                }
                Decoded::SendThenFinish(len) => {
                    self.send(stream, len)?;
                    return self.core.finish(frame_buf);
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
            ReadResult::Disconnected
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

    const UPGRADE_REQUEST: &str = "GET /chat HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: chat, superchat\r\nSec-WebSocket-Version: 13\r\n\r\n";

    fn accept(
        request: &[u8],
        decide: impl FnOnce(&Request<'_>) -> Decision<'static>,
    ) -> (
        Result<bool, FramerError<core::convert::Infallible>>,
        std::string::String,
        Option<ReadResult<'static>>,
    ) {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let frame_buf = vec![0; 1024].leak();
        let mut state = FramerState::new();
        let mut ws_server = WebSocketServer::new_server();
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        let mut stream = BufferStream::one_byte_per_read(request.to_vec());
        let accepted = framer.accept(&mut stream, decide);
        let next = match accepted {
            Ok(true) => Some(framer.read(&mut stream, frame_buf).unwrap()),
            _ => None,
        };
        let written = std::string::String::from_utf8_lossy(&stream.write_buf).into_owned();
        (accepted, written, next)
    }

    #[test]
    fn accept_answers_with_the_chosen_sub_protocol_and_keeps_following_frames() {
        let mut request = UPGRADE_REQUEST.as_bytes().to_vec();
        request.extend(client_frame(b"hi", WebSocketOpCode::TextFrame, true));
        let (accepted, written, next) = accept(&request, |request| {
            assert_eq!(request.path(), "/chat");
            assert_eq!(request.header("HOST"), Some(&b"localhost"[..]));
            assert!(request.offers("superchat") && !request.offers("mqtt"));
            Decision::Accept {
                sub_protocol: Some("superchat"),
            }
        });
        assert!(accepted.unwrap());
        assert!(written.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(written.contains("\r\nSec-WebSocket-Protocol: superchat\r\n"));
        assert!(written.contains("\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
        assert!(matches!(next, Some(ReadResult::Text("hi"))));
    }

    #[test]
    fn accept_sends_the_response_the_decision_chose() {
        let not_found = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let (accepted, written, _) =
            accept(UPGRADE_REQUEST.as_bytes(), |_| Decision::Respond(not_found));
        assert!(!accepted.unwrap());
        assert_eq!(written.as_bytes(), not_found);
    }

    #[test]
    fn accept_rejects_a_sub_protocol_the_client_did_not_offer() {
        let (accepted, written, _) = accept(UPGRADE_REQUEST.as_bytes(), |_| Decision::Accept {
            sub_protocol: Some("mqtt"),
        });
        assert!(matches!(
            accepted,
            Err(FramerError::WebSocket(crate::Error::SubProtocolNotOffered))
        ));
        assert!(written.is_empty());
    }

    #[test]
    fn accept_answers_requests_that_are_no_websocket_upgrade() {
        let accept_all = |_: &Request<'_>| Decision::Accept { sub_protocol: None };
        for (request, status) in [
            (
                "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                "400 Bad Request",
            ),
            (&UPGRADE_REQUEST.replace("GET", "POST"), "400 Bad Request"),
            (
                &UPGRADE_REQUEST.replace("Version: 13", "Version: 8"),
                "426 Upgrade Required",
            ),
            (
                &UPGRADE_REQUEST.replace("Sec-WebSocket-Key", "X-Key"),
                "400 Bad Request",
            ),
        ] {
            let (accepted, written, _) = accept(request.as_bytes(), accept_all);
            assert!(!accepted.unwrap(), "{request}");
            assert!(
                written.starts_with(&std::format!("HTTP/1.1 {status}\r\n")),
                "{written}"
            );
        }
    }

    #[test]
    fn accept_answers_malformed_http_with_bad_request() {
        let (accepted, written, _) = accept(b"GET /\0 HTTP/1.1\r\n\r\n", |_| Decision::Accept {
            sub_protocol: None,
        });
        assert!(matches!(
            accepted,
            Err(FramerError::WebSocket(crate::Error::HttpHeaderInvalid))
        ));
        assert!(written.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    }

    fn close_payload(status: u16, reason: &str) -> Vec<u8> {
        [&status.to_be_bytes()[..], reason.as_bytes()].concat()
    }

    #[test]
    fn close_from_the_other_party_returns_its_status_and_reason() {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut frame_buf = vec![0; 1024];
        let mut state = FramerState::new();
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let mut stream = ScriptedStream::new();
        stream.chunks.push_back(client_frame(
            &close_payload(4000, "bye"),
            WebSocketOpCode::ConnectionClose,
            true,
        ));
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        assert!(matches!(
            framer.read(&mut stream, &mut frame_buf).unwrap(),
            ReadResult::Closed {
                status: WebSocketCloseStatusCode::Custom(4000),
                reason: "bye"
            }
        ));
        assert_eq!(
            stream.written,
            [&[0x88, 0x05][..], &close_payload(4000, "bye")].concat()
        );
    }

    #[test]
    fn close_reply_returns_the_status_of_the_other_party() {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut frame_buf = vec![0; 1024];
        let mut state = FramerState::new();
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let mut stream = ScriptedStream::new();
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        framer
            .close(&mut stream, WebSocketCloseStatusCode::NormalClosure, None)
            .unwrap();
        stream
            .chunks
            .push_back(client_frame(b"", WebSocketOpCode::ConnectionClose, true));
        assert!(matches!(
            framer.read(&mut stream, &mut frame_buf).unwrap(),
            ReadResult::Closed {
                status: WebSocketCloseStatusCode::Empty,
                reason: ""
            }
        ));
    }

    fn read_with_failing_write(
        frame: Vec<u8>,
    ) -> (FramerError<Interrupted>, ReadResult<'static>, Vec<u8>) {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let frame_buf = vec![0; 1024].leak();
        let mut state = FramerState::new();
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let mut stream = ScriptedStream::new();
        stream.chunks.push_back(frame);
        stream.write_budget = 1;

        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        let first = framer.read(&mut stream, frame_buf).err().unwrap();
        stream.write_budget = usize::MAX;
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        let second = match framer.read(&mut stream, frame_buf) {
            Ok(result) => result,
            Err(error) => panic!("second read failed: {error:?}"),
        };
        (first, second, stream.written)
    }

    #[test]
    fn interrupted_close_reply_still_returns_the_close_status() {
        let payload = close_payload(1000, "bye");
        let (first, second, written) = read_with_failing_write(client_frame(
            &payload,
            WebSocketOpCode::ConnectionClose,
            true,
        ));
        assert!(matches!(first, FramerError::Io(Interrupted)));
        assert!(matches!(
            second,
            ReadResult::Closed {
                status: WebSocketCloseStatusCode::NormalClosure,
                reason: "bye"
            }
        ));
        assert_eq!(written, [&[0x88, 0x05][..], &payload].concat());
    }

    #[test]
    fn interrupted_close_after_a_protocol_violation_still_returns_the_violation() {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut frame_buf = vec![0; 1024];
        let mut state = FramerState::new();
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let mut stream = ScriptedStream::new();
        let mut frame = client_frame(b"a", WebSocketOpCode::TextFrame, true);
        frame[0] |= 0x40;
        stream.chunks.push_back(frame);
        stream.write_budget = 1;

        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        assert!(matches!(
            framer.read(&mut stream, &mut frame_buf),
            Err(FramerError::Io(Interrupted))
        ));
        stream.write_budget = usize::MAX;
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        assert!(matches!(
            framer.read(&mut stream, &mut frame_buf),
            Err(FramerError::WebSocket(crate::Error::ReservedBitsSet))
        ));
        assert_eq!(stream.written, [0x88, 0x02, 0x03, 0xEA]);
    }

    #[test]
    fn unmasked_client_frame_closes_with_protocol_error() {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut frame_buf = vec![0; 1024];
        let mut state = FramerState::new();
        let mut ws_server = open_server();
        let mut stream = ScriptedStream::new();
        stream.chunks.push_back(vec![0x81, 0x01, b'a']);

        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        assert!(matches!(
            framer.read(&mut stream, &mut frame_buf),
            Err(FramerError::WebSocket(crate::Error::UnmaskedClientFrame))
        ));
        assert_eq!(stream.written, [0x88, 0x02, 0x03, 0xEA]);
    }

    fn open_server() -> WebSocketServer {
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        ws_server
    }

    // Decodes unmasked frames into (opcode, fin, payload).
    fn frames(mut written: &[u8]) -> Vec<(u8, bool, Vec<u8>)> {
        let mut frames = Vec::new();
        while !written.is_empty() {
            let (len, header) = match written[1] {
                126 => (u16::from_be_bytes([written[2], written[3]]) as usize, 4),
                len => (len as usize, 2),
            };
            frames.push((
                written[0] & 0x0F,
                written[0] & 0x80 != 0,
                written[header..header + len].to_vec(),
            ));
            written = &written[header + len..];
        }
        frames
    }

    fn payloads(frames: &[(u8, bool, Vec<u8>)]) -> Vec<u8> {
        frames
            .iter()
            .flat_map(|(_, _, payload)| payload.clone())
            .collect()
    }

    #[test]
    fn write_splits_a_payload_that_does_not_fit_into_frames() {
        let (mut read_buf, mut write_buf, mut state) =
            (vec![0; 64], vec![0; 64], FramerState::new());
        let mut ws_server = open_server();
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        let mut stream = ScriptedStream::new();
        let payload: Vec<u8> = (0..150).collect();
        framer
            .write(
                &mut stream,
                WebSocketSendMessageType::Binary,
                true,
                &payload,
            )
            .unwrap();
        framer
            .write(&mut stream, WebSocketSendMessageType::Ping, true, b"p")
            .unwrap();

        let frames = frames(&stream.written);
        let kinds: Vec<_> = frames.iter().map(|(op, fin, _)| (*op, *fin)).collect();
        assert_eq!(kinds, [(2, false), (0, false), (0, true), (9, true)]);
        assert_eq!(payloads(&frames[..3]), payload);
    }

    #[test]
    fn write_continues_after_a_failure_when_called_again() {
        let (mut read_buf, mut write_buf, mut state) =
            (vec![0; 64], vec![0; 64], FramerState::new());
        let mut ws_server = open_server();
        let mut stream = ScriptedStream::new();
        let payload: Vec<u8> = (0..150).collect();
        let mut failures = 0;
        loop {
            stream.write_budget = 50;
            let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
            match framer.write(
                &mut stream,
                WebSocketSendMessageType::Binary,
                true,
                &payload,
            ) {
                Ok(()) => break,
                Err(FramerError::Io(Interrupted)) => failures += 1,
                Err(error) => panic!("write failed: {error:?}"),
            }
        }
        assert!(failures > 0);
        let frames = frames(&stream.written);
        assert!(frames.last().unwrap().1);
        assert_eq!(payloads(&frames), payload);
    }

    #[test]
    fn write_of_another_message_before_finishing_a_failed_one_is_rejected() {
        let (mut read_buf, mut write_buf, mut state) =
            (vec![0; 64], vec![0; 64], FramerState::new());
        let mut ws_server = open_server();
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        let mut stream = ScriptedStream::new();
        stream.write_budget = 10;
        assert!(framer
            .write(
                &mut stream,
                WebSocketSendMessageType::Binary,
                true,
                &[0; 150]
            )
            .is_err());
        stream.write_budget = usize::MAX;
        assert!(matches!(
            framer.write(&mut stream, WebSocketSendMessageType::Text, true, b"other"),
            Err(FramerError::WebSocket(crate::Error::UnfinishedWrite))
        ));
        framer
            .write(&mut stream, WebSocketSendMessageType::Ping, true, b"")
            .unwrap();
        framer
            .write(
                &mut stream,
                WebSocketSendMessageType::Binary,
                true,
                &[0; 150],
            )
            .unwrap();
        framer
            .write(&mut stream, WebSocketSendMessageType::Text, true, b"other")
            .unwrap();
        let kinds: Vec<_> = frames(&stream.written)
            .iter()
            .map(|(op, fin, _)| (*op, *fin))
            .collect();
        assert_eq!(
            kinds,
            [(2, false), (9, true), (0, false), (0, true), (1, true)]
        );
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
