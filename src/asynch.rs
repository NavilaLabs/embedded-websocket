//! A websocket framer for async streams that implement the [`embedded_io_async`] traits.
//!
//! The [`Framer`] reads and writes whole websocket messages and has the same API as the
//! blocking [`crate::blocking::Framer`]. It handles stream reads that return a partial frame, a
//! partial frame header or multiple frames at once.
//!
//! Any stream that implements [`embedded_io_async::Read`] and [`embedded_io_async::Write`]
//! works, for example the `TcpSocket` of `embassy-net`.

use embedded_io_async::{Read, Write};
use rand_core::Rng;

use crate::{
    framer_core::{Decoded, FramerCore},
    FramerError, FramerState, ReadResult, WebSocket, WebSocketCloseStatusCode, WebSocketContext,
    WebSocketOptions, WebSocketSendMessageType, WebSocketState, WebSocketSubProtocol,
    WebSocketType,
};

/// Reads and writes whole websocket messages over a async stream.
///
/// # Cancel safety
///
/// All methods are cancel safe if the `read` and `write` methods of the stream are. When a
/// future is dropped before it completes, the next call on a framer created from the same
/// buffers and [`FramerState`] continues where it stopped: a partially received message is
/// kept and a partially written frame is completed before anything else is written.
///
/// # Examples
///
/// ```no_run
/// use embedded_io_websocket::{
///     asynch::Framer,
///     FramerError, FramerState, ReadResult,
///     WebSocketClient, WebSocketOptions, WebSocketSendMessageType,
/// };
///
/// async fn hello<S: embedded_io_async::Read + embedded_io_async::Write>(
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
///     framer.connect(stream, &websocket_options).await?;
///     framer
///         .write(stream, WebSocketSendMessageType::Text, true, b"hello")
///         .await?;
///     if let ReadResult::Text(text) = framer.read(stream, &mut frame_buf).await? {
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
    pub async fn connect<S>(
        &mut self,
        stream: &mut S,
        websocket_options: &WebSocketOptions<'_>,
    ) -> Result<Option<WebSocketSubProtocol>, FramerError<S::Error>>
    where
        S: Read + Write,
    {
        self.send_unsent(stream).await?;
        let (len, web_socket_key) = self.core.encode_connect(websocket_options)?;
        self.send(stream, len).await?;

        loop {
            let received_size = stream
                .read(self.core.connect_read_space()?)
                .await
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
    pub async fn accept<S>(
        &mut self,
        stream: &mut S,
        websocket_context: &WebSocketContext,
        sub_protocol: Option<&WebSocketSubProtocol>,
    ) -> Result<(), FramerError<S::Error>>
    where
        S: Write,
    {
        self.send_unsent(stream).await?;
        let len = self.core.encode_accept(websocket_context, sub_protocol)?;
        self.send(stream, len).await
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
    pub async fn close<S>(
        &mut self,
        stream: &mut S,
        close_status: WebSocketCloseStatusCode,
        status_description: Option<&str>,
    ) -> Result<(), FramerError<S::Error>>
    where
        S: Write,
    {
        self.send_unsent(stream).await?;
        let len = self.core.encode_close(close_status, status_description)?;
        self.send(stream, len).await
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
    pub async fn write<S>(
        &mut self,
        stream: &mut S,
        message_type: WebSocketSendMessageType,
        end_of_message: bool,
        frame_buf: &[u8],
    ) -> Result<(), FramerError<S::Error>>
    where
        S: Write,
    {
        self.send_unsent(stream).await?;
        let len = self
            .core
            .encode_write(message_type, end_of_message, frame_buf)?;
        self.send(stream, len).await
    }

    /// Reads from the stream until a whole message arrived.
    ///
    /// Answers ping messages with a pong message and completes a close handshake the other party
    /// initiated. Returns [`ReadResult::Closed`] when the close handshake is complete or the
    /// stream ended.
    ///
    /// Pass the same `frame_buf` to every call: a call that is cancelled may leave the first
    /// frames of a message in it.
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
    pub async fn read<'b, S>(
        &mut self,
        stream: &mut S,
        frame_buf: &'b mut [u8],
    ) -> Result<ReadResult<'b>, FramerError<S::Error>>
    where
        S: Read + Write,
    {
        self.send_unsent(stream).await?;
        loop {
            match self.core.decode(frame_buf)? {
                Decoded::NeedMoreData => {
                    let len = stream
                        .read(self.core.read_space()?)
                        .await
                        .map_err(FramerError::Io)?;
                    if len == 0 {
                        return Ok(ReadResult::Closed);
                    }
                    self.core.commit_read(len);
                }
                Decoded::SendThenContinue(len) => {
                    self.send(stream, len).await?;
                }
                Decoded::SendThenClosed(len) => {
                    self.send(stream, len).await?;
                    return Ok(ReadResult::Closed);
                }
                Decoded::SendThenFail(len, error) => {
                    self.send(stream, len).await?;
                    return Err(error);
                }
                Decoded::Message(message) => return message.into_read_result(frame_buf),
            }
        }
    }

    async fn send<S: Write>(
        &mut self,
        stream: &mut S,
        len: usize,
    ) -> Result<(), FramerError<S::Error>> {
        self.core.queue_unsent(len);
        self.send_unsent(stream).await
    }

    async fn send_unsent<S: Write>(&mut self, stream: &mut S) -> Result<(), FramerError<S::Error>> {
        if self.core.unsent().is_empty() {
            return Ok(());
        }
        while !self.core.unsent().is_empty() {
            match stream
                .write(self.core.unsent())
                .await
                .map_err(FramerError::Io)?
            {
                0 => panic!("write() returned Ok(0)"),
                written => self.core.mark_sent(written),
            }
        }
        stream.flush().await.map_err(FramerError::Io)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    use std::{collections::VecDeque, vec, vec::Vec};

    use super::*;
    use crate::{WebSocketClient, WebSocketOpCode, WebSocketServer};

    struct OneBytePerReadStream {
        read_buf: Vec<u8>,
        read_cursor: usize,
        write_buf: Vec<u8>,
    }

    impl embedded_io_async::ErrorType for OneBytePerReadStream {
        type Error = core::convert::Infallible;
    }

    impl Read for OneBytePerReadStream {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            if buf.is_empty() || self.read_cursor == self.read_buf.len() {
                return Ok(0);
            }
            buf[0] = self.read_buf[self.read_cursor];
            self.read_cursor += 1;
            Ok(1)
        }
    }

    impl Write for OneBytePerReadStream {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.write_buf.extend_from_slice(buf);
            Ok(buf.len())
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn fragmented_frames_with_control_frames_one_byte_per_read() {
        let mut frames = Vec::new();
        let mut scratch = vec![0u8; 1024];
        let mut ws_server = WebSocketServer::new_server();
        for (payload, op_code, fin) in [
            ("hello", WebSocketOpCode::TextFrame, false),
            ("", WebSocketOpCode::Ping, true),
            (" world!", WebSocketOpCode::ContinuationFrame, true),
        ] {
            let len = ws_server
                .write_frame(payload.as_bytes(), &mut scratch, op_code, fin)
                .unwrap();
            frames.extend_from_slice(&scratch[..len]);
        }

        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut state = FramerState::default();
        let mut ws_client = WebSocketClient::new_client(rand::rng());
        ws_client.state = WebSocketState::Open;
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_client);
        let mut stream = OneBytePerReadStream {
            read_buf: frames,
            read_cursor: 0,
            write_buf: Vec::new(),
        };

        let mut frame_buf = vec![0; 1024];
        match framer.read(&mut stream, &mut frame_buf).await.unwrap() {
            ReadResult::Text(x) => assert_eq!(x, "hello world!"),
            _ => panic!("expected text frame"),
        }
        // unmasked pong with an empty payload
        assert_eq!(&stream.write_buf[..2], &[0x8A, 0x80]);

        assert!(matches!(
            framer.read(&mut stream, &mut frame_buf).await.unwrap(),
            ReadResult::Closed
        ));
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

    impl embedded_io_async::ErrorType for ScriptedStream {
        type Error = core::convert::Infallible;
    }

    impl Read for ScriptedStream {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let Some(chunk) = self.chunks.pop_front() else {
                return core::future::pending().await;
            };
            buf[..chunk.len()].copy_from_slice(&chunk);
            Ok(chunk.len())
        }
    }

    impl Write for ScriptedStream {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            if self.write_budget == 0 {
                return core::future::pending().await;
            }
            let len = buf.len().min(self.write_budget);
            self.write_budget -= len;
            self.written.extend_from_slice(&buf[..len]);
            Ok(len)
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
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

    fn poll_once<F: Future>(future: F) -> Poll<F::Output> {
        let mut future = pin!(future);
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
    }

    #[tokio::test]
    async fn cancelled_read_keeps_first_frames_of_message() {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut frame_buf = vec![0; 1024];
        let mut state = FramerState::default();
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let mut stream = ScriptedStream::new();

        stream
            .chunks
            .push_back(client_frame(b"hello", WebSocketOpCode::TextFrame, false));
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        assert!(poll_once(framer.read(&mut stream, &mut frame_buf)).is_pending());

        stream.chunks.push_back(client_frame(
            b" world!",
            WebSocketOpCode::ContinuationFrame,
            true,
        ));
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        match framer.read(&mut stream, &mut frame_buf).await.unwrap() {
            ReadResult::Text(text) => assert_eq!(text, "hello world!"),
            _ => panic!("expected text frame"),
        }
    }

    #[tokio::test]
    async fn cancelled_pong_is_completed_before_next_write() {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut frame_buf = vec![0; 1024];
        let mut state = FramerState::default();
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let mut stream = ScriptedStream::new();
        stream
            .chunks
            .push_back(client_frame(b"ping", WebSocketOpCode::Ping, true));
        stream.write_budget = 1;

        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        assert!(poll_once(framer.read(&mut stream, &mut frame_buf)).is_pending());
        assert_eq!(stream.written.len(), 1);

        stream.write_budget = usize::MAX;
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        framer
            .write(&mut stream, WebSocketSendMessageType::Text, true, b"next")
            .await
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

    #[tokio::test]
    async fn counts_pings_pongs_and_non_final_fragments() {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut frame_buf = vec![0; 1024];
        let mut state = FramerState::default();
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
            framer.read(&mut stream, &mut frame_buf).await.unwrap(),
            ReadResult::Pong(_)
        ));
        assert!(matches!(
            framer.read(&mut stream, &mut frame_buf).await.unwrap(),
            ReadResult::Text("xy")
        ));
        assert_eq!(state.control_frames(), 3);
    }

    #[tokio::test]
    async fn a_single_final_message_counts_no_control_frames() {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut frame_buf = vec![0; 1024];
        let mut state = FramerState::default();
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let mut stream = ScriptedStream::new();
        stream
            .chunks
            .push_back(client_frame(b"hi", WebSocketOpCode::TextFrame, true));

        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        framer.read(&mut stream, &mut frame_buf).await.unwrap();
        assert_eq!(state.control_frames(), 0);
    }

    async fn read_in_pieces(
        frames: Vec<Vec<u8>>,
        piece: usize,
    ) -> (FramerState, Vec<std::string::String>) {
        let mut read_buf = vec![0; 1024];
        let mut write_buf = vec![0; 1024];
        let mut frame_buf = vec![0; 1024];
        let mut state = FramerState::default();
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;
        let mut stream = ScriptedStream::new();
        for frame in frames {
            for chunk in frame.chunks(piece) {
                stream.chunks.push_back(chunk.to_vec());
            }
        }
        let mut texts = Vec::new();
        let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
        if let ReadResult::Text(text) = framer.read(&mut stream, &mut frame_buf).await.unwrap() {
            texts.push(text.into());
        }
        (state, texts)
    }

    #[tokio::test]
    async fn a_final_frame_that_arrives_in_pieces_counts_nothing() {
        let payload = [b'a'; 200];
        let (state, texts) = read_in_pieces(
            vec![client_frame(&payload, WebSocketOpCode::TextFrame, true)],
            7,
        )
        .await;
        assert_eq!(texts[0].len(), 200);
        assert_eq!(state.control_frames(), 0);
    }

    #[tokio::test]
    async fn a_fragment_that_arrives_in_pieces_counts_once() {
        let payload = [b'a'; 200];
        let (state, texts) = read_in_pieces(
            vec![
                client_frame(&payload, WebSocketOpCode::TextFrame, false),
                client_frame(b"z", WebSocketOpCode::ContinuationFrame, true),
            ],
            7,
        )
        .await;
        assert_eq!(texts[0].len(), 201);
        assert_eq!(state.control_frames(), 1);
    }
}
