use core::{ops::Range, str::Utf8Error};

use rand_core::Rng;

use crate::{
    WebSocket, WebSocketCloseStatusCode, WebSocketContext, WebSocketKey, WebSocketOptions,
    WebSocketReceiveMessageType, WebSocketSendMessageType, WebSocketState, WebSocketSubProtocol,
    WebSocketType,
};

/// A whole websocket message read from the stream.
pub enum ReadResult<'a> {
    /// A binary message.
    Binary(&'a [u8]),
    /// A text message.
    Text(&'a str),
    /// A pong message with its payload.
    Pong(&'a [u8]),
    /// The close handshake is complete or the stream ended.
    Closed,
}

/// An error of a framer operation.
#[derive(Debug)]
pub enum FramerError<E> {
    /// Reading from or writing to the stream failed.
    Io(E),
    /// A message, frame header or control frame does not fit into its buffer. Holds the size
    /// of that buffer.
    FrameTooLarge(usize),
    /// A text message is not valid UTF-8.
    Utf8(Utf8Error),
    /// The websocket protocol was violated or the operation is not valid in the current state.
    WebSocket(crate::Error),
}

pub(crate) enum Decoded {
    NeedMoreData,
    SendThenContinue(usize),
    SendThenClosed(usize),
    Message(Message),
}

pub(crate) enum Message {
    Binary(usize),
    Text(usize),
    Pong(Range<usize>),
    Closed,
}

impl Message {
    pub(crate) fn into_read_result<E>(
        self,
        frame_buf: &[u8],
    ) -> Result<ReadResult<'_>, FramerError<E>> {
        Ok(match self {
            Message::Binary(len) => ReadResult::Binary(&frame_buf[..len]),
            Message::Text(len) => ReadResult::Text(
                core::str::from_utf8(&frame_buf[..len]).map_err(FramerError::Utf8)?,
            ),
            Message::Pong(range) => ReadResult::Pong(&frame_buf[range]),
            Message::Closed => ReadResult::Closed,
        })
    }
}

/// Progress of a connection that outlives a single framer call.
///
/// Keep one per connection and pass it to every framer created for that connection. Use
/// [`FramerState::new`] for a new connection.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FramerState {
    pub(crate) read_cursor: usize,
    pub(crate) frame_cursor: usize,
    pub(crate) unsent: Range<usize>,
    pub(crate) control_frames: u64,
}

impl FramerState {
    /// Creates the state for a new connection.
    pub const fn new() -> Self {
        Self::with_buffered(0)
    }

    /// Creates the state for a connection whose read buffer already starts with `len` bytes
    /// that arrived after the HTTP header of the opening handshake.
    pub const fn with_buffered(len: usize) -> Self {
        Self {
            read_cursor: len,
            frame_cursor: 0,
            unsent: 0..0,
            control_frames: 0,
        }
    }

    /// Number of pings, pongs and non-final data frames decoded on this connection so far.
    ///
    /// A peer can send these without ever completing a message, so a caller that limits
    /// messages cannot see them. Saturates at `u64::MAX`.
    pub const fn control_frames(&self) -> u64 {
        self.control_frames
    }
}

pub(crate) struct FramerCore<'a, TRng, TWebSocketType>
where
    TRng: Rng,
    TWebSocketType: WebSocketType,
{
    read_buf: &'a mut [u8],
    // Undecoded bytes always start at index 0, so a framer recreated with the same `read_buf` and
    // `read_len` continues where the previous one stopped.
    read_len: &'a mut usize,
    write_buf: &'a mut [u8],
    frame_cursor: &'a mut usize,
    websocket: &'a mut WebSocket<TRng, TWebSocketType>,
    control_frames: &'a mut u64,
}

impl<'a, TRng> FramerCore<'a, TRng, crate::Client>
where
    TRng: Rng,
{
    pub(crate) fn encode_connect<E>(
        &mut self,
        websocket_options: &WebSocketOptions,
    ) -> Result<(usize, WebSocketKey), FramerError<E>> {
        *self.read_len = 0;
        self.websocket
            .client_connect(websocket_options, self.write_buf)
            .map_err(FramerError::WebSocket)
    }

    pub(crate) fn decode_connect_response<E>(
        &mut self,
        web_socket_key: &WebSocketKey,
    ) -> Result<Option<Option<WebSocketSubProtocol>>, FramerError<E>> {
        match self
            .websocket
            .client_accept(web_socket_key, &self.read_buf[..*self.read_len])
        {
            Ok((len, sub_protocol)) => {
                self.consume(len);
                Ok(Some(sub_protocol))
            }
            Err(crate::Error::HttpHeaderIncomplete) => Ok(None),
            Err(e) => Err(FramerError::WebSocket(e)),
        }
    }

    pub(crate) fn connect_read_space<E>(&mut self) -> Result<&mut [u8], FramerError<E>> {
        if *self.read_len == self.read_buf.len() {
            return Err(FramerError::WebSocket(crate::Error::HttpHeaderIncomplete));
        }
        Ok(&mut self.read_buf[*self.read_len..])
    }
}

impl<'a, TRng> FramerCore<'a, TRng, crate::Server>
where
    TRng: Rng,
{
    pub(crate) fn encode_accept<E>(
        &mut self,
        websocket_context: &WebSocketContext,
    ) -> Result<usize, FramerError<E>> {
        self.websocket
            .server_accept(&websocket_context.sec_websocket_key, None, self.write_buf)
            .map_err(FramerError::WebSocket)
    }
}

impl<'a, TRng, TWebSocketType> FramerCore<'a, TRng, TWebSocketType>
where
    TRng: Rng,
    TWebSocketType: WebSocketType,
{
    pub(crate) fn new(
        read_buf: &'a mut [u8],
        read_len: &'a mut usize,
        frame_cursor: &'a mut usize,
        control_frames: &'a mut u64,
        write_buf: &'a mut [u8],
        websocket: &'a mut WebSocket<TRng, TWebSocketType>,
    ) -> Self {
        Self {
            read_buf,
            read_len,
            write_buf,
            frame_cursor,
            websocket,
            control_frames,
        }
    }

    pub(crate) fn state(&self) -> WebSocketState {
        self.websocket.state
    }

    pub(crate) fn written(&self, len: usize) -> &[u8] {
        &self.write_buf[..len]
    }

    pub(crate) fn encode_close<E>(
        &mut self,
        close_status: WebSocketCloseStatusCode,
        status_description: Option<&str>,
    ) -> Result<usize, FramerError<E>> {
        self.websocket
            .close(close_status, status_description, self.write_buf)
            .map_err(FramerError::WebSocket)
    }

    pub(crate) fn encode_write<E>(
        &mut self,
        message_type: WebSocketSendMessageType,
        end_of_message: bool,
        frame_buf: &[u8],
    ) -> Result<usize, FramerError<E>> {
        self.websocket
            .write(message_type, end_of_message, frame_buf, self.write_buf)
            .map_err(FramerError::WebSocket)
    }

    pub(crate) fn read_space<E>(&mut self) -> Result<&mut [u8], FramerError<E>> {
        if *self.read_len == self.read_buf.len() {
            return Err(FramerError::FrameTooLarge(self.read_buf.len()));
        }
        Ok(&mut self.read_buf[*self.read_len..])
    }

    pub(crate) fn commit_read(&mut self, len: usize) {
        *self.read_len += len;
    }

    pub(crate) fn decode<E>(&mut self, frame_buf: &mut [u8]) -> Result<Decoded, FramerError<E>> {
        loop {
            let buffered = &self.read_buf[..*self.read_len];
            if buffered.is_empty() {
                return Ok(Decoded::NeedMoreData);
            }

            // Control frames are decoded in one piece because their payload is answered or
            // returned as a whole and the close status is only parsed at the start of a frame.
            match self.websocket.next_control_frame_len(buffered) {
                Ok(Some(len)) if len.total > buffered.len() => {
                    return self.need_more_data();
                }
                Ok(Some(len)) if *self.frame_cursor + len.payload > frame_buf.len() => {
                    return Err(FramerError::FrameTooLarge(frame_buf.len()));
                }
                Ok(_) => {}
                Err(crate::Error::ReadFrameIncomplete) => return self.need_more_data(),
                Err(e) => return Err(FramerError::WebSocket(e)),
            }

            if *self.frame_cursor >= frame_buf.len() {
                return Err(FramerError::FrameTooLarge(frame_buf.len()));
            }

            // A frame whose payload arrives in pieces reports `end_of_message == false` for every
            // piece, so only the call that parses a new header may count a fragment.
            let starts_new_frame = self.websocket.continuation_read.is_none();
            let ws_result = match self
                .websocket
                .read(buffered, &mut frame_buf[*self.frame_cursor..])
            {
                Ok(ws_result) => ws_result,
                Err(crate::Error::ReadFrameIncomplete) => return self.need_more_data(),
                Err(e) => return Err(FramerError::WebSocket(e)),
            };
            self.consume(ws_result.len_from);

            let payload = *self.frame_cursor..*self.frame_cursor + ws_result.len_to;
            match ws_result.message_type {
                WebSocketReceiveMessageType::Binary | WebSocketReceiveMessageType::Text => {
                    *self.frame_cursor = payload.end;
                    let header_is_final = match &self.websocket.continuation_read {
                        Some(unfinished) => unfinished.is_fin_bit_set,
                        None => ws_result.end_of_message,
                    };
                    if starts_new_frame && !header_is_final {
                        *self.control_frames = self.control_frames.saturating_add(1);
                    }
                    if ws_result.end_of_message {
                        *self.frame_cursor = 0;
                        return Ok(Decoded::Message(
                            if ws_result.message_type == WebSocketReceiveMessageType::Binary {
                                Message::Binary(payload.end)
                            } else {
                                Message::Text(payload.end)
                            },
                        ));
                    }
                }
                WebSocketReceiveMessageType::CloseMustReply => {
                    let len = self.encode_write(
                        WebSocketSendMessageType::CloseReply,
                        true,
                        &frame_buf[payload],
                    )?;
                    return Ok(Decoded::SendThenClosed(len));
                }
                WebSocketReceiveMessageType::CloseCompleted => {
                    return Ok(Decoded::Message(Message::Closed));
                }
                WebSocketReceiveMessageType::Ping => {
                    *self.control_frames = self.control_frames.saturating_add(1);
                    let len = self.encode_write(
                        WebSocketSendMessageType::Pong,
                        true,
                        &frame_buf[payload],
                    )?;
                    return Ok(Decoded::SendThenContinue(len));
                }
                WebSocketReceiveMessageType::Pong => {
                    *self.control_frames = self.control_frames.saturating_add(1);
                    return Ok(Decoded::Message(Message::Pong(payload)));
                }
            }
        }
    }

    fn need_more_data<E>(&self) -> Result<Decoded, FramerError<E>> {
        if *self.read_len == self.read_buf.len() {
            Err(FramerError::FrameTooLarge(self.read_buf.len()))
        } else {
            Ok(Decoded::NeedMoreData)
        }
    }

    fn consume(&mut self, len: usize) {
        self.read_buf.copy_within(len..*self.read_len, 0);
        *self.read_len -= len;
    }
}
