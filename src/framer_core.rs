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

pub(crate) enum Decoded<E> {
    NeedMoreData,
    SendThenContinue(usize),
    SendThenClosed(usize),
    SendThenFail(usize, FramerError<E>),
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
    // Bytes at the start of the current text message that are known to be valid UTF-8.
    pub(crate) text_checked: usize,
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
            text_checked: 0,
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
    // Undecoded bytes always start at index 0 of `read_buf`, so a framer recreated with the same
    // `read_buf` and `state` continues where the previous one stopped.
    state: &'a mut FramerState,
    write_buf: &'a mut [u8],
    websocket: &'a mut WebSocket<TRng, TWebSocketType>,
}

impl<'a, TRng> FramerCore<'a, TRng, crate::Client>
where
    TRng: Rng,
{
    pub(crate) fn encode_connect<E>(
        &mut self,
        websocket_options: &WebSocketOptions,
    ) -> Result<(usize, WebSocketKey), FramerError<E>> {
        self.state.read_cursor = 0;
        self.websocket
            .client_connect(websocket_options, self.write_buf)
            .map_err(FramerError::WebSocket)
    }

    pub(crate) fn decode_connect_response<E>(
        &mut self,
        web_socket_key: &WebSocketKey,
        sub_protocols: Option<&[&str]>,
    ) -> Result<Option<Option<WebSocketSubProtocol>>, FramerError<E>> {
        match self.websocket.client_accept(
            web_socket_key,
            sub_protocols,
            &self.read_buf[..self.state.read_cursor],
        ) {
            Ok((len, sub_protocol)) => {
                self.consume(len);
                Ok(Some(sub_protocol))
            }
            Err(crate::Error::HttpHeaderIncomplete) => Ok(None),
            Err(e) => Err(FramerError::WebSocket(e)),
        }
    }

    pub(crate) fn connect_read_space<E>(&mut self) -> Result<&mut [u8], FramerError<E>> {
        if self.state.read_cursor == self.read_buf.len() {
            return Err(FramerError::WebSocket(crate::Error::HttpHeaderIncomplete));
        }
        Ok(&mut self.read_buf[self.state.read_cursor..])
    }
}

impl<'a, TRng> FramerCore<'a, TRng, crate::Server>
where
    TRng: Rng,
{
    pub(crate) fn encode_accept<E>(
        &mut self,
        websocket_context: &WebSocketContext,
        sub_protocol: Option<&WebSocketSubProtocol>,
    ) -> Result<usize, FramerError<E>> {
        if let Some(sub_protocol) = sub_protocol {
            if !websocket_context
                .sec_websocket_protocol_list
                .contains(sub_protocol)
            {
                return Err(FramerError::WebSocket(crate::Error::SubProtocolNotOffered));
            }
        }
        self.websocket
            .server_accept(
                &websocket_context.sec_websocket_key,
                sub_protocol,
                self.write_buf,
            )
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
        state: &'a mut FramerState,
        write_buf: &'a mut [u8],
        websocket: &'a mut WebSocket<TRng, TWebSocketType>,
    ) -> Self {
        Self {
            read_buf,
            state,
            write_buf,
            websocket,
        }
    }

    pub(crate) fn queue_unsent(&mut self, len: usize) {
        self.state.unsent = 0..len;
    }

    pub(crate) fn unsent(&self) -> &[u8] {
        &self.write_buf[self.state.unsent.clone()]
    }

    pub(crate) fn mark_sent(&mut self, len: usize) {
        self.state.unsent.start += len;
    }

    pub(crate) fn websocket_state(&self) -> WebSocketState {
        self.websocket.state
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
        if self.state.read_cursor == self.read_buf.len() {
            return Err(FramerError::FrameTooLarge(self.read_buf.len()));
        }
        Ok(&mut self.read_buf[self.state.read_cursor..])
    }

    pub(crate) fn commit_read(&mut self, len: usize) {
        self.state.read_cursor += len;
    }

    pub(crate) fn decode<E>(&mut self, frame_buf: &mut [u8]) -> Result<Decoded<E>, FramerError<E>> {
        let error = match self.decode_frames(frame_buf) {
            Err(error) => error,
            decoded => return decoded,
        };
        let close_status = match &error {
            FramerError::Utf8(_) | FramerError::WebSocket(crate::Error::Utf8Error) => {
                WebSocketCloseStatusCode::InvalidPayloadData
            }
            FramerError::FrameTooLarge(_) => WebSocketCloseStatusCode::MessageTooBig,
            FramerError::WebSocket(
                crate::Error::InvalidOpCode
                | crate::Error::InvalidFrameLength
                | crate::Error::InvalidCloseStatusCode
                | crate::Error::UnexpectedContinuationFrame
                | crate::Error::ReservedBitsSet
                | crate::Error::FragmentedControlFrame
                | crate::Error::UnexpectedDataFrame,
            ) => WebSocketCloseStatusCode::ProtocolError,
            _ => return Err(error),
        };
        if self.websocket.state != WebSocketState::Open {
            return Err(error);
        }
        let len = self.encode_close(close_status, None)?;
        Ok(Decoded::SendThenFail(len, error))
    }

    fn decode_frames<E>(&mut self, frame_buf: &mut [u8]) -> Result<Decoded<E>, FramerError<E>> {
        loop {
            let buffered = &self.read_buf[..self.state.read_cursor];
            if buffered.is_empty() {
                return Ok(Decoded::NeedMoreData);
            }

            // Control frames are decoded in one piece because their payload is answered or
            // returned as a whole and the close status is only parsed at the start of a frame.
            match self.websocket.next_control_frame_len(buffered) {
                Ok(Some(len)) if len.total > buffered.len() => {
                    return self.need_more_data();
                }
                Ok(Some(len)) if self.state.frame_cursor + len.payload > frame_buf.len() => {
                    return Err(FramerError::FrameTooLarge(frame_buf.len()));
                }
                Ok(_) => {}
                Err(crate::Error::ReadFrameIncomplete) => return self.need_more_data(),
                Err(e) => return Err(FramerError::WebSocket(e)),
            }

            if self.state.frame_cursor >= frame_buf.len() {
                return Err(FramerError::FrameTooLarge(frame_buf.len()));
            }

            // A frame whose payload arrives in pieces reports `end_of_message == false` for every
            // piece, so only the call that parses a new header may count a fragment.
            let starts_new_frame = self.websocket.continuation_read.is_none();
            let ws_result = match self
                .websocket
                .read(buffered, &mut frame_buf[self.state.frame_cursor..])
            {
                Ok(ws_result) => ws_result,
                Err(crate::Error::ReadFrameIncomplete) => return self.need_more_data(),
                Err(e) => return Err(FramerError::WebSocket(e)),
            };
            self.consume(ws_result.len_from);

            let payload = self.state.frame_cursor..self.state.frame_cursor + ws_result.len_to;
            match ws_result.message_type {
                WebSocketReceiveMessageType::Binary | WebSocketReceiveMessageType::Text => {
                    self.state.frame_cursor = payload.end;
                    let header_is_final = match &self.websocket.continuation_read {
                        Some(unfinished) => unfinished.is_fin_bit_set,
                        None => ws_result.end_of_message,
                    };
                    if starts_new_frame && !header_is_final {
                        self.state.control_frames = self.state.control_frames.saturating_add(1);
                    }
                    let is_text = ws_result.message_type == WebSocketReceiveMessageType::Text;
                    if is_text {
                        self.check_text(&frame_buf[..payload.end], ws_result.end_of_message)?;
                    }
                    if ws_result.end_of_message {
                        self.state.frame_cursor = 0;
                        self.state.text_checked = 0;
                        return Ok(Decoded::Message(if is_text {
                            Message::Text(payload.end)
                        } else {
                            Message::Binary(payload.end)
                        }));
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
                    self.state.control_frames = self.state.control_frames.saturating_add(1);
                    let len = self.encode_write(
                        WebSocketSendMessageType::Pong,
                        true,
                        &frame_buf[payload],
                    )?;
                    return Ok(Decoded::SendThenContinue(len));
                }
                WebSocketReceiveMessageType::Pong => {
                    self.state.control_frames = self.state.control_frames.saturating_add(1);
                    return Ok(Decoded::Message(Message::Pong(payload)));
                }
            }
        }
    }

    fn need_more_data<E>(&self) -> Result<Decoded<E>, FramerError<E>> {
        if self.state.read_cursor == self.read_buf.len() {
            Err(FramerError::FrameTooLarge(self.read_buf.len()))
        } else {
            Ok(Decoded::NeedMoreData)
        }
    }

    // Fails as soon as a fragment makes the message invalid instead of waiting for its end. Only
    // a message that is not complete yet may end inside a character.
    fn check_text<E>(&mut self, text: &[u8], is_complete: bool) -> Result<(), FramerError<E>> {
        match core::str::from_utf8(&text[self.state.text_checked..]) {
            Ok(_) => self.state.text_checked = text.len(),
            Err(error) if error.error_len().is_none() && !is_complete => {
                self.state.text_checked += error.valid_up_to();
            }
            Err(error) => return Err(FramerError::Utf8(error)),
        }
        Ok(())
    }

    fn consume(&mut self, len: usize) {
        self.read_buf.copy_within(len..self.state.read_cursor, 0);
        self.state.read_cursor -= len;
    }
}
