use core::{ops::Range, str::Utf8Error};

use rand_core::Rng;

use crate::{
    head,
    request::{Decision, Request},
    WebSocket, WebSocketCloseStatusCode, WebSocketKey, WebSocketOptions,
    WebSocketReceiveMessageType, WebSocketSendMessageType, WebSocketState, WebSocketSubProtocol,
    WebSocketType, MASK_KEY_LEN, MAX_CONTROL_FRAME_PAYLOAD_LEN,
};

/// A whole websocket message read from the stream.
pub enum ReadResult<'a> {
    /// A binary message.
    Binary(&'a [u8]),
    /// A text message.
    Text(&'a str),
    /// A pong message with its payload.
    Pong(&'a [u8]),
    /// The close handshake is complete. Holds the status code and reason the other party sent,
    /// or [`WebSocketCloseStatusCode::Empty`] and an empty reason if it sent none.
    Closed {
        /// The status code of the other party.
        status: WebSocketCloseStatusCode,
        /// The reason the other party gave.
        reason: &'a str,
    },
    /// The stream ended before the close handshake was complete.
    Disconnected,
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

pub(crate) enum Answer<'a> {
    Accept(usize),
    Respond(&'a [u8]),
}

pub(crate) enum Decoded {
    NeedMoreData,
    SendThenContinue(usize),
    // The result of the read is kept in `FramerState::pending` until the bytes are sent, so a
    // read interrupted while sending them still returns it.
    SendThenFinish(usize),
    Message(Message),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Pending {
    Message(Message),
    Failed(Failure),
}

// A `FramerError` of a protocol violation, which never holds an error of the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Failure {
    FrameTooLarge(usize),
    Utf8(Utf8Error),
    WebSocket(crate::Error),
}

impl<E> From<Failure> for FramerError<E> {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::FrameTooLarge(len) => FramerError::FrameTooLarge(len),
            Failure::Utf8(error) => FramerError::Utf8(error),
            Failure::WebSocket(error) => FramerError::WebSocket(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Message {
    Binary(usize),
    Text(usize),
    Pong(Range<usize>),
    Closed(Range<usize>),
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
            Message::Closed(range) => match &frame_buf[range] {
                [high, low, reason @ ..] => ReadResult::Closed {
                    status: WebSocketCloseStatusCode::from_u16(u16::from_be_bytes([*high, *low])),
                    reason: core::str::from_utf8(reason).map_err(FramerError::Utf8)?,
                },
                _ => ReadResult::Closed {
                    status: WebSocketCloseStatusCode::Empty,
                    reason: "",
                },
            },
        })
    }
}

/// The smallest read buffer a framer can work with: it fits the largest control frame, which is
/// masked and carries 125 bytes of payload.
///
/// The read buffer must also fit the HTTP header the other side sends in the opening handshake,
/// whose size the other side decides.
pub const MIN_READ_BUF_LEN: usize = 2 + MASK_KEY_LEN + MAX_CONTROL_FRAME_PAYLOAD_LEN;

/// The smallest frame buffer a framer can work with: it fits the largest control frame payload.
///
/// The frame buffer must also fit the largest text or binary message you accept.
pub const MIN_FRAME_BUF_LEN: usize = MAX_CONTROL_FRAME_PAYLOAD_LEN;

/// The smallest write buffer a framer can work with: it fits the largest control frame and the
/// largest response of a server to the opening handshake, which names a sub protocol of
/// [`WebSocketSubProtocol`]'s full capacity.
///
/// A client's write buffer must also fit its own request of the opening handshake, which grows with
/// the path, host, origin, sub protocols and additional headers of its [`WebSocketOptions`].
pub const MIN_WRITE_BUF_LEN: usize = 179;

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
    pub(crate) pending: Option<Pending>,
    pub(crate) writing: Option<WriteProgress>,
}

// How much of a message a failed write already queued, so writing it again continues there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WriteProgress {
    len: usize,
    queued: usize,
    has_started: bool,
}

impl FramerState {
    /// Creates the state for a new connection.
    pub const fn new() -> Self {
        Self {
            read_cursor: 0,
            frame_cursor: 0,
            unsent: 0..0,
            control_frames: 0,
            text_checked: 0,
            pending: None,
            writing: None,
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
        searched: &mut usize,
    ) -> Result<Option<Option<WebSocketSubProtocol>>, FramerError<E>> {
        let Some(head_len) = self.head_len(searched) else {
            return Ok(None);
        };
        let (len, sub_protocol) = self
            .websocket
            .client_accept(web_socket_key, sub_protocols, &self.read_buf[..head_len])
            .map_err(FramerError::WebSocket)?;
        self.consume(len);
        Ok(Some(sub_protocol))
    }
}

impl<'a, TRng> FramerCore<'a, TRng, crate::Server>
where
    TRng: Rng,
{
    pub(crate) fn answer_request<'d, E>(
        &mut self,
        head_len: usize,
        decide: impl FnOnce(&Request<'_>) -> Decision<'d>,
    ) -> Result<Answer<'d>, FramerError<E>> {
        let request = Request::parse(&self.read_buf[..head_len]).map_err(FramerError::WebSocket)?;
        let sub_protocol = match decide(&request) {
            Decision::Respond(response) => return Ok(Answer::Respond(response)),
            Decision::Accept { sub_protocol } => sub_protocol,
        };
        let key = match request.upgrade_key() {
            Ok(key) => key,
            Err(response) => return Ok(Answer::Respond(response)),
        };
        let sub_protocol = sub_protocol
            .map(|protocol| request.sub_protocol(protocol))
            .transpose()
            .map_err(FramerError::WebSocket)?;

        let len = self
            .websocket
            .server_accept(&key, sub_protocol.as_ref(), self.write_buf)
            .map_err(FramerError::WebSocket)?;
        // bytes after the request header are the first frames of the client
        self.consume(head_len);
        Ok(Answer::Accept(len))
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

    pub(crate) fn head_len(&self, searched: &mut usize) -> Option<usize> {
        head::head_len(&self.read_buf[..self.state.read_cursor], searched)
    }

    pub(crate) fn header_read_space<E>(&mut self) -> Result<&mut [u8], FramerError<E>> {
        if self.state.read_cursor == self.read_buf.len() {
            return Err(FramerError::WebSocket(crate::Error::HttpHeaderIncomplete));
        }
        Ok(&mut self.read_buf[self.state.read_cursor..])
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

    /// Encodes the next frame of the text or binary `payload` into the write buffer, or returns
    /// `None` when all of it is encoded. A payload that does not fit into the write buffer is split
    /// into several frames.
    pub(crate) fn encode_next_frame<E>(
        &mut self,
        message_type: WebSocketSendMessageType,
        end_of_message: bool,
        payload: &[u8],
    ) -> Result<Option<usize>, FramerError<E>> {
        let mut progress = match self.state.writing.take() {
            None => WriteProgress {
                len: payload.len(),
                queued: 0,
                has_started: false,
            },
            Some(progress) if progress.len == payload.len() => progress,
            Some(progress) => {
                self.state.writing = Some(progress);
                return Err(FramerError::WebSocket(crate::Error::UnfinishedWrite));
            }
        };
        if progress.has_started && progress.queued == progress.len {
            return Ok(None);
        }
        let remaining = progress.len - progress.queued;
        let fragment_len = remaining.min(self.max_frame_payload());
        if fragment_len == 0 && remaining > 0 {
            return Err(FramerError::WebSocket(crate::Error::WriteToBufferTooSmall));
        }
        let is_last = fragment_len == remaining;
        let fragment = &payload[progress.queued..progress.queued + fragment_len];
        let len = self.encode_write(message_type, end_of_message && is_last, fragment)?;
        progress.queued += fragment_len;
        progress.has_started = true;
        self.state.writing = Some(progress);
        Ok(Some(len))
    }

    // The largest payload whose frame fits into the write buffer (RFC 6455 section 5.2).
    fn max_frame_payload(&self) -> usize {
        let mask_len = if self.websocket.is_client {
            MASK_KEY_LEN
        } else {
            0
        };
        let space = self.write_buf.len().saturating_sub(mask_len);
        if space >= 10 + 65536 {
            space - 10
        } else if space >= 4 + 126 {
            (space - 4).min(u16::MAX as usize)
        } else {
            space.saturating_sub(2).min(125)
        }
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

    pub(crate) fn decode<E>(&mut self, frame_buf: &mut [u8]) -> Result<Decoded, FramerError<E>> {
        let error = match self.decode_frames(frame_buf) {
            Err(error) => error,
            decoded => return decoded,
        };
        let (close_status, failure) = match error {
            FramerError::Utf8(error) => (
                WebSocketCloseStatusCode::InvalidPayloadData,
                Failure::Utf8(error),
            ),
            FramerError::WebSocket(crate::Error::Utf8Error) => (
                WebSocketCloseStatusCode::InvalidPayloadData,
                Failure::WebSocket(crate::Error::Utf8Error),
            ),
            FramerError::FrameTooLarge(len) => (
                WebSocketCloseStatusCode::MessageTooBig,
                Failure::FrameTooLarge(len),
            ),
            FramerError::WebSocket(
                error @ (crate::Error::InvalidOpCode
                | crate::Error::InvalidFrameLength
                | crate::Error::InvalidCloseStatusCode
                | crate::Error::UnexpectedContinuationFrame
                | crate::Error::ReservedBitsSet
                | crate::Error::FragmentedControlFrame
                | crate::Error::UnexpectedDataFrame
                | crate::Error::UnmaskedClientFrame
                | crate::Error::MaskedServerFrame),
            ) => (
                WebSocketCloseStatusCode::ProtocolError,
                Failure::WebSocket(error),
            ),
            error => return Err(error),
        };
        if self.websocket.state != WebSocketState::Open {
            return Err(failure.into());
        }
        let len = self.encode_close(close_status, None)?;
        self.state.pending = Some(Pending::Failed(failure));
        Ok(Decoded::SendThenFinish(len))
    }

    pub(crate) fn has_pending(&self) -> bool {
        self.state.pending.is_some()
    }

    /// Returns the result a read kept while it sent bytes.
    pub(crate) fn finish<'b, E>(
        &mut self,
        frame_buf: &'b [u8],
    ) -> Result<ReadResult<'b>, FramerError<E>> {
        match self.state.pending.take() {
            Some(Pending::Message(message)) => message.into_read_result(frame_buf),
            Some(Pending::Failed(failure)) => Err(failure.into()),
            None => Err(FramerError::WebSocket(crate::Error::Unknown)),
        }
    }

    fn decode_frames<E>(&mut self, frame_buf: &mut [u8]) -> Result<Decoded, FramerError<E>> {
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
                        &frame_buf[payload.clone()],
                    )?;
                    self.state.pending = Some(Pending::Message(Message::Closed(payload)));
                    return Ok(Decoded::SendThenFinish(len));
                }
                WebSocketReceiveMessageType::CloseCompleted => {
                    return Ok(Decoded::Message(Message::Closed(payload)));
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

    fn need_more_data<E>(&self) -> Result<Decoded, FramerError<E>> {
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
