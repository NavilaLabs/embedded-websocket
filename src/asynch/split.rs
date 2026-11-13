use core::{
    cell::{Cell, RefCell, RefMut},
    future::{poll_fn, Future},
    ops::{Deref, DerefMut},
    task::{Poll, Waker},
};

use embedded_io_async::{Read, Write};
use rand_core::Rng;

use super::{send, send_unsent};
use crate::{
    framer_core::{Decoded, FramerCore, Message, ReadMode},
    FramerError, FramerState, ReadChunk, ReadResult, WebSocket, WebSocketCloseStatusCode,
    WebSocketSendMessageType, WebSocketType,
};

/// An async lock that the [`Reader`] and [`Writer`] of a connection share.
///
/// [`LocalMutex`] works for halves that run on the same executor. To run them on different
/// executors or threads, implement this trait for a newtype around a mutex that works there,
/// for example `embassy_sync::mutex::Mutex`.
pub trait Lock {
    /// The value the lock protects.
    type Target;

    /// Grants exclusive access to the value until it is dropped.
    type Guard<'a>: DerefMut<Target = Self::Target>
    where
        Self: 'a;

    /// Waits until no other guard exists and returns a new one.
    fn lock(&self) -> impl Future<Output = Self::Guard<'_>>;
}

/// A [`Lock`] for halves that run on the same executor. It is not `Sync`.
pub struct LocalMutex<T> {
    value: RefCell<T>,
    waiting: Cell<Option<Waker>>,
}

impl<T> LocalMutex<T> {
    /// Creates an unlocked mutex holding `value`.
    pub const fn new(value: T) -> Self {
        Self {
            value: RefCell::new(value),
            waiting: Cell::new(None),
        }
    }

    /// Returns the value.
    pub fn into_inner(self) -> T {
        self.value.into_inner()
    }
}

impl<T> Lock for LocalMutex<T> {
    type Target = T;
    type Guard<'a>
        = LocalGuard<'a, T>
    where
        T: 'a;

    fn lock(&self) -> impl Future<Output = LocalGuard<'_, T>> {
        poll_fn(move |context| match self.value.try_borrow_mut() {
            Ok(value) => Poll::Ready(LocalGuard {
                value,
                _wake: WakeOnDrop(&self.waiting),
            }),
            Err(_) => {
                if let Some(previous) = self.waiting.replace(Some(context.waker().clone())) {
                    if !previous.will_wake(context.waker()) {
                        // only one waker fits, so the previous task polls again and re-registers
                        previous.wake();
                    }
                }
                Poll::Pending
            }
        })
    }
}

/// Exclusive access to the value of a [`LocalMutex`].
pub struct LocalGuard<'a, T> {
    value: RefMut<'a, T>,
    // Declared after `value`, so the waiting task is woken once the value is free.
    _wake: WakeOnDrop<'a>,
}

impl<T> Deref for LocalGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> DerefMut for LocalGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

async fn yield_now() {
    let mut yielded = false;
    poll_fn(|context| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            context.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await
}

struct WakeOnDrop<'a>(&'a Cell<Option<Waker>>);

impl Drop for WakeOnDrop<'_> {
    fn drop(&mut self) {
        if let Some(waker) = self.0.take() {
            waker.wake();
        }
    }
}

/// The parts of a connection that its [`Reader`] and [`Writer`] both use: the stream frames are
/// written to, the write buffer, the websocket and the [`FramerState`].
///
/// Put it into a [`Lock`] and create both halves from that lock.
pub struct Shared<'a, W, TRng, TWebSocketType>
where
    TRng: Rng,
    TWebSocketType: WebSocketType,
{
    stream: W,
    state: &'a mut FramerState,
    write_buf: &'a mut [u8],
    websocket: &'a mut WebSocket<TRng, TWebSocketType>,
}

impl<'a, W, TRng, TWebSocketType> Shared<'a, W, TRng, TWebSocketType>
where
    W: Write,
    TRng: Rng,
    TWebSocketType: WebSocketType,
{
    /// Creates the shared parts from the write half of a stream and the `state`, `write_buf` and
    /// `websocket` of a [`Framer`](super::Framer) that completed the opening handshake.
    ///
    /// `write_buf` must fit any control frame (up to 131 bytes).
    pub fn new(
        stream: W,
        state: &'a mut FramerState,
        write_buf: &'a mut [u8],
        websocket: &'a mut WebSocket<TRng, TWebSocketType>,
    ) -> Self {
        Self {
            stream,
            state,
            write_buf,
            websocket,
        }
    }

    /// Returns the state of the connection, for example to check
    /// [`FramerState::awaiting_pong`].
    pub fn state(&self) -> &FramerState {
        self.state
    }

    fn parts<'b>(
        &'b mut self,
        read_buf: &'b mut [u8],
    ) -> (FramerCore<'b, TRng, TWebSocketType>, &'b mut W) {
        (
            FramerCore::new(read_buf, self.state, self.write_buf, self.websocket),
            &mut self.stream,
        )
    }
}

/// Reads websocket messages while a [`Writer`] of the same connection writes.
///
/// Answers pings and close handshakes through the shared write side. It holds the lock while it
/// decodes frames and sends these answers, never while it waits for the stream.
///
/// # Cancel safety
///
/// The methods are cancel safe if the `read` and `write` methods of the streams are. Keep the
/// reader after a cancelled call: it holds bytes the stream returned until the next call.
pub struct Reader<'a, R, L> {
    read_buf: &'a mut [u8],
    received: usize,
    stream: R,
    shared: &'a L,
}

impl<'a, 's, R, L, W, TRng, TWebSocketType> Reader<'a, R, L>
where
    R: Read<Error = W::Error>,
    W: Write + 's,
    L: Lock<Target = Shared<'s, W, TRng, TWebSocketType>>,
    TRng: Rng + 's,
    TWebSocketType: WebSocketType + 's,
{
    /// Creates a reader from the read half of a stream.
    ///
    /// Pass the `read_buf` of the [`Framer`](super::Framer) that completed the opening
    /// handshake: it may already hold the first frames of the other party.
    pub fn new(read_buf: &'a mut [u8], stream: R, shared: &'a L) -> Self {
        Self {
            read_buf,
            received: 0,
            stream,
            shared,
        }
    }

    /// Reads from the stream until a whole message arrived, see
    /// [`Framer::read`](super::Framer::read).
    ///
    /// # Errors
    ///
    /// The errors of [`Framer::read`](super::Framer::read).
    pub async fn read<'b>(
        &mut self,
        frame_buf: &'b mut [u8],
    ) -> Result<ReadResult<'b>, FramerError<R::Error>> {
        self.read_message(frame_buf, ReadMode::WholeMessages)
            .await?
            .into_read_result(frame_buf)
    }

    /// Reads from the stream until the next chunk of a message arrived, see
    /// [`Framer::read_chunk`](super::Framer::read_chunk).
    ///
    /// # Errors
    ///
    /// The errors of [`Framer::read_chunk`](super::Framer::read_chunk).
    pub async fn read_chunk<'b>(
        &mut self,
        frame_buf: &'b mut [u8],
    ) -> Result<ReadChunk<'b>, FramerError<R::Error>> {
        self.read_message(frame_buf, ReadMode::Chunks)
            .await?
            .into_read_chunk(frame_buf)
    }

    async fn read_message(
        &mut self,
        frame_buf: &mut [u8],
        mode: ReadMode,
    ) -> Result<Message, FramerError<R::Error>> {
        loop {
            let read_start = {
                let mut guard = self.shared.lock().await;
                let (mut core, stream) = guard.parts(self.read_buf);
                core.commit_read(core::mem::take(&mut self.received));
                send_unsent(&mut core, stream).await?;
                if core.has_pending() {
                    return core.finish();
                }
                loop {
                    match core.decode(frame_buf, mode)? {
                        Decoded::NeedMoreData => break core.read_space_start()?,
                        Decoded::SendThenContinue(len) => send(&mut core, stream, len).await?,
                        Decoded::SendThenFinish(len) => {
                            send(&mut core, stream, len).await?;
                            return core.finish();
                        }
                        Decoded::Message(message) => return Ok(message),
                    }
                }
            };
            let len = self
                .stream
                .read(&mut self.read_buf[read_start..])
                .await
                .map_err(FramerError::Io)?;
            if len == 0 {
                return Ok(Message::Disconnected);
            }
            self.received = len;
        }
    }
}

/// Writes websocket messages while a [`Reader`] of the same connection reads.
///
/// Takes the lock for one frame at a time, so the reader can answer a ping between the frames
/// of a long message.
///
/// # Cancel safety
///
/// The methods are cancel safe if the `write` method of the stream is, with the same rules for
/// resuming as [`Framer::write`](super::Framer::write).
pub struct Writer<'a, L> {
    shared: &'a L,
}

impl<'a, 's, L, W, TRng, TWebSocketType> Writer<'a, L>
where
    W: Write + 's,
    L: Lock<Target = Shared<'s, W, TRng, TWebSocketType>>,
    TRng: Rng + 's,
    TWebSocketType: WebSocketType + 's,
{
    /// Creates a writer.
    pub fn new(shared: &'a L) -> Self {
        Self { shared }
    }

    /// Writes `frame_buf` to the stream, see [`Framer::write`](super::Framer::write).
    ///
    /// # Errors
    ///
    /// The errors of [`Framer::write`](super::Framer::write).
    pub async fn write(
        &mut self,
        message_type: WebSocketSendMessageType,
        end_of_message: bool,
        frame_buf: &[u8],
    ) -> Result<(), FramerError<W::Error>> {
        let is_data = matches!(
            message_type,
            WebSocketSendMessageType::Text | WebSocketSendMessageType::Binary
        );
        loop {
            {
                let mut guard = self.shared.lock().await;
                let (mut core, stream) = guard.parts(&mut []);
                send_unsent(&mut core, stream).await?;
                if !is_data {
                    let len = core.encode_write(message_type, end_of_message, frame_buf)?;
                    return send(&mut core, stream, len).await;
                }
                let Some(len) = core.encode_next_frame(message_type, end_of_message, frame_buf)?
                else {
                    return Ok(());
                };
                send(&mut core, stream, len).await?;
                if core.all_frames_queued() {
                    core.encode_next_frame(message_type, end_of_message, frame_buf)?;
                    return Ok(());
                }
            }
            // gives a reader that waits for the lock a chance to take it before the next frame
            yield_now().await;
        }
    }

    /// Sends a keepalive ping, see [`FramerState::awaiting_pong`] and
    /// [`Shared::state`].
    ///
    /// # Errors
    ///
    /// * [`FramerError::Io`] if writing to the stream fails.
    /// * [`FramerError::WebSocket`] if the websocket is not open or the write buffer cannot fit a
    ///   ping frame.
    pub async fn ping(&mut self) -> Result<(), FramerError<W::Error>> {
        let mut guard = self.shared.lock().await;
        let (mut core, stream) = guard.parts(&mut []);
        send_unsent(&mut core, stream).await?;
        let len = core.encode_keepalive_ping()?;
        send(&mut core, stream, len).await
    }

    /// Initiates a close handshake, see [`Framer::close`](super::Framer::close).
    ///
    /// The [`Reader`] returns [`ReadResult::Closed`] once the other party completed it.
    ///
    /// # Errors
    ///
    /// The errors of [`Framer::close`](super::Framer::close).
    pub async fn close(
        &mut self,
        close_status: WebSocketCloseStatusCode,
        status_description: Option<&str>,
    ) -> Result<(), FramerError<W::Error>> {
        let mut guard = self.shared.lock().await;
        let (mut core, stream) = guard.parts(&mut []);
        send_unsent(&mut core, stream).await?;
        let len = core.encode_close(close_status, status_description)?;
        send(&mut core, stream, len).await
    }
}
