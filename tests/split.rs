//! Tests for the read and write halves of the async framer, polled concurrently on one thread.
#![cfg(feature = "asynch")]

use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use std::{cell::RefCell, collections::VecDeque, rc::Rc};

use embedded_io_websocket::{
    asynch::{LocalMutex, Lock, Reader, Shared, Writer},
    FramerState, ReadResult, WebSocketClient, WebSocketReceiveMessageType,
    WebSocketSendMessageType, WebSocketServer, WebSocketState,
};
use proptest::prelude::*;

#[derive(Debug)]
struct Never;

impl core::fmt::Display for Never {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("never")
    }
}

impl core::error::Error for Never {}

impl embedded_io::Error for Never {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

/// Returns `Pending` on the first poll.
struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: core::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            Poll::Pending
        }
    }
}

/// Yields before the calls the pattern marks, and splits reads and writes into its lengths.
#[derive(Clone)]
struct Pacing {
    lens: Vec<usize>,
    yields: Vec<bool>,
    calls: usize,
}

impl Pacing {
    fn steady() -> Self {
        Self {
            lens: vec![usize::MAX],
            yields: vec![false],
            calls: 0,
        }
    }

    async fn next_len(&mut self) -> usize {
        let index = self.calls;
        self.calls += 1;
        if self.yields[index % self.yields.len()] {
            YieldOnce(false).await;
        }
        self.lens[index % self.lens.len()]
    }
}

/// Bytes the other party sent. Waits forever once they are read, unless `ends` is set.
struct Incoming {
    unread: VecDeque<u8>,
    pacing: Pacing,
    ends: bool,
}

impl embedded_io::ErrorType for Incoming {
    type Error = Never;
}

impl embedded_io_async::Read for Incoming {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Never> {
        let len = self.pacing.next_len().await;
        if self.unread.is_empty() && !self.ends {
            core::future::pending::<()>().await;
        }
        let len = len.min(buf.len()).min(self.unread.len());
        for (to, from) in buf.iter_mut().zip(self.unread.drain(..len)) {
            *to = from;
        }
        Ok(len)
    }
}

/// Collects what the framer sends.
struct Outgoing {
    written: Rc<RefCell<Vec<u8>>>,
    pacing: Pacing,
}

impl embedded_io::ErrorType for Outgoing {
    type Error = Never;
}

impl embedded_io_async::Write for Outgoing {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Never> {
        let len = self.pacing.next_len().await.min(buf.len());
        self.written.borrow_mut().extend_from_slice(&buf[..len]);
        Ok(len)
    }

    async fn flush(&mut self) -> Result<(), Never> {
        Ok(())
    }
}

fn client_frames(frames: &[(WebSocketSendMessageType, bool, &[u8])]) -> Vec<u8> {
    let mut ws_client = WebSocketClient::new_client(rand::rng());
    ws_client.state = WebSocketState::Open;
    let mut encoded = Vec::new();
    let mut frame = vec![0; 8192];
    for (message_type, end_of_message, payload) in frames {
        let len = ws_client
            .write(*message_type, *end_of_message, payload, &mut frame)
            .unwrap();
        encoded.extend_from_slice(&frame[..len]);
    }
    encoded
}

#[derive(Debug, Default, PartialEq)]
struct Sent {
    messages: Vec<(WebSocketReceiveMessageType, Vec<u8>)>,
    pongs: Vec<Vec<u8>>,
}

/// Decodes the frames a server sent.
fn sent(written: &[u8]) -> Sent {
    let mut ws_client = WebSocketClient::new_client(rand::rng());
    ws_client.state = WebSocketState::Open;
    let mut sent = Sent::default();
    let mut message = Vec::new();
    let mut payload = vec![0; 70000];
    let mut from = written;
    while !from.is_empty() {
        let result = ws_client.read(from, &mut payload).unwrap();
        assert!(result.len_from > 0, "incomplete frame in {written:x?}");
        let data = &payload[..result.len_to];
        match result.message_type {
            WebSocketReceiveMessageType::Pong => sent.pongs.push(data.to_vec()),
            WebSocketReceiveMessageType::Text | WebSocketReceiveMessageType::Binary => {
                message.extend_from_slice(data);
                if result.end_of_message {
                    sent.messages
                        .push((result.message_type, core::mem::take(&mut message)));
                }
            }
            other => panic!("unexpected {other:?}"),
        }
        from = &from[result.len_from..];
    }
    sent
}

fn poll<F: Future>(future: core::pin::Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn open_server() -> WebSocketServer {
    let mut ws_server = WebSocketServer::new_server();
    ws_server.state = WebSocketState::Open;
    ws_server
}

#[test]
fn reader_answers_a_ping_through_the_shared_write_side() {
    let written = Rc::new(RefCell::new(Vec::new()));
    let outgoing = Outgoing {
        written: written.clone(),
        pacing: Pacing::steady(),
    };
    let incoming = Incoming {
        unread: client_frames(&[
            (WebSocketSendMessageType::Ping, true, b"are you there"),
            (WebSocketSendMessageType::Text, true, b"hello"),
        ])
        .into(),
        pacing: Pacing::steady(),
        ends: true,
    };
    let (mut read_buf, mut write_buf, mut frame_buf) = (vec![0; 256], vec![0; 256], vec![0; 256]);
    let mut state = FramerState::new();
    let mut ws_server = open_server();
    let shared = LocalMutex::new(Shared::new(
        outgoing,
        &mut state,
        &mut write_buf,
        &mut ws_server,
    ));
    let mut reader = Reader::new(&mut read_buf, incoming, &shared);

    let read = pin!(reader.read(&mut frame_buf));
    match poll(read) {
        Poll::Ready(Ok(ReadResult::Text(text))) => assert_eq!(text, "hello"),
        _ => panic!("expected the text message"),
    }

    assert_eq!(sent(&written.borrow()).pongs, [b"are you there".to_vec()]);
}

#[test]
fn writer_writes_while_the_reader_waits_for_data() {
    let written = Rc::new(RefCell::new(Vec::new()));
    let outgoing = Outgoing {
        written: written.clone(),
        pacing: Pacing::steady(),
    };
    let incoming = Incoming {
        unread: VecDeque::new(),
        pacing: Pacing::steady(),
        ends: false,
    };
    let (mut read_buf, mut write_buf, mut frame_buf) = (vec![0; 256], vec![0; 256], vec![0; 256]);
    let mut state = FramerState::new();
    let mut ws_server = open_server();
    let shared = LocalMutex::new(Shared::new(
        outgoing,
        &mut state,
        &mut write_buf,
        &mut ws_server,
    ));
    let mut reader = Reader::new(&mut read_buf, incoming, &shared);
    let mut writer = Writer::new(&shared);

    let mut read = pin!(reader.read(&mut frame_buf));
    assert!(poll(read.as_mut()).is_pending());
    let write = pin!(writer.write(WebSocketSendMessageType::Text, true, b"hi"));
    assert!(matches!(poll(write), Poll::Ready(Ok(()))));
    assert!(poll(read).is_pending());

    assert_eq!(
        sent(&written.borrow()).messages,
        [(WebSocketReceiveMessageType::Text, b"hi".to_vec())]
    );
}

/// The type of every frame a server sent.
fn frame_types(written: &[u8]) -> Vec<WebSocketReceiveMessageType> {
    let mut ws_client = WebSocketClient::new_client(rand::rng());
    ws_client.state = WebSocketState::Open;
    let mut payload = vec![0; 70000];
    let mut types = Vec::new();
    let mut from = written;
    while !from.is_empty() {
        let result = ws_client.read(from, &mut payload).unwrap();
        types.push(result.message_type);
        from = &from[result.len_from..];
    }
    types
}

#[test]
fn pong_goes_out_between_the_frames_of_a_long_message() {
    let written = Rc::new(RefCell::new(Vec::new()));
    let outgoing = Outgoing {
        written: written.clone(),
        pacing: Pacing {
            lens: vec![usize::MAX],
            yields: vec![true],
            calls: 0,
        },
    };
    let incoming = Incoming {
        unread: client_frames(&[(WebSocketSendMessageType::Ping, true, b"ping")]).into(),
        pacing: Pacing::steady(),
        ends: false,
    };
    let (mut read_buf, mut frame_buf) = (vec![0; 256], vec![0; 256]);
    let mut write_buf = vec![0; 140];
    let mut state = FramerState::new();
    let mut ws_server = open_server();
    let shared = LocalMutex::new(Shared::new(
        outgoing,
        &mut state,
        &mut write_buf,
        &mut ws_server,
    ));
    let mut reader = Reader::new(&mut read_buf, incoming, &shared);
    let mut writer = Writer::new(&shared);

    let message = vec![7; 1000];
    let mut write = pin!(writer.write(WebSocketSendMessageType::Binary, true, &message));
    let mut read = pin!(reader.read(&mut frame_buf));
    assert!(poll(write.as_mut()).is_pending());
    let mut write_done = false;
    for _ in 0..1000 {
        assert!(poll(read.as_mut()).is_pending());
        write_done = write_done || poll(write.as_mut()).is_ready();
    }
    assert!(write_done);

    let types = frame_types(&written.borrow());
    let pong = types
        .iter()
        .position(|t| *t == WebSocketReceiveMessageType::Pong)
        .expect("a pong");
    assert!(
        pong < types.len() - 1,
        "pong after the whole message: {types:?}"
    );
}

#[derive(Debug, Clone)]
struct Concurrent {
    pings: Vec<Vec<u8>>,
    messages: Vec<Vec<u8>>,
    write_buf_len: usize,
    read_pacing: (Vec<usize>, Vec<bool>),
    write_pacing: (Vec<usize>, Vec<bool>),
}

fn pacing() -> impl Strategy<Value = (Vec<usize>, Vec<bool>)> {
    (
        prop::collection::vec(1usize..200, 1..10),
        prop::collection::vec(prop::bool::weighted(0.4), 1..10),
    )
}

fn concurrent() -> impl Strategy<Value = Concurrent> {
    (
        prop::collection::vec(prop::collection::vec(any::<u8>(), 0..=125), 0..8),
        prop::collection::vec(prop::collection::vec(any::<u8>(), 0..1500), 1..5),
        140usize..400,
        pacing(),
        pacing(),
    )
        .prop_map(
            |(pings, messages, write_buf_len, read_pacing, write_pacing)| Concurrent {
                pings,
                messages,
                write_buf_len,
                read_pacing,
                write_pacing,
            },
        )
}

fn pacing_of((lens, yields): &(Vec<usize>, Vec<bool>)) -> Pacing {
    Pacing {
        lens: lens.clone(),
        yields: yields.clone(),
        calls: 0,
    }
}

proptest! {
    #[test]
    fn pongs_and_messages_interleave_as_whole_frames(concurrent in concurrent()) {
        let written = Rc::new(RefCell::new(Vec::new()));
        let outgoing = Outgoing {
            written: written.clone(),
            pacing: pacing_of(&concurrent.write_pacing),
        };
        let pings: Vec<_> = concurrent
            .pings
            .iter()
            .map(|ping| (WebSocketSendMessageType::Ping, true, &ping[..]))
            .collect();
        let incoming = Incoming {
            unread: client_frames(&pings).into(),
            pacing: pacing_of(&concurrent.read_pacing),
            ends: true,
        };
        let (mut read_buf, mut frame_buf) = (vec![0; 256], vec![0; 256]);
        let mut write_buf = vec![0; concurrent.write_buf_len];
        let mut state = FramerState::new();
        let mut ws_server = open_server();
        let shared = LocalMutex::new(Shared::new(
            outgoing,
            &mut state,
            &mut write_buf,
            &mut ws_server,
        ));
        let mut reader = Reader::new(&mut read_buf, incoming, &shared);
        let mut writer = Writer::new(&shared);

        // pings are answered inside `read`, so the only result is the end of the stream
        let mut read_all = pin!(async {
            match reader.read(&mut frame_buf).await {
                Ok(ReadResult::Disconnected) => {}
                Ok(_) => panic!("the client sends only pings"),
                Err(error) => panic!("read failed: {error:?}"),
            }
        });
        let mut write_all = pin!(async {
            for message in &concurrent.messages {
                writer
                    .write(WebSocketSendMessageType::Binary, true, message)
                    .await
                    .unwrap();
            }
        });
        let (mut read_done, mut write_done) = (false, false);
        for _ in 0..1_000_000 {
            read_done = read_done || poll(read_all.as_mut()).is_ready();
            write_done = write_done || poll(write_all.as_mut()).is_ready();
            if read_done && write_done {
                break;
            }
        }
        prop_assert!(read_done && write_done, "the halves block each other");

        let sent = sent(&written.borrow());
        prop_assert_eq!(sent.pongs, concurrent.pings.clone());
        let expected: Vec<_> = concurrent
            .messages
            .iter()
            .map(|message| (WebSocketReceiveMessageType::Binary, message.clone()))
            .collect();
        prop_assert_eq!(sent.messages, expected);
    }
}

#[test]
fn reader_keeps_received_bytes_when_cancelled_while_waiting_for_the_lock() {
    let outgoing = Outgoing {
        written: Rc::new(RefCell::new(Vec::new())),
        pacing: Pacing::steady(),
    };
    let incoming = Incoming {
        unread: client_frames(&[(WebSocketSendMessageType::Text, true, b"hello")]).into(),
        pacing: Pacing {
            lens: vec![usize::MAX],
            yields: vec![true],
            calls: 0,
        },
        ends: false,
    };
    let (mut read_buf, mut write_buf, mut frame_buf) = (vec![0; 256], vec![0; 256], vec![0; 256]);
    let mut state = FramerState::new();
    let mut ws_server = open_server();
    let shared = LocalMutex::new(Shared::new(
        outgoing,
        &mut state,
        &mut write_buf,
        &mut ws_server,
    ));
    let mut reader = Reader::new(&mut read_buf, incoming, &shared);

    {
        let mut read = pin!(reader.read(&mut frame_buf));
        assert!(poll(read.as_mut()).is_pending(), "waits for the stream");
        let Poll::Ready(guard) = poll(pin!(shared.lock())) else {
            panic!("the lock is free while the reader waits for the stream");
        };
        assert!(poll(read.as_mut()).is_pending(), "waits for the lock");
        drop(guard);
    }

    match poll(pin!(reader.read(&mut frame_buf))) {
        Poll::Ready(Ok(ReadResult::Text(text))) => assert_eq!(text, "hello"),
        _ => panic!("expected the text message"),
    };
}

#[test]
fn local_mutex_wakes_the_waiting_task_on_unlock() {
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        task::Wake,
    };

    struct CountingWaker(AtomicUsize);

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let mutex = LocalMutex::new(0);
    let counter = Arc::new(CountingWaker(AtomicUsize::new(0)));
    let waker = Waker::from(counter.clone());
    let Poll::Ready(guard) = poll(pin!(mutex.lock())) else {
        panic!("the mutex is free");
    };
    let mut waiting = pin!(mutex.lock());
    assert!(waiting
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
        .is_pending());
    assert_eq!(counter.0.load(Ordering::SeqCst), 0);

    drop(guard);

    assert_eq!(counter.0.load(Ordering::SeqCst), 1);
    assert!(poll(waiting).is_ready());
}
