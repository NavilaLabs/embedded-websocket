//! Property tests that feed the framers random messages over streams that split, delay and
//! interrupt reads and writes at random points.

use std::collections::VecDeque;

use embedded_io_websocket::{
    blocking, FramerError, FramerState, ReadResult, WebSocketClient, WebSocketCloseStatusCode,
    WebSocketReceiveMessageType, WebSocketSendMessageType, WebSocketServer, WebSocketState,
};
use proptest::prelude::*;

#[derive(Debug, Clone, PartialEq)]
enum Message {
    Text(String),
    Binary(Vec<u8>),
}

impl Message {
    fn payload(&self) -> &[u8] {
        match self {
            Message::Text(text) => text.as_bytes(),
            Message::Binary(binary) => binary,
        }
    }

    fn message_type(&self) -> WebSocketSendMessageType {
        match self {
            Message::Text(_) => WebSocketSendMessageType::Text,
            Message::Binary(_) => WebSocketSendMessageType::Binary,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum End {
    Closed(u16, String),
    Disconnected,
}

#[derive(Debug, Clone)]
struct Fragment {
    len_percent: usize,
    ping_before: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct Conversation {
    messages: Vec<(Message, Vec<Fragment>)>,
    close: Option<(u16, String)>,
    read_buf_len: usize,
    read_lens: Vec<usize>,
    write_lens: Vec<usize>,
    interruptions: Vec<bool>,
}

impl Conversation {
    fn encoded(&self) -> Vec<u8> {
        let mut ws_client = WebSocketClient::new_client(rand::rng());
        ws_client.state = WebSocketState::Open;
        let mut encoded = Vec::new();
        let mut frame = vec![0; 8192];
        for (message, fragments) in &self.messages {
            let payload = message.payload();
            let mut start = 0;
            for (index, fragment) in fragments.iter().enumerate() {
                if let Some(ping) = &fragment.ping_before {
                    let len = ws_client
                        .write(WebSocketSendMessageType::Ping, true, ping, &mut frame)
                        .unwrap();
                    encoded.extend_from_slice(&frame[..len]);
                }
                let is_last = index == fragments.len() - 1;
                let end = if is_last {
                    payload.len()
                } else {
                    (start + payload.len() * fragment.len_percent / 100).min(payload.len())
                };
                let len = ws_client
                    .write(
                        message.message_type(),
                        is_last,
                        &payload[start..end],
                        &mut frame,
                    )
                    .unwrap();
                encoded.extend_from_slice(&frame[..len]);
                start = end;
            }
        }
        if let Some((status, reason)) = &self.close {
            let payload = [&status.to_be_bytes()[..], reason.as_bytes()].concat();
            let len = ws_client
                .write(
                    WebSocketSendMessageType::CloseReply,
                    true,
                    &payload,
                    &mut frame,
                )
                .unwrap();
            encoded.extend_from_slice(&frame[..len]);
        }
        encoded
    }

    fn end(&self) -> End {
        match &self.close {
            Some((status, reason)) => End::Closed(*status, reason.clone()),
            None => End::Disconnected,
        }
    }

    fn pings(&self) -> Vec<Vec<u8>> {
        self.messages
            .iter()
            .flat_map(|(_, fragments)| fragments.iter().filter_map(|f| f.ping_before.clone()))
            .collect()
    }

    fn stream(&self) -> ChunkedStream {
        ChunkedStream {
            unread: self.encoded().into(),
            read_lens: self.read_lens.clone(),
            write_lens: self.write_lens.clone(),
            interruptions: self.interruptions.clone(),
            calls: 0,
            interrupted: false,
            written: Vec::new(),
        }
    }
}

fn message() -> impl Strategy<Value = Message> {
    prop_oneof![
        "\\PC{0,600}".prop_map(Message::Text),
        prop::collection::vec(any::<u8>(), 0..2000).prop_map(Message::Binary),
    ]
}

fn fragment() -> impl Strategy<Value = Fragment> {
    (
        0usize..=100,
        prop::option::weighted(0.3, prop::collection::vec(any::<u8>(), 0..=125)),
    )
        .prop_map(|(len_percent, ping_before)| Fragment {
            len_percent,
            ping_before,
        })
}

fn conversation() -> impl Strategy<Value = Conversation> {
    (
        prop::collection::vec((message(), prop::collection::vec(fragment(), 1..4)), 1..6),
        prop::option::of((
            prop::sample::select(vec![1000u16, 1001, 1008, 1011, 3000, 4999]),
            "[a-z ]{0,30}",
        )),
        140usize..512,
        prop::collection::vec(1usize..300, 1..20),
        prop::collection::vec(1usize..300, 1..20),
        prop::collection::vec(prop::bool::weighted(0.2), 1..20),
    )
        .prop_map(
            |(messages, close, read_buf_len, read_lens, write_lens, interruptions)| Conversation {
                messages,
                close,
                read_buf_len,
                read_lens,
                write_lens,
                interruptions,
            },
        )
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

/// Splits reads and writes into the lengths of the conversation and interrupts every call the
/// conversation marks once before it succeeds.
struct ChunkedStream {
    unread: VecDeque<u8>,
    read_lens: Vec<usize>,
    write_lens: Vec<usize>,
    interruptions: Vec<bool>,
    calls: usize,
    interrupted: bool,
    written: Vec<u8>,
}

impl ChunkedStream {
    fn interrupt(&mut self) -> bool {
        if !self.interrupted && self.interruptions[self.calls % self.interruptions.len()] {
            self.interrupted = true;
            return true;
        }
        self.interrupted = false;
        self.calls += 1;
        false
    }

    fn read_now(&mut self, buf: &mut [u8]) -> usize {
        let len = buf
            .len()
            .min(self.unread.len())
            .min(self.read_lens[self.calls % self.read_lens.len()]);
        for (to, from) in buf.iter_mut().zip(self.unread.drain(..len)) {
            *to = from;
        }
        len
    }

    fn write_now(&mut self, buf: &[u8]) -> usize {
        let len = buf
            .len()
            .min(self.write_lens[self.calls % self.write_lens.len()]);
        self.written.extend_from_slice(&buf[..len]);
        len
    }

    fn pongs(&self) -> Vec<Vec<u8>> {
        let mut ws_client = WebSocketClient::new_client(rand::rng());
        ws_client.state = WebSocketState::Open;
        let mut pongs = Vec::new();
        let mut from = &self.written[..];
        let mut payload = vec![0; 256];
        while !from.is_empty() {
            let result = ws_client.read(from, &mut payload).unwrap();
            match result.message_type {
                WebSocketReceiveMessageType::Pong => pongs.push(payload[..result.len_to].to_vec()),
                WebSocketReceiveMessageType::CloseMustReply => {
                    assert_eq!(
                        result.len_from,
                        from.len(),
                        "the close reply is the last frame"
                    );
                }
                other => panic!("unexpected {other:?}"),
            }
            from = &from[result.len_from..];
        }
        pongs
    }
}

impl embedded_io::ErrorType for ChunkedStream {
    type Error = Interrupted;
}

impl embedded_io::Read for ChunkedStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Interrupted> {
        if self.interrupt() {
            return Err(Interrupted);
        }
        Ok(self.read_now(buf))
    }
}

impl embedded_io::Write for ChunkedStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Interrupted> {
        if self.interrupt() {
            return Err(Interrupted);
        }
        Ok(self.write_now(buf))
    }

    fn flush(&mut self) -> Result<(), Interrupted> {
        Ok(())
    }
}

fn received(result: ReadResult<'_>) -> Result<Message, End> {
    match result {
        ReadResult::Text(text) => Ok(Message::Text(text.to_owned())),
        ReadResult::Binary(binary) => Ok(Message::Binary(binary.to_vec())),
        ReadResult::Pong(_) => panic!("the client sends no pongs"),
        ReadResult::Closed { status, reason } => {
            Err(End::Closed(status_code(status), reason.to_owned()))
        }
        ReadResult::Disconnected => Err(End::Disconnected),
    }
}

fn status_code(status: WebSocketCloseStatusCode) -> u16 {
    match status {
        WebSocketCloseStatusCode::NormalClosure => 1000,
        WebSocketCloseStatusCode::EndpointUnavailable => 1001,
        WebSocketCloseStatusCode::PolicyViolation => 1008,
        WebSocketCloseStatusCode::InternalServerError => 1011,
        WebSocketCloseStatusCode::Custom(code) => code,
        other => panic!("unexpected {other:?}"),
    }
}

fn expected(conversation: &Conversation) -> Vec<Message> {
    conversation
        .messages
        .iter()
        .map(|(message, _)| message.clone())
        .collect()
}

proptest! {
    #[test]
    fn blocking_framer_survives_split_and_interrupted_io(conversation in conversation()) {
        let mut stream = conversation.stream();
        let mut read_buf = vec![0; conversation.read_buf_len];
        let mut write_buf = vec![0; 256];
        let mut frame_buf = vec![0; 4096];
        let mut state = FramerState::new();
        let mut ws_server = WebSocketServer::new_server();
        ws_server.state = WebSocketState::Open;

        let mut messages = Vec::new();
        let end = loop {
            let mut framer =
                blocking::Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
            match framer.read(&mut stream, &mut frame_buf) {
                Ok(result) => match received(result) {
                    Ok(message) => messages.push(message),
                    Err(end) => break end,
                },
                Err(FramerError::Io(Interrupted)) => {}
                Err(error) => panic!("read failed: {error:?}"),
            }
        };

        prop_assert_eq!(messages, expected(&conversation));
        prop_assert_eq!(end, conversation.end());
        prop_assert_eq!(stream.pongs(), conversation.pings());
    }
}

#[cfg(feature = "asynch")]
mod asynch {
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    use embedded_io_websocket::asynch::Framer;

    use super::*;

    /// Returns `Pending` on the first poll, so a caller that polls once cancels the operation.
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

    impl embedded_io_async::Read for ChunkedStream {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Interrupted> {
            if self.interrupt() {
                YieldOnce(false).await;
            }
            Ok(self.read_now(buf))
        }
    }

    impl embedded_io_async::Write for ChunkedStream {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Interrupted> {
            if self.interrupt() {
                YieldOnce(false).await;
            }
            Ok(self.write_now(buf))
        }

        async fn flush(&mut self) -> Result<(), Interrupted> {
            Ok(())
        }
    }

    fn poll_once<F: Future>(future: F) -> Poll<F::Output> {
        pin!(future).poll(&mut Context::from_waker(Waker::noop()))
    }

    proptest! {
        #[test]
        fn async_framer_survives_split_and_cancelled_io(conversation in conversation()) {
            let mut stream = conversation.stream();
            let mut read_buf = vec![0; conversation.read_buf_len];
            let mut write_buf = vec![0; 256];
            let mut frame_buf = vec![0; 4096];
            let mut state = FramerState::new();
            let mut ws_server = WebSocketServer::new_server();
            ws_server.state = WebSocketState::Open;

            let mut messages = Vec::new();
            let end = loop {
                let mut framer =
                    Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_server);
                match poll_once(framer.read(&mut stream, &mut frame_buf)) {
                    Poll::Ready(Ok(result)) => match received(result) {
                        Ok(message) => messages.push(message),
                        Err(end) => break end,
                    },
                    Poll::Ready(Err(error)) => panic!("read failed: {error:?}"),
                    Poll::Pending => {}
                }
            };

            prop_assert_eq!(messages, expected(&conversation));
            prop_assert_eq!(end, conversation.end());
            prop_assert_eq!(stream.pongs(), conversation.pings());
        }
    }
}
