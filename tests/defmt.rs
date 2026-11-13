//! Checks that the types a firmware logs implement `defmt::Format`.
#![cfg(feature = "defmt")]

use embedded_io_websocket::{
    Error, FramerError, ReadChunk, ReadResult, WebSocketCloseStatusCode, WebSocketReadResult,
    WebSocketReceiveMessageType, WebSocketSendMessageType, WebSocketState,
};

fn implements_format<T: defmt::Format>() {}

#[test]
fn loggable_types_implement_format() {
    implements_format::<Error>();
    implements_format::<FramerError<embedded_io::ErrorKind>>();
    implements_format::<ReadResult<'static>>();
    implements_format::<ReadChunk<'static>>();
    implements_format::<WebSocketCloseStatusCode>();
    implements_format::<WebSocketReadResult>();
    implements_format::<WebSocketReceiveMessageType>();
    implements_format::<WebSocketSendMessageType>();
    implements_format::<WebSocketState>();
}
