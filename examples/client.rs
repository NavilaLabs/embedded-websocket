// The MIT License (MIT)
// Copyright (c) 2019 David Haig

// Demo websocket client connecting to localhost port 1337 using the blocking framer.
// Any stream implementing the embedded-io traits works the same way. Here a std TcpStream is
// wrapped with embedded-io-adapters.
// Run with: cargo run --example client

use embedded_io_adapters::std::FromStd;
use embedded_io_websocket::{
    blocking::Framer, FramerError, FramerState, ReadResult, WebSocketClient,
    WebSocketCloseStatusCode, WebSocketOptions, WebSocketSendMessageType,
};
use std::error::Error;
use std::net::TcpStream;

fn main() -> Result<(), FramerError<impl Error>> {
    let address = "127.0.0.1:1337";
    println!("Connecting to: {}", address);
    let stream = TcpStream::connect(address).map_err(FramerError::Io)?;
    let mut stream = FromStd::new(stream);
    println!("Connected.");

    let mut read_buf = [0; 4000];
    let mut state = FramerState::default();
    let mut write_buf = [0; 4000];
    let mut frame_buf = [0; 4000];
    let mut websocket = WebSocketClient::new_client(rand::rng());

    let websocket_options = WebSocketOptions {
        path: "/chat",
        host: "localhost",
        origin: "http://localhost:1337",
        sub_protocols: None,
        additional_headers: None,
    };

    let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut websocket);
    framer.connect(&mut stream, &websocket_options)?;

    let message = "Hello, World!";
    framer.write(
        &mut stream,
        WebSocketSendMessageType::Text,
        true,
        message.as_bytes(),
    )?;

    loop {
        match framer.read(&mut stream, &mut frame_buf)? {
            ReadResult::Text(text) => {
                println!("Received: {}", text);

                // close the websocket after receiving the first reply
                framer.close(
                    &mut stream,
                    WebSocketCloseStatusCode::NormalClosure,
                    Some("Done chatting"),
                )?;
                println!("Sent close handshake");
            }
            ReadResult::Closed { status, reason } => {
                println!("Connection closed: {status:?} {reason:?}");
                break;
            }
            ReadResult::Disconnected => {
                println!("Connection dropped before the close handshake");
                break;
            }
            ReadResult::Binary(_) | ReadResult::Pong(_) => {}
        }
    }
    Ok(())
}
