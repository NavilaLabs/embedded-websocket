// The MIT License (MIT)
// Copyright (c) 2019 David Haig

// Demo websocket client connecting to localhost port 1337 using the async framer.
// Any stream implementing the embedded-io-async traits works the same way, for example the
// TcpSocket of embassy-net. Here a tokio TcpStream is wrapped with embedded-io-adapters.
// Run with: cargo run --example client_async --features asynch

use embedded_io_adapters::tokio_1::FromTokio;
use embedded_io_websocket::{
    asynch::Framer, FramerError, FramerState, ReadResult, WebSocketClient,
    WebSocketCloseStatusCode, WebSocketOptions, WebSocketSendMessageType,
};
use std::error::Error;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), FramerError<impl Error>> {
    let address = "127.0.0.1:1337";
    println!("Connecting to: {}", address);
    let stream = TcpStream::connect(address).await.map_err(FramerError::Io)?;
    let mut stream = FromTokio::new(stream);
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
    framer.connect(&mut stream, &websocket_options).await?;

    let message = "Hello, World!";
    framer
        .write(
            &mut stream,
            WebSocketSendMessageType::Text,
            true,
            message.as_bytes(),
        )
        .await?;

    loop {
        match framer.read(&mut stream, &mut frame_buf).await? {
            ReadResult::Text(text) => {
                println!("Received: {}", text);

                // close the websocket after receiving the first reply
                framer
                    .close(
                        &mut stream,
                        WebSocketCloseStatusCode::NormalClosure,
                        Some("Done chatting"),
                    )
                    .await?;
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
