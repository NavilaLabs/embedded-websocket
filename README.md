# embedded-io-websocket
A lightweight rust websocket library for embedded systems `no_std`, with blocking and async framers for [embedded-io](https://crates.io/crates/embedded-io) streams.

This crate started as a fork of [embedded-websocket](https://github.com/ninjasource/embedded-websocket) by David Haig.

This library facilitates the encoding and decoding of websocket messages and can be used for both clients and servers. The library is intended to be used in constrained memory environments like embedded microcontrollers which cannot reference the rust standard library. The library will work with arbitrarily small buffers regardless of websocket frame size as long as the websocket header can be read (2 - 14 bytes depending)

## no_std support

The library is `no_std` by default. The `std` feature only adds `std::error::Error` implementations.

## Framers

The framers let you work with whole websocket messages without dealing with fragmented data:

* `blocking::Framer` works with any stream that implements the [embedded-io](https://crates.io/crates/embedded-io) traits.
* `asynch::Framer` works with any stream that implements the [embedded-io-async](https://crates.io/crates/embedded-io-async) traits, for example the `TcpSocket` of [embassy-net](https://crates.io/crates/embassy-net). It needs the `asynch` feature.

Both have the same API. They split messages that do not fit into the write buffer into several frames, and a read or write that fails or is cancelled can be called again to continue where it stopped.

```
embedded-io-websocket = { version = "x.x.x", features = ["asynch"] }
```

To use a `std` or `tokio` stream, wrap it with `FromStd` or `FromTokio` from [embedded-io-adapters](https://crates.io/crates/embedded-io-adapters).

Without a framer, `WebSocketClient` and `WebSocketServer` encode and decode frames on byte slices, so you can use any transport.

## Running the examples

The server accepts client connections in a loop and echoes back whatever text a client sends. The client connects to the server, sends one "Hello, World!" message, waits for the response, then closes the connection. Proper open and close handshakes are demonstrated.

To run the demo web server with the blocking or the async framer:

```
cargo run --example server
cargo run --example server_async --features asynch
```

To run the demo websocket client:

```
cargo run --example client
cargo run --example client_async --features asynch
```

or open `http://127.0.0.1:1337/` in your browser.

## Example websocket client usage

The following example, also found [here](./examples/client.rs), performs the opening handshake, sends a short message, initiates a close handshake and waits for the server to complete it.

```rust
let stream = TcpStream::connect("127.0.0.1:1337").map_err(FramerError::Io)?;
let mut stream = FromStd::new(stream);

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
framer.write(&mut stream, WebSocketSendMessageType::Text, true, b"Hello, World!")?;

loop {
    match framer.read(&mut stream, &mut frame_buf)? {
        ReadResult::Text(text) => {
            println!("Received: {}", text);
            // close the websocket after receiving the first reply
            framer.close(&mut stream, WebSocketCloseStatusCode::NormalClosure, None)?;
        }
        ReadResult::Closed { status, reason } => break println!("Closed: {status:?} {reason}"),
        ReadResult::Disconnected => break println!("Dropped before the close handshake"),
        ReadResult::Binary(_) | ReadResult::Pong(_) => {}
    }
}
```

## Example websocket server usage

The framer reads the HTTP request of the opening handshake and lets you decide how to answer it, for example by path. The following is taken from the [server example](./examples/server.rs):

```rust
let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut websocket);

let is_open = framer.accept(&mut stream, |request| match request.path() {
    "/chat" => Decision::Accept { sub_protocol: None },
    "/" => Decision::Respond(ROOT_HTML.as_bytes()),
    _ => Decision::Respond(NOT_FOUND.as_bytes()),
})?;
if !is_open {
    return Ok(());
}

while let ReadResult::Text(text) = framer.read(&mut stream, &mut frame_buf)? {
    framer.write(&mut stream, WebSocketSendMessageType::Text, true, text.as_bytes())?;
}
```

`request` also gives access to the headers, for example to check `Origin` or an authentication token, and tells whether the client offered a sub protocol.

## License 

Licensed under either MIT or Apache-2.0 at your option
