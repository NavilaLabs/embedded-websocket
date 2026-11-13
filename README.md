# embedded-websocket
A lightweight rust websocket library for embedded systems `no_std`

This library facilitates the encoding and decoding of websocket messages and can be used for both clients and servers. The library is intended to be used in constrained memory environments like embedded microcontrollers which cannot reference the rust standard library. The library will work with arbitrarily small buffers regardless of websocket frame size as long as the websocket header can be read (2 - 14 bytes depending)

## no_std support

The library is `no_std` by default. The `std` feature only adds `std::error::Error` implementations.

## Framers

The framers let you work with whole websocket messages without dealing with fragmented data. They work with any stream that implements the [embedded-io](https://crates.io/crates/embedded-io) or [embedded-io-async](https://crates.io/crates/embedded-io-async) traits:

* `embedded-io`: the `framer_embedded_io` module works with blocking streams.
* `embedded-io-async`: the `framer_embedded_io_async` module works with async streams, for example the `TcpSocket` of [embassy-net](https://crates.io/crates/embassy-net).

Both have the same API.

```
embedded-websocket = { version = "x.x.x", features = ["embedded-io-async"] }
```

To use a `std` or `tokio` stream, wrap it with `FromStd` or `FromTokio` from [embedded-io-adapters](https://crates.io/crates/embedded-io-adapters).

Without a framer, `WebSocketClient` and `WebSocketServer` encode and decode frames on byte slices, so you can use any transport.

## Running the examples

The server accepts client connections in a loop and echoes back whatever text a client sends. The client connects to the server, sends one "Hello, World!" message, waits for the response, then closes the connection. Proper open and close handshakes are demonstrated.

To run the demo web server with the blocking or the async framer:

```
cargo run --example server_embedded_io --features embedded-io
cargo run --example server_embedded_io_async --features embedded-io-async
```

To run the demo websocket client:

```
cargo run --example client_embedded_io --features embedded-io
cargo run --example client_embedded_io_async --features embedded-io-async
```

or open `http://127.0.0.1:1337/` in your browser.

## Example websocket client usage

The following example, also found [here](./examples/client_embedded_io.rs), performs the opening handshake, sends a short message, initiates a close handshake and waits for the server to complete it.

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

while let ReadResult::Text(text) = framer.read(&mut stream, &mut frame_buf)? {
    println!("Received: {}", text);

    // close the websocket after receiving the first reply
    framer.close(&mut stream, WebSocketCloseStatusCode::NormalClosure, None)?;
}
```

## Example websocket server usage

The server example is a little too verbose to include in this readme, see the [server example](./examples/server_embedded_io.rs).

## License 

Licensed under either MIT or Apache-2.0 at your option
