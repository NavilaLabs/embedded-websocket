# embedded-io-websocket
A lightweight rust websocket library for embedded systems `no_std`, with blocking and async framers for [embedded-io](https://crates.io/crates/embedded-io) streams.

This crate started as a fork of [embedded-websocket](https://github.com/ninjasource/embedded-websocket) by David Haig.

It works for clients and servers, allocates nothing and needs no standard library. It passes all cases of the [Autobahn testsuite](https://github.com/crossbario/autobahn-testsuite) except compression, which it does not support.

```
embedded-io-websocket = { version = "x.x.x", features = ["asynch"] }
```

## Features

* `asynch`: the async framer for [embedded-io-async](https://crates.io/crates/embedded-io-async) streams.
* `std`: implements `std::error::Error` for the error types. Without it the crate is `no_std`.
* `defmt`: implements `defmt::Format` for the errors, read results, close status codes and message types, so firmware can log them with [defmt](https://crates.io/crates/defmt).

The minimum supported Rust version is 1.87.

## Framers

The framers let you work with whole websocket messages without dealing with fragmented data:

* `blocking::Framer` works with any stream that implements the [embedded-io](https://crates.io/crates/embedded-io) traits.
* `asynch::Framer` works with any stream that implements the [embedded-io-async](https://crates.io/crates/embedded-io-async) traits, for example the `TcpSocket` of [embassy-net](https://crates.io/crates/embassy-net).

Both have the same API:

* `connect` and `accept` perform the opening handshake of the client and the server.
* `read` returns whole text and binary messages, answers pings and completes a close handshake the other party starts. It returns `Closed` with the status and reason of the other party when the close handshake is complete, and `Disconnected` when the stream ended before. If the other party violates the protocol, the framer closes the connection with the matching status code and returns the error.
* `read_chunk` reads messages larger than `frame_buf` in chunks of up to `frame_buf` bytes, for example to stream a firmware image to flash. Text chunks end at character boundaries, so each one is a valid `&str`. Once a chunk of a message was returned, read the rest of it with `read_chunk` as well.
* `ping` sends a keepalive ping, and `FramerState::awaiting_pong` stays `true` until its pong arrives. The crate has no clock: ping on a timer of your choice, and treat a pong that is still awaited at the next tick as a dead connection.
* `write` splits messages that do not fit into the write buffer into several frames.
* `asynch::Reader` and `asynch::Writer` split a connection after the opening handshake, so one task reads while another writes. They share the write side through a lock: `LocalMutex` for tasks on one executor, or your own `Lock` implementation around a mutex such as `embassy_sync::mutex::Mutex`. The reader still answers pings, and the writer releases the lock between the frames of a long message.
* A `read`, `read_chunk` or `write` that fails, or is cancelled in the async framer, can be called again to continue where it stopped. Call `write` again with the same message before writing another one.

To use a `std` or `tokio` stream, wrap it with `FromStd` or `FromTokio` from [embedded-io-adapters](https://crates.io/crates/embedded-io-adapters).

### Buffers

A framer works on three buffers you provide, and a `FramerState` that you keep per connection:

* `read_buf` holds received bytes. It must fit the HTTP header the other side sends in the opening handshake (a browser request is often 300 to 600 bytes, more with cookies) and a whole control frame (up to 131 bytes). Text and binary messages can be larger, they are moved to `frame_buf` piece by piece.
* `frame_buf` receives a whole message, so it must fit the largest message you accept, and at least 125 bytes for control frame payloads. Larger messages fail the connection with status 1009 when read with `read`; `read_chunk` returns them in pieces instead.
* `write_buf` holds what the framer sends. It must fit the HTTP header of your side of the opening handshake (129 bytes for a server, plus 26 bytes and the length of the sub protocol if it chooses one; 150 bytes plus path, host, origin, sub protocols and extra headers for a client) and a whole control frame (up to 131 bytes), because the framer answers pings by itself. Text and binary messages larger than it are sent in several frames.

`MIN_READ_BUF_LEN`, `MIN_FRAME_BUF_LEN` and `MIN_WRITE_BUF_LEN` hold the minimum for everything except the HTTP headers above, for example to check buffer sizes at compile time. Buffer sizes are not checked when a framer is created: a buffer that is too small fails the operation that needs the space. 1 KiB each is a safe start.

### Without a framer

`WebSocketClient` and `WebSocketServer` encode and decode handshakes and frames on byte slices, so they work with any transport and arbitrarily small buffers, as long as a frame header (2 to 14 bytes) and a control frame (up to 131 bytes) fit. A server reads the request with `Request::read` and answers it with `server_accept`, which also writes the rejection of a request that is not an upgrade. Sub protocols and headers have no length limit except the buffers you pass.

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

### On hardware with embassy-net

`examples/embassy-pico-w` (Raspberry Pi Pico W) and `examples/embassy-esp32c3` (ESP32-C3) join a WiFi network, send one message to a `wss://` echo server over TLS 1.3 with [embedded-tls](https://crates.io/crates/embedded-tls), and then serve a `ws://` echo server on port 80. The application code is shared in `examples/embassy-common`; each board crate only sets up the chip, the WiFi driver and [embassy-net](https://crates.io/crates/embassy-net). They are separate crates with their own targets and are not part of the published package.

The client verifies the server certificate against one certificate authority and the host name. Only ECDSA P-256 and P-384 certificates are supported, and the validity period is not checked because the boards have no clock. Configure the examples at build time:

```
cd examples/embassy-pico-w        # or examples/embassy-esp32c3
./fetch-firmware.sh               # Pico W only: the firmware of the WiFi chip
WIFI_SSID=... WIFI_PASSWORD=... WSS_HOST=echo.example.com WSS_PATH=/ \
WSS_CA_DER=/path/to/root-ca.der cargo run --release
```

Without `WSS_CA_DER` the examples skip the `wss://` client. `cargo run` flashes with [probe-rs](https://probe.rs) for the Pico W and [espflash](https://github.com/esp-rs/espflash) for the ESP32-C3. `cargo test` in `examples/embassy-common` runs the client against a local TLS server, including the rejection of a wrong authority and a wrong host name.

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

## Testing

```
cargo test --features asynch
autobahn/run.sh
```

`autobahn/run.sh` runs the Autobahn testsuite against an echo server and an echo client built on the blocking framer. It needs Docker and jq.

`fuzz/run.sh [seconds]` runs every fuzz target in `fuzz/` for the given time (default 60 seconds) with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz), which needs a nightly toolchain. The targets cover the HTTP head scanner, request and response parsing, the frame decoder and a server framer, and check properties beyond crashes, for example that an accepted key is 16 base64 encoded bytes and that a decoded frame encodes back to the same bytes. A failing input lands in `fuzz/artifacts/`; replay it with `cargo +nightly fuzz run <target> <file>`.

## License

Licensed under either MIT or Apache-2.0 at your option
