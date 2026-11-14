# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`embedded-io-websocket`: a `no_std`, allocation-free RFC 6455 websocket library for clients and servers, with a blocking and an async framer over `embedded-io` / `embedded-io-async` streams. Fork of `embedded-websocket` by David Haig. MSRV is 1.87; CI lints with a pinned toolchain (1.100.0) and `RUSTFLAGS=-D warnings`.

Protocol behavior is justified by RFC 6455 (and RFC 9112 for the HTTP head), never by what this library itself sends: the other party may be any implementation.

## Commands

```sh
cargo test --features asynch                     # most tests; async code is behind `asynch`
cargo test --features asynch --test handshake    # one integration test file
cargo test --features asynch <name_substring>    # single test by name
cargo clippy --all-targets --features "std,asynch"
cargo fmt --check
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
cargo build --target thumbv7em-none-eabihf --features asynch,defmt   # no_std check
```

CI runs clippy and tests for each feature set: `""`, `asynch`, `std`, `std,asynch`, `asynch,defmt`. Check more than one when touching `cfg`-gated code.

Heavier checks:

- `autobahn/run.sh`: Autobahn testsuite against `autobahn/server.rs` and `autobahn/client.rs` (blocking framer). Needs Docker and jq. Fails on any result other than OK, NON-STRICT or INFORMATIONAL.
- `fuzz/run.sh [seconds]`: every cargo-fuzz target in `fuzz/fuzz_targets/` (nightly). The library exposes entry points for them in `lib.rs` `mod fuzzing` under `cfg(fuzzing)`.
- `size/report.py measure > size.json && size/report.py markdown size.json`: flash/RAM cost on Cortex-M4F (needs `llvm-tools`). Code size matters; CI reports the delta against `master` on PRs.
- `examples/embassy-common`, `examples/embassy-pico-w`, `examples/embassy-esp32c3` are separate crates with their own targets, not part of the workspace or package. `cargo test` in `embassy-common` runs the TLS client against a local server.

## Architecture

Three layers, from bottom to top:

1. **Codec on byte slices** (`lib.rs`, `http.rs`, `head.rs`, `request.rs`, `url.rs`): `WebSocket<TRng, Client|Server>` (aliases `WebSocketClient`, `WebSocketServer`) encodes and decodes handshakes and frames without any I/O. `head.rs` scans and validates the HTTP head; `request.rs` holds the server-side `Request` and `Decision`; `http.rs` builds and checks handshake requests and responses; `url.rs` parses `ws://`/`wss://` URLs without copying.

2. **`framer_core.rs`**: all framing logic shared by both framers, still I/O-free. `FramerCore` borrows `read_buf`, `write_buf`, the `WebSocket`, and a `FramerState`. Its methods return what the shell must do next (`Decoded::NeedMoreData`, `SendThenContinue`, `SendThenFinish`, `Message`; `Answer` for the server handshake). It handles control frames answered automatically (ping, close), chunked reads with UTF-8 carry-over, multi-frame writes, and the 1009/1002/1007 failure paths.

3. **I/O shells** `blocking.rs` and `asynch.rs`: thin loops that read into `core.read_space()`, call `core.decode()`, and flush `core.unsent()`. They have the same public API and are kept in parallel; a change to one usually needs the same change in the other. `asynch/split.rs` adds `Reader`/`Writer` that share the write side through a `Lock` (`LocalMutex` or user-provided), since the reader must answer pings and close.

### Resumability invariant

Every framer call must be resumable after an I/O error or (async) cancellation: a new `Framer` built from the same buffers and `FramerState` continues where the last one stopped. That is why all progress lives in `FramerState` (read/frame cursors, `unsent` range, `pending` result, `writing` progress, chunk carry) and why undecoded bytes always start at index 0 of `read_buf`. State changes only after a frame was written. Preserve this when changing any read or write path.

### Buffers

Callers supply `read_buf`, `frame_buf`, `write_buf`; nothing is allocated and sizes are not checked up front. `MIN_READ_BUF_LEN`, `MIN_FRAME_BUF_LEN`, `MIN_WRITE_BUF_LEN` in `framer_core.rs` encode the control-frame minimums; `tests/buffer_minimums.rs` checks them. Handshake header sizes documented in `README.md` must stay accurate when the handshake output changes.

## Specifications

Where the RFCs leave room, behavior follows what the large implementations agree on (browsers per WHATWG, tungstenite, Gorilla, Node `ws`, Python `websockets`, llhttp, httparse, nginx): `http(s)://` URLs are read as `ws(s)://`, and obsolete line folding is rejected. Deliberately stricter than most of them: only CRLF line endings, and non-minimal frame length encodings fail the connection.

Code cites the governing section as `RFC <number> section <x.y>`; keep that style.

- **RFC 6455** (WebSocket): framing and control frames (section 5) in `lib.rs` and `framer_core.rs`, masking keys (5.3, 10.3; clients require `rand_core::CryptoRng`) in `lib.rs` `new_client`, client handshake (4.1) in `http.rs`, server handshake (4.2) and unique fields (11.3) in `request.rs`, close status codes (7.4) in `lib.rs`, URIs (3) in `url.rs`.
- **RFC 9112** (HTTP/1.1 message syntax): head layout (2.1) and empty lines before a request (2.2) in `head.rs`, request target (3.2.1) in `http.rs`, `Host` (3.2) and message body (6.3) in `request.rs`.
- **RFC 9110** (HTTP semantics): field names, values and tokens (section 5) in `head.rs` and `http.rs`.
- **RFC 3986** (URI syntax): path and percent encoding in `url.rs`.

## Features

- `asynch`: `asynch` module (`embedded-io-async`).
- `std`: `std::error::Error` impls; without it the crate is `no_std`.
- `defmt`: `defmt::Format` derives on public errors, results and enums.
