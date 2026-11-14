//! Opening handshakes without fixed limits on sub protocols, headers or the number of offers.

use std::collections::VecDeque;

use embedded_io_websocket::{
    blocking::Framer, Error, FramerState, Request, WebSocketClient, WebSocketKey, WebSocketOptions,
    WebSocketServer,
};

const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

// Gives the client the fixed key `AAAAAAAAAAAAAAAAAAAAAA==`. Only acceptable in a test: a real
// client needs unpredictable masking keys.
struct ZeroRng;

impl rand::TryRng for ZeroRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        dest.fill(0);
        Ok(())
    }
}

impl rand::TryCryptoRng for ZeroRng {}
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

fn upgrade_request(sub_protocols: &str) -> String {
    format!(
        "GET /chat HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Protocol: {sub_protocols}\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    )
}

fn switching_protocols(sub_protocol: &str) -> String {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Protocol: {sub_protocol}\r\nSec-WebSocket-Accept: {ACCEPT}\r\n\r\n"
    )
}

#[test]
fn request_read_returns_the_head_length_and_waits_for_the_whole_head() {
    let request = upgrade_request("chat");
    let bytes = [request.as_bytes(), b"first frame"].concat();

    let (parsed, len) = Request::read(&bytes).unwrap();
    assert_eq!(len, request.len());
    assert_eq!(parsed.path(), "/chat");
    assert!(matches!(
        Request::read(&request.as_bytes()[..request.len() - 1]),
        Err(Error::HttpHeaderIncomplete)
    ));
}

#[test]
fn server_accepts_a_long_sub_protocol_among_many_offers() {
    let long = "p".repeat(100);
    let offers = format!("a, b, c, d, {long}");
    let request = upgrade_request(&offers);
    let (request, _) = Request::read(request.as_bytes()).unwrap();

    let mut to = [0; 512];
    let mut ws_server = WebSocketServer::new_server();
    let len = ws_server
        .server_accept(&request, Some(&long), &mut to)
        .unwrap();

    let response = std::str::from_utf8(&to[..len]).unwrap();
    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(response.contains(&format!("\r\nSec-WebSocket-Protocol: {long}\r\n")));
    assert!(response.contains(&format!("\r\nSec-WebSocket-Accept: {ACCEPT}\r\n")));
}

#[test]
fn server_refuses_a_sub_protocol_the_client_did_not_offer() {
    let request = upgrade_request("chat");
    let (request, _) = Request::read(request.as_bytes()).unwrap();
    let mut ws_server = WebSocketServer::new_server();
    assert_eq!(
        ws_server
            .server_accept(&request, Some("superchat"), &mut [0; 512])
            .err(),
        Some(Error::SubProtocolNotOffered)
    );
}

#[test]
fn server_writes_the_rejection_of_a_request_that_is_not_an_upgrade() {
    for (request, status) in [
        (
            "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_owned(),
            "400",
        ),
        (
            upgrade_request("chat").replace("Version: 13", "Version: 8"),
            "426",
        ),
    ] {
        let (request, _) = Request::read(request.as_bytes()).unwrap();
        let mut to = [0; 512];
        let mut ws_server = WebSocketServer::new_server();
        let Err(Error::NotAnUpgrade(len)) = ws_server.server_accept(&request, None, &mut to) else {
            panic!("expected a rejection with status {status}");
        };
        assert!(to[..len].starts_with(format!("HTTP/1.1 {status} ").as_bytes()));
        assert!(to[..len].ends_with(b"\r\n\r\n"));
    }
}

#[test]
fn client_returns_the_offered_sub_protocol_it_got() {
    let long = "p".repeat(100);
    let offers = ["chat", long.as_str()];
    let response = switching_protocols(&long);
    let key = WebSocketKey::try_from(KEY).unwrap();

    let mut ws_client = WebSocketClient::new_client(rand::rng());
    let (len, sub_protocol) = ws_client
        .client_accept(&key, Some(&offers), response.as_bytes())
        .unwrap();

    assert_eq!(len, response.len());
    assert!(std::ptr::eq(sub_protocol.unwrap(), offers[1]));
}

#[test]
fn client_request_larger_than_a_kilobyte_fits_a_large_buffer() {
    let header = format!("X-Padding: {}", "x".repeat(2000));
    let headers = [header.as_str()];
    let options = WebSocketOptions {
        path: "/chat",
        host: "localhost",
        origin: Some("http://localhost"),
        sub_protocols: None,
        additional_headers: Some(&headers),
    };
    let mut to = vec![0; 4096];
    let mut ws_client = WebSocketClient::new_client(rand::rng());
    let (len, _) = ws_client.client_connect(&options, &mut to).unwrap();
    assert!(len > 2000);
    assert!(std::str::from_utf8(&to[..len]).unwrap().contains(&header));
    assert_eq!(
        WebSocketClient::new_client(rand::rng())
            .client_connect(&options, &mut to[..len - 1])
            .err(),
        Some(Error::WriteToBufferTooSmall)
    );
}

struct Replay {
    unread: VecDeque<u8>,
    written: Vec<u8>,
}

impl embedded_io::ErrorType for Replay {
    type Error = core::convert::Infallible;
}

impl embedded_io::Read for Replay {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let len = buf.len().min(self.unread.len());
        for (to, from) in buf.iter_mut().zip(self.unread.drain(..len)) {
            *to = from;
        }
        Ok(len)
    }
}

impl embedded_io::Write for Replay {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn framer_connect_returns_the_chosen_offer() {
    let long = "p".repeat(100);
    let offers = ["chat", long.as_str()];
    let options = WebSocketOptions {
        path: "/chat",
        host: "localhost",
        origin: Some("http://localhost"),
        sub_protocols: Some(&offers),
        additional_headers: None,
    };
    let (mut read_buf, mut write_buf) = (vec![0; 1024], vec![0; 1024]);
    let mut state = FramerState::new();
    // the zero key is answered by this accept string
    let mut ws_client = WebSocketClient::new_client(ZeroRng);
    let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut ws_client);
    let response = switching_protocols(&long).replace(ACCEPT, "ICX+Yqv66kxgM0FcWaLWlFLwTAI=");
    let mut stream = Replay {
        unread: response.into_bytes().into(),
        written: Vec::new(),
    };

    let sub_protocol = framer.connect(&mut stream, &options).unwrap();
    assert!(std::ptr::eq(sub_protocol.unwrap(), offers[1]));
}
