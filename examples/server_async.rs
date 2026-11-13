// The MIT License (MIT)
// Copyright (c) 2019 David Haig

// Demo websocket server that listens on localhost port 1337 using the async framer.
// If accessed from a browser it will return a web page that will automatically attempt to
// open a websocket connection to itself. Alternatively, the client_async.rs example
// can be used to open a websocket connection directly. The server will echo all Text
// messages back to the client as well as responding to any opening and closing handshakes.
// Any stream implementing the embedded-io-async traits works the same way, for example the
// TcpSocket of embassy-net. Here a tokio TcpStream is wrapped with embedded-io-adapters.
// Run with: cargo run --example server_async --features asynch

use embedded_io_adapters::tokio_1::FromTokio;
use tokio::net::{TcpListener, TcpStream};

use embedded_io_websocket::{
    asynch::Framer, Decision, FramerError, FramerState, ReadResult, WebSocketSendMessageType,
    WebSocketServer,
};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = "127.0.0.1:1337";
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on: {}", addr);

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("Client connected {addr:?}");
        tokio::spawn(async {
            match handle_client(stream).await {
                Ok(()) => println!("Connection closed"),
                Err(e) => println!("Error: {:?}", e),
            }
        });
    }
}

async fn handle_client(stream: TcpStream) -> Result<(), FramerError<std::io::Error>> {
    let mut stream = FromTokio::new(stream);
    let mut read_buf = [0; 4000];
    let mut write_buf = [0; 4000];
    let mut frame_buf = [0; 4000];
    let mut state = FramerState::new();
    let mut websocket = WebSocketServer::new_server();
    let mut framer = Framer::new(&mut read_buf, &mut state, &mut write_buf, &mut websocket);

    let is_open = framer
        .accept(&mut stream, |request| match request.path() {
            "/chat" => Decision::Accept { sub_protocol: None },
            "/" => Decision::Respond(ROOT_HTML.as_bytes()),
            _ => Decision::Respond(NOT_FOUND.as_bytes()),
        })
        .await?;
    if !is_open {
        return Ok(());
    }
    println!("Websocket connection opened");

    while let ReadResult::Text(text) = framer.read(&mut stream, &mut frame_buf).await? {
        println!("Received: {}", text);
        framer
            .write(
                &mut stream,
                WebSocketSendMessageType::Text,
                true,
                text.as_bytes(),
            )
            .await?;
    }
    Ok(())
}

const NOT_FOUND: &str = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

const ROOT_HTML : &str = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 2590\r\nConnection: close\r\n\r\n<!doctype html>
<html>
<head>
    <meta content='text/html;charset=utf-8' http-equiv='Content-Type' />
    <meta content='utf-8' http-equiv='encoding' />
    <meta name='viewport' content='width=device-width, initial-scale=0.5, maximum-scale=0.5, user-scalable=0' />
    <meta name='apple-mobile-web-app-capable' content='yes' />
    <meta name='apple-mobile-web-app-status-bar-style' content='black' />
    <title>Web Socket Demo</title>
    <style type='text/css'>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font: 13px Helvetica, Arial; }
        form { background: #000; padding: 3px; position: fixed; bottom: 0; width: 100%; }
        form input { border: 0; padding: 10px; width: 90%; margin-right: .5%; }
        form button { width: 9%; background: rgb(130, 200, 255); border: none; padding: 10px; }
        #messages { list-style-type: none; margin: 0; padding: 0; }
        #messages li { padding: 5px 10px; }
        #messages li:nth-child(odd) { background: #eee; }
    </style>
</head>
<body>
    <ul id='messages'></ul>
    <form action=''>
    <input id='txtBox' autocomplete='off' /><button>Send</button>
    </form>
    <script type='text/javascript' src='http://code.jquery.com/jquery-1.11.1.js' ></script>
    <script type='text/javascript'>
        var CONNECTION;
        window.onload = function () {
            // open the connection to the Web Socket server
            CONNECTION = new WebSocket('ws://localhost:1337/chat');
			// CONNECTION = new WebSocket('ws://' + location.host + ':1337/chat');

            // When the connection is open
            CONNECTION.onopen = function () {
                $('#messages').append($('<li>').text('Connection opened'));
            };

            // when the connection is closed by the server
            CONNECTION.onclose = function () {
                $('#messages').append($('<li>').text('Connection closed'));
            };

            // Log errors
            CONNECTION.onerror = function (e) {
                console.log('An error occured');
            };

            // Log messages from the server
            CONNECTION.onmessage = function (e) {
                $('#messages').append($('<li>').text(e.data));
            };
        };

		$(window).on('beforeunload', function(){
			CONNECTION.close();
		});

        // when we press the Send button, send the text to the server
        $('form').submit(function(){
            CONNECTION.send($('#txtBox').val());
            $('#txtBox').val('');
            return false;
        });
    </script>
</body>
</html>";
