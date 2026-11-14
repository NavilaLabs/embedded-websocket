//! The HTTP head scanner finds the first empty line, also when the bytes arrive in two parts, and
//! the request head scanner finds the same head after the empty lines a request may start with.
#![no_main]

use embedded_io_websocket::fuzzing::{head_len, request_head_len};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (usize, &[u8])| {
    let (split, buf) = input;
    let expected = buf
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4);

    let mut searched = 0;
    assert_eq!(head_len(buf, &mut searched), expected);
    assert_eq!(searched, buf.len());

    let split = split % (buf.len() + 1);
    let mut searched = 0;
    let first = head_len(&buf[..split], &mut searched);
    let incremental = first.or_else(|| head_len(buf, &mut searched));
    assert_eq!(incremental, expected);

    let empty_lines_len = buf
        .chunks_exact(2)
        .take_while(|line| *line == b"\r\n")
        .count()
        * 2;
    let expected = head_len(&buf[empty_lines_len..], &mut 0).map(|len| empty_lines_len + len);
    let mut searched = 0;
    assert_eq!(request_head_len(buf, &mut searched), expected);
    let mut searched = 0;
    let first = request_head_len(&buf[..split], &mut searched);
    let incremental = first.or_else(|| request_head_len(buf, &mut searched));
    assert_eq!(incremental, expected);
});
