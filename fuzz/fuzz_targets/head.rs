//! The HTTP head scanner finds the first empty line, also when the bytes arrive in two parts.
#![no_main]

use embedded_io_websocket::fuzzing::head_len;
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
});
