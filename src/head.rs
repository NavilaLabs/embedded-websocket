use core::str;

use crate::{Error, Result};

const END: &[u8] = b"\r\n\r\n";

/// Returns the length of the HTTP head at the start of `buf` including the empty line that ends
/// it, or `None` if the head is not complete yet.
///
/// `searched` holds how many bytes of `buf` a previous call already searched; it is updated so
/// repeated calls on a growing buffer take linear time overall.
pub(crate) fn head_len(buf: &[u8], searched: &mut usize) -> Option<usize> {
    let start = searched.saturating_sub(END.len() - 1).min(buf.len());
    *searched = buf.len();
    buf[start..]
        .windows(END.len())
        .position(|window| window == END)
        .map(|position| start + position + END.len())
}

/// A complete and validated HTTP/1.1 message head (RFC 9112 section 2.1).
pub(crate) struct Head<'a> {
    start_line: &'a str,
    fields: &'a [u8],
}

impl<'a> Head<'a> {
    /// Validates `head`, which must end with the empty line.
    pub(crate) fn parse(head: &'a [u8]) -> Result<Self> {
        let head = head.strip_suffix(END).ok_or(Error::HttpHeaderInvalid)?;
        let (start_line, fields) = match find_line_end(head) {
            Some(end) => (&head[..end], &head[end + 2..]),
            None => (head, &[][..]),
        };
        if !start_line
            .iter()
            .all(|&byte| byte == b' ' || byte.is_ascii_graphic())
        {
            return Err(Error::HttpHeaderInvalid);
        }
        let head = Self {
            start_line: str::from_utf8(start_line).map_err(|_| Error::HttpHeaderInvalid)?,
            fields,
        };
        // A field line cannot contain CR or LF, so a bare CR or LF fails here instead of being
        // read as a line break that other HTTP parsers would not see.
        if !lines(fields).all(is_valid_field) {
            return Err(Error::HttpHeaderInvalid);
        }
        Ok(head)
    }

    /// The request line or status line split at its first two spaces.
    pub(crate) fn start_line(&self) -> Option<(&'a str, &'a str, &'a str)> {
        let (first, rest) = self.start_line.split_once(' ')?;
        let (second, third) = rest.split_once(' ').unwrap_or((rest, ""));
        Some((first, second, third))
    }

    /// Name and value of every header field, with the whitespace around the value removed.
    pub(crate) fn fields(&self) -> impl Iterator<Item = (&'a str, &'a [u8])> {
        lines(self.fields).map(|line| {
            let colon = line.iter().position(|&byte| byte == b':').unwrap_or(0);
            // validated in `parse`: the name is a token and therefore ASCII
            let name = str::from_utf8(&line[..colon]).unwrap_or_default();
            (name, line[colon + 1..].trim_ascii())
        })
    }

    /// The value of the first header field called `name`, compared case-insensitively.
    pub(crate) fn field(&self, name: &str) -> Option<&'a [u8]> {
        self.fields()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    /// The comma-separated elements of all header fields called `name` (RFC 9110 section 5.3).
    pub(crate) fn tokens(&self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.fields()
            .filter(move |(field, _)| field.eq_ignore_ascii_case(name))
            .filter_map(|(_, value)| str::from_utf8(value).ok())
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .filter(|token| !token.is_empty())
    }

    /// Whether a field called `name` lists `token`, compared case-insensitively.
    pub(crate) fn has_token(&self, name: &'a str, token: &str) -> bool {
        self.tokens(name)
            .any(|listed| listed.eq_ignore_ascii_case(token))
    }
}

fn find_line_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|window| window == b"\r\n")
}

// Splits only at CRLF, so a bare CR or LF stays inside its line.
fn lines(mut bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    core::iter::from_fn(move || {
        if bytes.is_empty() {
            return None;
        }
        let line;
        (line, bytes) = match find_line_end(bytes) {
            Some(end) => (&bytes[..end], &bytes[end + 2..]),
            None => (bytes, &[][..]),
        };
        Some(line)
    })
}

// RFC 9110 section 5: field-name ":" OWS field-value OWS, without obsolete line folding
pub(crate) fn is_valid_field(line: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|&byte| byte == b':') else {
        return false;
    };
    let (name, value) = (&line[..colon], &line[colon + 1..]);
    !name.is_empty() && name.iter().all(|&byte| is_token_byte(byte)) && is_valid_field_value(value)
}

// RFC 9110 section 5.5, including the whitespace around the value
pub(crate) fn is_valid_field_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|&byte| byte == b'\t' || byte >= 0x20 && byte != 0x7F)
}

// RFC 9110 section 5.6.2
pub(crate) fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_len_finds_the_end_across_calls() {
        let head = b"GET / HTTP/1.1\r\nHost: a\r\n\r\nframes";
        let mut searched = 0;
        for len in 0..26 {
            assert_eq!(head_len(&head[..len], &mut searched), None);
        }
        assert_eq!(head_len(&head[..27], &mut searched), Some(27));
        assert_eq!(head_len(head, &mut 0), Some(27));
    }

    #[test]
    fn fields_are_trimmed_and_found_case_insensitively() {
        let head = Head::parse(b"GET /chat HTTP/1.1\r\nHost:  a \r\nConnection: keep-alive,Upgrade\r\nconnection: x\r\n\r\n").unwrap();
        assert_eq!(head.start_line(), Some(("GET", "/chat", "HTTP/1.1")));
        assert_eq!(head.field("HOST"), Some(&b"a"[..]));
        assert!(head.has_token("Connection", "upgrade"));
        assert!(head.has_token("connection", "x"));
        assert!(!head.has_token("connection", "close"));
    }

    #[test]
    fn head_without_fields_is_valid() {
        let head = Head::parse(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(head.fields().count(), 0);
    }

    #[test]
    fn malformed_heads_are_rejected() {
        for head in [
            &b"GET / HTTP/1.1\r\nHost a\r\n\r\n"[..],
            b"GET / HTTP/1.1\r\n: a\r\n\r\n",
            b"GET / HTTP/1.1\r\nHo st: a\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\nX: b\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\rX: b\r\n\r\n",
            b"GET / HTTP/1.1\r\nA: a\nB: b\r\r\n\r\n",
            b"GET / HTTP/1.1\r\nA: a\r\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\0\r\n\r\n",
            b"GET /\0 HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\n",
        ] {
            assert!(
                matches!(Head::parse(head), Err(Error::HttpHeaderInvalid)),
                "{head:?}"
            );
        }
    }
}
